/**
 * The PLR-VPN-v1 exit HTTP API (SPEC-VPN §3), node:http only, one port:
 *
 *   GET /v1/attestation?nonce=<64 hex>   SPEC §6.2 bundle (app_compose = the VPN compose)
 *   GET /v1/tunnel + Upgrade: plr-vpn/1  101, then the raw socket carries the §4 tunnel (tunnel.ts)
 *   GET /v1/receipts/proof?seq=<n>       SPEC §6.4 for VPN receipts
 *   GET /healthz                         {"ok":true}
 *
 * No per-connection logging at all (not even routes or status codes). Error bodies are fixed codes. The egress
 * policy and the DoH resolvers come from the measured compose bytes themselves, never from a separate setting.
 */
import http from "node:http";
import type { Duplex } from "node:stream";
import { sha256 } from "@noble/hashes/sha2.js";
import type { Attester, CollateralJson, RootKind } from "@plr/shared";
import { vpnPolicyOf, type VpnCompose } from "../compose.js";
import { HttpError, parseUrl, sendError } from "../http-util.js";
import { commonRoutes, type RouteHandler } from "../service-routes.js";
import { createDohLookup } from "./doh.js";
import { dialEgress, type Dialer, type LookupAll } from "./egress.js";
import type { VpnKeys } from "./keys.js";
import type { VpnReceiptLog } from "./receipts.js";
import { nodeTimers, type Timers } from "./timers.js";
import { DEFAULT_TUNNEL_TIMEOUTS, ExitTunnel, type TunnelTimeouts } from "./tunnel.js";

export const TUNNEL_PATH = "/v1/tunnel";
export const UPGRADE_TOKEN = "plr-vpn/1";

export interface ExitOptions {
  attester: Attester;
  keys: VpnKeys;
  /** Exact bytes of the measured VPN app-compose.json (its policy.egress is enforced). */
  composeBytes: Uint8Array;
  receipts: VpnReceiptLog;
  /** The registration quote once registered, served in `/v1/attestation` (SPEC-CHAINS §4). */
  registrationQuote?: () => Uint8Array | null;
  /** The root published in the bundle (`root_kind`, SPEC-TDX §1.5); default MOCK. */
  rootKind?: RootKind;
  /** INTEL mode: the Intel collateral served with the quote (SPEC-TDX §1.5); failure → 503 E_UPSTREAM. */
  collateral?: (quote: Uint8Array) => Promise<CollateralJson>;
  /**
   * The enforced VPN policy. Default: the strict policy of `composeBytes`. In dstack mode `composeBytes` is the
   * dstack app-compose (which carries no egress policy), so boot passes the policy of the baked-in compose instead.
   */
  policy?: VpnCompose["policy"];
  /** Upstream dialer (default: the honest {@link dialEgress}). */
  dial?: Dialer;
  /**
   * Resolver for destination names. Default (and the only one bootExit uses): RFC 8484 DoH through the measured
   * `policy.dns.doh` resolvers, no fallback. Unit tests may inject a fake.
   */
  lookup?: LookupAll;
  /** Concurrent tunnels (default 1024); above it new tunnels get 503. */
  maxTunnels?: number;
  /** Destination ports the exit dials (others get CONNECT_ERR `E_EGRESS_DENIED`); default any port. */
  allowedPorts?: readonly number[] | null;
  timeouts?: Partial<TunnelTimeouts>;
  /** Timer source of the tunnel deadlines (default Node timers; tests drive a manual clock). */
  timers?: Timers;
  now?: () => number;
}

export interface ExitServer {
  server: http.Server;
  /** Number of open tunnels. */
  readonly tunnels: number;
  /** Destroys every open tunnel (shutdown). */
  destroyTunnels(): void;
}

const MAX_TUNNELS = 1024;

function rawError(sock: Duplex, status: 400 | 404 | 503, code: string): void {
  const reason = status === 400 ? "Bad Request" : status === 404 ? "Not Found" : "Service Unavailable";
  const body = JSON.stringify({ error: code });
  if (sock.writable) {
    sock.end(
      `HTTP/1.1 ${status} ${reason}\r\ncontent-type: application/json\r\ncache-control: no-store\r\nconnection: close\r\n` +
        `content-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
    setTimeout(() => sock.destroy(), 1000).unref();
  } else sock.destroy();
}

function headerIs(v: string | string[] | undefined, want: string): boolean {
  return typeof v === "string" && v.trim().toLowerCase() === want;
}

function connectionHasUpgrade(v: string | string[] | undefined): boolean {
  return typeof v === "string" && v.split(",").some((t) => t.trim().toLowerCase() === "upgrade");
}

export function createExit(o: ExitOptions): ExitServer {
  const composeBytes = o.composeBytes.slice();
  // Strict + canonical (`plr-vpn`, or the `vpn` part of a `plr-combo`); the policy we enforce is the measured one.
  const vpnPolicy = o.policy ?? vpnPolicyOf(composeBytes);
  const policy = { allow_loopback: vpnPolicy.egress.allow_loopback, deny_private: vpnPolicy.egress.deny_private };
  const composeHash = sha256(composeBytes);
  const maxTunnels = o.maxTunnels ?? MAX_TUNNELS;
  const timeouts: TunnelTimeouts = { ...DEFAULT_TUNNEL_TIMEOUTS, ...o.timeouts };
  const ctx = {
    keys: o.keys,
    composeHash,
    policy,
    receipts: o.receipts,
    dial: o.dial ?? dialEgress,
    lookup: o.lookup ?? createDohLookup(vpnPolicy.dns.doh),
    timeouts,
    timers: o.timers ?? nodeTimers,
    now: o.now ?? Date.now,
    allowedPorts: o.allowedPorts ? new Set(o.allowedPorts) : null,
  };
  const open = new Set<ExitTunnel>();

  const common = commonRoutes({
    attester: o.attester,
    keys: o.keys,
    composeBytes,
    receipts: o.receipts,
    rootKind: o.rootKind ?? "MOCK",
    ...(o.collateral ? { collateral: o.collateral } : {}),
    ...(o.registrationQuote ? { registrationQuote: o.registrationQuote } : {}),
  });
  const tunnelWithoutUpgrade: RouteHandler = () => {
    throw new HttpError(400, "E_BAD_REQUEST");
  };
  const routes: Record<string, RouteHandler> = {
    "/v1/attestation": common.attestation,
    [TUNNEL_PATH]: tunnelWithoutUpgrade,
    "/v1/receipts/proof": common.proof,
    "/healthz": common.healthz,
  };

  const server = http.createServer({ maxHeaderSize: 16 * 1024 }, (req, res) => {
    void (async () => {
      try {
        const { path, query } = parseUrl(req.url);
        const handler = Object.hasOwn(routes, path) ? routes[path] : undefined;
        if (!handler) throw new HttpError(404, "E_NOT_FOUND");
        await handler(req, res, query);
      } catch (e) {
        req.resume();
        if (e instanceof HttpError) sendError(res, e.status, e.code);
        else sendError(res, 500, "E_INTERNAL");
      }
    })();
  });

  server.on("upgrade", (req: http.IncomingMessage, sock: Duplex, head: Buffer) => {
    sock.on("error", () => sock.destroy());
    let path: string;
    let query: URLSearchParams;
    try {
      ({ path, query } = parseUrl(req.url));
    } catch {
      return rawError(sock, 400, "E_BAD_REQUEST");
    }
    if (path !== TUNNEL_PATH) return rawError(sock, 404, "E_NOT_FOUND");
    if (req.method !== "GET" || [...query.keys()].length !== 0 || !headerIs(req.headers.upgrade, UPGRADE_TOKEN) || !connectionHasUpgrade(req.headers.connection)) {
      return rawError(sock, 400, "E_BAD_REQUEST");
    }
    if (open.size >= maxTunnels) return rawError(sock, 503, "E_UPSTREAM");
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nupgrade: ${UPGRADE_TOKEN}\r\n\r\n`);
    let t: ExitTunnel | null = null;
    t = new ExitTunnel(sock, head, ctx, () => {
      if (t) open.delete(t);
    });
    if (t.state !== "closed") open.add(t); // (it may already have failed on `head`)
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 60_000;
  server.keepAliveTimeout = 5_000;
  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    else socket.destroy();
  });

  return {
    server,
    get tunnels() {
      return open.size;
    },
    destroyTunnels() {
      for (const t of [...open]) t.destroy();
    },
  };
}
