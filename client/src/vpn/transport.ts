/**
 * Minimal node:http(s) transport to a VPN exit (SPEC-VPN §3) with an injectable DNS `lookup`, so every lookup the
 * client itself performs (the exit URL host) goes through `o.lookup` (SPEC-VPN §9.2). Destinations are never
 * resolved here — they travel inside the encrypted CONNECT frame.
 *
 * The byte stream to the exit is either a direct TCP connection (default) or any `Duplex` produced by an
 * {@link ExitTarget.createConnection} dialer — e.g. a {@link VpnStream} through an entry exit (two-hop, SPEC-VPN
 * §10), in which case no lookup and no direct connection to the exit happen at all. For an `https:` exit the
 * dialed stream is wrapped in TLS here (certificate checked against the exit URL host).
 *
 * Bounded: whole-request timeouts, response body limits, no redirects (node:http never follows them), no
 * connection reuse (`agent: false` / one dialed stream per request). Errors are generic `TransportError`s,
 * except that a `PlrError` raised by the dialer (e.g. the entry hop's verification code) is passed through
 * unchanged. Nothing here logs, and errors never carry URLs, addresses or payload.
 */
import { request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { isIP, type LookupFunction, type Socket } from "node:net";
import type { Duplex } from "node:stream";
import type { lookup as dnsLookup } from "node:dns";
import { isPlrError, type PlrError } from "@plr/shared";

export type Lookup = typeof dnsLookup;

/** Opens a fresh byte stream to the exit (one per HTTP request / tunnel). Rejections should be `PlrError`s. */
export type Dialer = () => Promise<Duplex>;

/** Upgrade token of the tunnel endpoint (SPEC-VPN §3). */
export const TUNNEL_UPGRADE = "plr-vpn/1";

export class TransportError extends Error {
  constructor(readonly kind: "unreachable" | "timeout" | "too-large" | "bad-upgrade" | "status") {
    super(`exit transport: ${kind}`);
    this.name = "TransportError";
  }
}

export interface ExitTarget {
  /** Normalised exit base URL (origin + path prefix, no trailing slash). */
  base: URL;
  lookup: Lookup | undefined;
  /** Dials the exit through something other than direct TCP (two-hop). When set, `lookup` is never used. */
  createConnection?: Dialer;
}

/** Hostname without IPv6 brackets. */
export function urlHost(url: URL): string {
  return url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
}

/** Explicit or default port of an `http(s):` URL. */
export function urlPort(url: URL): number {
  return url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
}

type CreateConnection = (opts: unknown, cb: (err: Error | null, stream?: Duplex) => void) => undefined;

function dialedConnection(t: ExitTarget, dial: Dialer): CreateConnection {
  return (_opts, cb) => {
    dial().then(
      (raw) => {
        if (t.base.protocol !== "https:") {
          cb(null, raw);
          return;
        }
        const host = urlHost(t.base);
        const tls = tlsConnect({
          socket: raw,
          host,
          ...(isIP(host) === 0 ? { servername: host } : {}),
          ALPNProtocols: ["http/1.1"],
          rejectUnauthorized: true,
        });
        // Closing TLS ends (not destroys) the dialed stream, so e.g. an entry tunnel can still finish cleanly.
        tls.on("close", () => {
          if (!raw.destroyed && !raw.writableEnded) raw.end();
        });
        cb(null, tls);
      },
      (e: unknown) => cb(e instanceof Error ? e : new TransportError("unreachable")),
    );
    return undefined;
  };
}

function requestFor(t: ExitTarget, path: string, extra: RequestOptions): ClientRequest {
  const url = new URL(t.base.href.replace(/\/?$/, "/") + path.replace(/^\//, ""));
  const opts: RequestOptions = {
    protocol: url.protocol,
    hostname: urlHost(url),
    port: url.port === "" ? undefined : Number(url.port),
    path: url.pathname + url.search,
    ...extra,
  };
  if (t.createConnection !== undefined) {
    // node:http uses `createConnection` only without an agent; TLS (if any) is layered in dialedConnection, so
    // the request itself is always plain HTTP over the dialed stream.
    opts.createConnection = dialedConnection(t, t.createConnection) as unknown as RequestOptions["createConnection"];
    opts.protocol = "http:";
    return httpRequest(opts);
  }
  opts.agent = false;
  // The dns.lookup type is a superset of net's LookupFunction (same callback convention).
  if (t.lookup !== undefined) opts.lookup = t.lookup as unknown as LookupFunction;
  return url.protocol === "https:" ? httpsRequest(opts) : httpRequest(opts);
}

/** Maps a request error: a dialer's PlrError passes through, anything else is `unreachable`. */
const requestError = (e: unknown): PlrError | TransportError => (isPlrError(e) ? e : new TransportError("unreachable"));

/** `GET` returning status and the body (≤ `maxBytes`). @throws TransportError | PlrError (from the dialer) */
export function getBounded(t: ExitTarget, path: string, o: { timeoutMs: number; maxBytes: number }): Promise<{ status: number; body: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err: TransportError | PlrError | null, v?: { status: number; body: Uint8Array }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err !== null) {
        req.destroy();
        reject(err);
      } else resolve(v!);
    };
    const req = requestFor(t, path, { method: "GET", headers: { accept: "application/json", connection: "close" } });
    const timer = setTimeout(() => done(new TransportError("timeout")), o.timeoutMs);
    timer.unref?.();
    req.on("error", (e) => done(requestError(e)));
    req.on("response", (res: IncomingMessage) => {
      const declared = res.headers["content-length"];
      if (declared !== undefined && /^\d+$/.test(declared) && Number(declared) > o.maxBytes) {
        res.destroy();
        done(new TransportError("too-large"));
        return;
      }
      const parts: Buffer[] = [];
      let n = 0;
      res.on("data", (c: Buffer) => {
        n += c.length;
        if (n > o.maxBytes) {
          res.destroy();
          done(new TransportError("too-large"));
          return;
        }
        parts.push(c);
      });
      res.on("error", () => done(new TransportError("unreachable")));
      res.on("aborted", () => done(new TransportError("unreachable")));
      res.on("end", () => done(null, { status: res.statusCode ?? 0, body: new Uint8Array(Buffer.concat(parts)) }));
    });
    req.end();
  });
}

/**
 * `GET /v1/tunnel` with `Connection: Upgrade`, `Upgrade: plr-vpn/1`; resolves with the raw stream after a
 * `101` whose `Upgrade` header is exactly the tunnel token, plus any bytes already read past the headers
 * (they may already hold the exit's server_hello). The stream is a `net.Socket` for a direct connection, or
 * the dialed `Duplex` (TLS-wrapped for `https:`).
 * @throws TransportError | PlrError (from the dialer)
 */
export function openUpgrade(t: ExitTarget, path: string, o: { timeoutMs: number }): Promise<{ socket: Duplex; head: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err: TransportError | PlrError): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      reject(err);
    };
    const req = requestFor(t, path, { method: "GET", headers: { connection: "Upgrade", upgrade: TUNNEL_UPGRADE } });
    const timer = setTimeout(() => fail(new TransportError("timeout")), o.timeoutMs);
    timer.unref?.();
    req.on("error", (e) => fail(requestError(e)));
    req.on("response", (res: IncomingMessage) => {
      res.resume();
      res.destroy();
      fail(new TransportError("status"));
    });
    req.on("upgrade", (res: IncomingMessage, socket: Socket | Duplex, head: Buffer) => {
      if (settled) {
        socket.destroy();
        return;
      }
      const up = res.headers.upgrade;
      if (res.statusCode !== 101 || typeof up !== "string" || up.toLowerCase() !== TUNNEL_UPGRADE) {
        socket.destroy();
        fail(new TransportError("bad-upgrade"));
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({ socket, head: new Uint8Array(head) });
    });
    req.end();
  });
}
