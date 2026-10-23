/**
 * Minimal node:http(s) transport to a VPN exit (SPEC-VPN §3) with an injectable DNS `lookup`, so every lookup the
 * client itself performs (the exit URL host) goes through `o.lookup` (SPEC-VPN §9.2). Destinations are never
 * resolved here — they travel inside the encrypted CONNECT frame.
 *
 * Bounded: whole-request timeouts, response body limits, no redirects (node:http never follows them), no
 * connection reuse (`agent: false`). Errors are generic `TransportError`s; callers map them to PlrError codes.
 * Nothing here logs, and errors never carry URLs, addresses or payload.
 */
import { request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import type { lookup as dnsLookup } from "node:dns";
import type { LookupFunction, Socket } from "node:net";

export type Lookup = typeof dnsLookup;

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
}

function requestFor(t: ExitTarget, path: string, extra: RequestOptions): ClientRequest {
  const url = new URL(t.base.href.replace(/\/?$/, "/") + path.replace(/^\//, ""));
  const opts: RequestOptions = {
    protocol: url.protocol,
    hostname: url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname,
    port: url.port === "" ? undefined : Number(url.port),
    path: url.pathname + url.search,
    agent: false,
    ...extra,
  };
  // The dns.lookup type is a superset of net's LookupFunction (same callback convention).
  if (t.lookup !== undefined) opts.lookup = t.lookup as unknown as LookupFunction;
  return url.protocol === "https:" ? httpsRequest(opts) : httpRequest(opts);
}

/** `GET` returning status and the body (≤ `maxBytes`). @throws TransportError */
export function getBounded(t: ExitTarget, path: string, o: { timeoutMs: number; maxBytes: number }): Promise<{ status: number; body: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err: TransportError | null, v?: { status: number; body: Uint8Array }): void => {
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
    req.on("error", () => done(new TransportError("unreachable")));
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
 * `GET /v1/tunnel` with `Connection: Upgrade`, `Upgrade: plr-vpn/1`; resolves with the raw socket after a
 * `101` whose `Upgrade` header is exactly the tunnel token, plus any bytes already read past the headers.
 * @throws TransportError
 */
export function openUpgrade(t: ExitTarget, path: string, o: { timeoutMs: number }): Promise<{ socket: Socket; head: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (kind: TransportError["kind"]): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      reject(new TransportError(kind));
    };
    const req = requestFor(t, path, { method: "GET", headers: { connection: "Upgrade", upgrade: TUNNEL_UPGRADE } });
    const timer = setTimeout(() => fail("timeout"), o.timeoutMs);
    timer.unref?.();
    req.on("error", () => fail("unreachable"));
    req.on("response", (res: IncomingMessage) => {
      res.resume();
      res.destroy();
      fail("status");
    });
    req.on("upgrade", (res: IncomingMessage, socket: Socket, head: Buffer) => {
      if (settled) {
        socket.destroy();
        return;
      }
      const up = res.headers.upgrade;
      if (res.statusCode !== 101 || typeof up !== "string" || up.toLowerCase() !== TUNNEL_UPGRADE) {
        socket.destroy();
        fail("bad-upgrade");
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({ socket, head: new Uint8Array(head) });
    });
    req.end();
  });
}
