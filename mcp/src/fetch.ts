/**
 * `fetch_via_exit` mechanics: URL / port validation and one HTTP/1.1 GET over an attested tunnel. The tunnel
 * target is passed to the exit unresolved (remote DNS); nothing here opens a direct connection or resolves a name.
 */
import { connect as tlsConnect } from "node:tls";
import type { Duplex } from "node:stream";

export const DEFAULT_MAX_BYTES = 20_000;
export const HARD_MAX_BYTES = 1_000_000;
const ALLOWED_PORTS: readonly number[] = [80, 443];
const FETCH_TIMEOUT_MS = 30_000;
const SHOWN_HEADERS = ["content-type", "content-length", "content-encoding", "location", "last-modified", "etag", "date", "server"];

export interface FetchTarget {
  host: string;
  port: number;
  tls: boolean;
  /** Path + query (no fragment). */
  path: string;
  /** `Host` header value. */
  hostHeader: string;
}

export class UrlRefused extends Error {
  readonly code = "E_BAD_INPUT";
}

/** http(s) only, no credentials, port 80 or 443 only (the exit allows nothing else). @throws UrlRefused */
export function parseFetchUrl(input: unknown, allowedPorts: readonly number[] = ALLOWED_PORTS): FetchTarget {
  if (typeof input !== "string" || input.length === 0 || input.length > 4096) throw new UrlRefused("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new UrlRefused("url is not a valid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new UrlRefused("only http and https URLs are allowed");
  if (u.username !== "" || u.password !== "") throw new UrlRefused("URLs with credentials are not allowed");
  const tls = u.protocol === "https:";
  const port = u.port === "" ? (tls ? 443 : 80) : Number(u.port);
  if (!allowedPorts.includes(port)) throw new UrlRefused(`port ${port} is not allowed (only ${allowedPorts.join(" and ")})`);
  if (u.hostname === "") throw new UrlRefused("url has no host");
  const defaultPort = tls ? 443 : 80;
  return { host: u.hostname.replace(/^\[|\]$/g, ""), port, tls, path: u.pathname + u.search, hostHeader: port === defaultPort ? u.host.replace(/:\d+$/, "") : u.host };
}

export interface FetchResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  /** True when the body was cut at `max_bytes` (or the connection stopped before the end). */
  truncated: boolean;
  bytes: number;
}

/** `max_bytes`: integer 1..1 000 000, default 20 000. @throws UrlRefused */
export function parseMaxBytes(v: unknown): number {
  if (v === undefined) return DEFAULT_MAX_BYTES;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > HARD_MAX_BYTES) throw new UrlRefused(`max_bytes must be an integer between 1 and ${HARD_MAX_BYTES}`);
  return v;
}

/** Decodes as much of a chunked body as `raw` holds (bytes), stopping at `limit` decoded bytes. */
function dechunk(raw: Buffer, limit: number): { body: Buffer; complete: boolean } {
  const parts: Buffer[] = [];
  let have = 0;
  let pos = 0;
  for (;;) {
    const eol = raw.indexOf("\r\n", pos, "latin1");
    if (eol < 0) return { body: Buffer.concat(parts), complete: false };
    const size = parseInt(raw.toString("latin1", pos, eol).split(";")[0]!, 16);
    if (!Number.isInteger(size) || size < 0) return { body: Buffer.concat(parts), complete: false };
    if (size === 0) return { body: Buffer.concat(parts), complete: true };
    const chunk = raw.subarray(eol + 2, eol + 2 + size);
    parts.push(chunk);
    have += chunk.length;
    if (chunk.length < size || have >= limit) return { body: Buffer.concat(parts), complete: false };
    pos = eol + 2 + size + 2;
  }
}

/** One GET over `tunnel` (already connected to host:port through the exit). Closes the tunnel. Rejects on timeout / protocol error. */
export async function httpGetOver(tunnel: Duplex, t: FetchTarget, maxBytes: number, timeoutMs = FETCH_TIMEOUT_MS): Promise<FetchResult> {
  const sock: Duplex = t.tls ? tlsConnect({ socket: tunnel, servername: /^[\d.]+$|:/.test(t.host) ? undefined : t.host, minVersion: "TLSv1.2" }) : tunnel;
  try {
    // header block + body, capped: stop reading once the headers plus 2x max_bytes (chunk framing) are in.
    const cap = 64 * 1024 + maxBytes * 2 + 1024;
    const raw = await new Promise<Buffer>((ok, no) => {
      const chunks: Buffer[] = [];
      let n = 0;
      let done = false;
      const finish = (e?: Error): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (e) no(e);
        else ok(Buffer.concat(chunks));
      };
      const timer = setTimeout(() => finish(new Error("timeout")), timeoutMs);
      timer.unref?.();
      sock.on("data", (c: Buffer) => {
        chunks.push(c);
        n += c.length;
        if (n >= cap) finish();
      });
      sock.on("end", () => finish());
      sock.on("close", () => finish());
      sock.on("error", (e) => finish(e));
      sock.write(`GET ${t.path} HTTP/1.1\r\nHost: ${t.hostHeader}\r\nUser-Agent: provenexit-mcp\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n`);
    });
    const split = raw.indexOf("\r\n\r\n", 0, "latin1");
    if (split < 0) throw new Error("no HTTP response");
    const head = raw.toString("latin1", 0, split).split("\r\n");
    const m = /^HTTP\/1\.[01] (\d{3})/.exec(head[0] ?? "");
    if (m === null) throw new Error("not an HTTP response");
    const headers: Record<string, string> = {};
    const all: Record<string, string> = {};
    for (const line of head.slice(1)) {
      const i = line.indexOf(":");
      if (i > 0) all[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    }
    for (const k of SHOWN_HEADERS) if (all[k] !== undefined) headers[k] = all[k]!;
    let body = raw.subarray(split + 4);
    let complete = true;
    if (/chunked/i.test(all["transfer-encoding"] ?? "")) {
      const d = dechunk(body, maxBytes + 1);
      body = d.body;
      complete = d.complete;
    } else if (all["content-length"] !== undefined && /^\d+$/.test(all["content-length"])) {
      complete = body.length >= Number(all["content-length"]);
    }
    const truncated = body.length > maxBytes || !complete;
    const shown = body.subarray(0, maxBytes);
    return { status: Number(m[1]), headers, body: new TextDecoder("utf-8").decode(shown), truncated, bytes: shown.length };
  } finally {
    sock.destroy();
    tunnel.destroy();
  }
}
