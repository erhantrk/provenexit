/**
 * Local SOCKS5 front end of the VPN client (SPEC-VPN §8, §9.2): RFC 1928, no-auth, CONNECT only, loopback only.
 * Hostnames are passed to the exit unresolved (`socks5h`: remote DNS); the client never resolves destinations.
 *
 * Per connection: the greeting and request are parsed with the `@plr/shared` codecs under a byte cap and a
 * handshake timeout; `VpnClient.connect` runs every SPEC-VPN §7 check; the reply is `socksReplyFor(code)`. On
 * failure the reply is sent and the connection closed — nothing is contacted. On success bytes are piped both
 * ways with backpressure; a tunnel failure resets the SOCKS connection (never a clean EOF). Nothing is logged.
 */
import { createServer, type Server, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import {
  PlrError,
  SOCKS,
  SOCKS_REP,
  encodeSocksReply,
  isPlrError,
  parseIpv4,
  parseSocksGreeting,
  parseSocksRequest,
  socksReplyFor,
  type SocksRequest,
} from "@plr/shared";
import { isPlainObject } from "../util.js";
import type { VpnClient } from "./client.js";
import type { VpnStream } from "./stream.js";

export interface VpnProxyOptions {
  port: number;
  /** Bind address: a loopback IP literal only (default `127.0.0.1`). */
  host?: string;
  client: VpnClient;
  /** Max simultaneous SOCKS connections (default 256). */
  maxConnections?: number;
  /** Max time from accept to a complete SOCKS request (default 10 s). */
  handshakeTimeoutMs?: number;
}

export interface VpnProxyHandle {
  /** `socks5h://<host>:<port>` — the `h` tells clients to let the proxy resolve names (remote DNS). */
  url: string;
  port: number;
  close(): Promise<void>;
}

/** Greeting ≤ 2 + 255 bytes, request ≤ 4 + 1 + 255 + 2 bytes: anything beyond is not SOCKS5. */
const MAX_HANDSHAKE_BYTES = 1024;
const DEFAULT_MAX_CONNECTIONS = 256;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/** 127.0.0.0/8 or ::1 as an IP literal (no names: binding must not depend on DNS). */
function isLoopbackLiteral(h: string): boolean {
  if (h === "::1") return true;
  const b = parseIpv4(h);
  return b !== null && b[0] === 127;
}

function isLoopbackPeer(addr: string | undefined): boolean {
  if (addr === undefined) return false;
  if (addr === "::1") return true;
  const v4 = addr.startsWith("::ffff:") ? addr.slice(7) : addr;
  return isLoopbackLiteral(v4);
}

/** Unknown ATYP is the one malformed request that gets its own reply (0x08, SPEC-VPN §9.1). */
function unknownAtyp(b: Uint8Array): boolean {
  return b.length >= 4 && b[0] === SOCKS.VERSION && b[2] === 0 && ![SOCKS.ATYP_IPV4, SOCKS.ATYP_DOMAIN, SOCKS.ATYP_IPV6].includes(b[3] as 1 | 3 | 4);
}

/** Abortive close (RST where supported): the application must not mistake a failure for a clean EOF. */
function reset(sock: Socket): void {
  if (sock.destroyed) return;
  if (typeof sock.resetAndDestroy === "function") sock.resetAndDestroy();
  else sock.destroy();
}

/** Writes `bytes` (if still possible) and closes our side; the peer may linger ≤ 1 s before a hard close. */
function replyAndClose(sock: Socket, rep: number | Uint8Array): void {
  if (sock.destroyed) return;
  sock.removeAllListeners("data");
  sock.pause();
  sock.end(typeof rep === "number" ? encodeSocksReply(rep) : rep);
  setTimeout(() => sock.destroy(), 1000).unref();
}

export async function startVpn(o: VpnProxyOptions): Promise<VpnProxyHandle> {
  if (!isPlainObject(o)) throw new PlrError("E_BAD_INPUT", "options required");
  const { client } = o;
  if (typeof client !== "object" || client === null || typeof client.connect !== "function") {
    throw new PlrError("E_BAD_INPUT", "client required");
  }
  if (!Number.isSafeInteger(o.port) || o.port < 0 || o.port > 65535) throw new PlrError("E_BAD_INPUT", "bad port");
  const host = o.host ?? "127.0.0.1";
  if (typeof host !== "string" || !isLoopbackLiteral(host)) throw new PlrError("E_BAD_INPUT", "the SOCKS5 proxy binds to a loopback address only");
  const maxConnections = o.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 65_536) throw new PlrError("E_BAD_INPUT", "bad maxConnections");
  const handshakeMs = o.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  if (!Number.isSafeInteger(handshakeMs) || handshakeMs < 1 || handshakeMs > 600_000) throw new PlrError("E_BAD_INPUT", "bad handshakeTimeoutMs");

  const sockets = new Set<Socket>();
  const tunnels = new Set<VpnStream>();
  let closing = false;

  const server: Server = createServer({ allowHalfOpen: true, pauseOnConnect: false }, (sock) => {
    if (closing || !isLoopbackPeer(sock.remoteAddress)) {
      sock.destroy();
      return;
    }
    sockets.add(sock);
    sock.on("close", () => sockets.delete(sock));
    sock.on("error", () => sock.destroy());
    handleConnection(sock);
  });
  server.maxConnections = maxConnections;

  function handleConnection(sock: Socket): void {
    let buf = new Uint8Array(0);
    let stage: "greeting" | "request" | "connecting" = "greeting";
    const timer = setTimeout(() => sock.destroy(), handshakeMs);
    timer.unref();
    sock.on("close", () => clearTimeout(timer));

    const onData = (chunk: Buffer): void => {
      if (buf.length + chunk.length > MAX_HANDSHAKE_BYTES) {
        sock.destroy();
        return;
      }
      const next = new Uint8Array(buf.length + chunk.length);
      next.set(buf, 0);
      next.set(chunk, buf.length);
      buf = next;
      try {
        if (stage === "greeting") {
          const g = parseSocksGreeting(buf);
          if (g === null) return;
          buf = buf.slice(g.consumed);
          if (!g.methods.includes(SOCKS.METHOD_NO_AUTH)) {
            replyAndClose(sock, Uint8Array.of(SOCKS.VERSION, SOCKS.METHOD_NONE_ACCEPTABLE));
            return;
          }
          sock.write(Uint8Array.of(SOCKS.VERSION, SOCKS.METHOD_NO_AUTH));
          stage = "request";
        }
        if (stage === "request") {
          if (buf.length === 0) return;
          const req = parseSocksRequest(buf);
          if (req === null) return;
          stage = "connecting";
          clearTimeout(timer);
          sock.removeListener("data", onData);
          sock.pause();
          const early = buf.slice(req.consumed); // bytes an optimistic client sent before our reply
          buf = new Uint8Array(0);
          if (req.cmd !== SOCKS.CMD_CONNECT) {
            replyAndClose(sock, SOCKS_REP.COMMAND_NOT_SUPPORTED);
            return;
          }
          void connectAndPipe(sock, req, early);
        }
      } catch {
        // Malformed SOCKS (E_BAD_INPUT): unknown ATYP → 0x08, anything else → close (0x01 once in the request stage).
        if (stage === "greeting") sock.destroy();
        else replyAndClose(sock, unknownAtyp(buf) ? SOCKS_REP.ATYP_NOT_SUPPORTED : SOCKS_REP.GENERAL_FAILURE);
      }
    };
    sock.on("data", onData);
  }

  async function connectAndPipe(sock: Socket, req: SocksRequest, early: Uint8Array): Promise<void> {
    let stream: VpnStream;
    try {
      stream = await client.connect(req.host, req.port);
    } catch (e) {
      replyAndClose(sock, socksReplyFor(isPlrError(e) ? e.code : "E_INTERNAL"));
      return;
    }
    if (sock.destroyed || closing) {
      stream.destroy();
      return;
    }
    tunnels.add(stream);
    stream.receipt().catch(() => undefined);
    stream.on("close", () => tunnels.delete(stream));
    // Tunnel failure (E_DECRYPT / E_TRUNCATED / …): reset the application connection, never a clean EOF.
    stream.on("error", () => reset(sock));
    sock.on("error", () => stream.destroy());
    sock.on("close", () => {
      if (!stream.writableEnded) stream.destroy(); // application vanished without a half-close
    });
    sock.write(encodeSocksReply(SOCKS_REP.SUCCEEDED));
    if (early.length > 0) stream.write(early);
    // pipe(): backpressure both ways; EOF on one side half-closes the other (s2c FIN → sock.end, sock EOF → c2s FIN).
    stream.pipe(sock);
    sock.pipe(stream);
    sock.resume();
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const port = (server.address() as AddressInfo).port;
  const urlHost = host.includes(":") ? `[${host}]` : host;
  return {
    url: `socks5h://${urlHost}:${port}`,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        closing = true;
        server.close(() => resolve());
        for (const t of tunnels) t.destroy();
        for (const s of sockets) s.destroy();
      }),
  };
}
