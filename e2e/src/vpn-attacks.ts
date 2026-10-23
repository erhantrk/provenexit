/**
 * ⚠️ Network attackers in front of an HONEST, APPROVED VPN exit (`vpn-honest-test`, SPEC-VPN §9.3). The operator
 * controls the network but not the measured exit code, so every attack is a TCP/HTTP proxy:
 *
 * - `vpn-mitm-key`        rewrites `x25519` in attestation responses to the attacker's own key.
 * - `vpn-replay-quote`    replays its first attestation response for every later nonce.
 * - `vpn-tamper-stream`   flips one ciphertext byte of the first s2c DATA frame of every tunnel.
 * - `vpn-truncate-stream` forwards CONNECT_OK and the first s2c DATA frame, then closes the client socket
 *                         (no FIN frame ever reaches the client).
 *
 * The tunnel cannot be decrypted by the proxy: it parses only the u32be frame lengths (SPEC-VPN §4.2) and knows
 * the frame *types* only from the state machine (s2c frame 0 = CONNECT_OK, s2c frame 1 = the first DATA frame).
 * Proxy log lines (`plr-attack[<kind>]: …`) are content-free: no destination, payload, address or port.
 */
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { TUNNEL } from "@plr/shared";
import { attestationTamperer, fwdHeaders, readAll, request, upstreamOf, type AttackProxy, type Upstream } from "./attacks.js";

export const VPN_ATTACKS = ["vpn-mitm-key", "vpn-replay-quote", "vpn-tamper-stream", "vpn-truncate-stream"] as const;
export type VpnAttackKind = (typeof VPN_ATTACKS)[number];

export function isVpnAttack(v: string): v is VpnAttackKind {
  return (VPN_ATTACKS as readonly string[]).includes(v);
}

/** Bounds: exit JSON replies (receipt proofs, errors) are a few KiB. */
const MAX_REPLY = 256 * 1024;
const UPGRADE_TIMEOUT_MS = 15_000;

/**
 * Splits the s2c byte stream into wire frames by length only and lets `onFrame` decide what to forward.
 * A length outside the SPEC range switches to raw pass-through (the client rejects it anyway).
 */
class FrameCutter {
  #buf: Buffer = Buffer.alloc(0);
  #index = 0;
  #raw = false;
  constructor(
    private readonly onFrame: (index: number, wire: Buffer) => void,
    private readonly onRaw: (b: Buffer) => void,
  ) {}
  push(chunk: Buffer): void {
    if (this.#raw) return this.onRaw(chunk);
    this.#buf = this.#buf.length === 0 ? chunk : Buffer.concat([this.#buf, chunk]);
    while (this.#buf.length >= 4) {
      const len = this.#buf.readUInt32BE(0);
      if (len < TUNNEL.MIN_FRAME_LEN || len > TUNNEL.MAX_FRAME_LEN) {
        this.#raw = true;
        const rest = this.#buf;
        this.#buf = Buffer.alloc(0);
        return this.onRaw(rest);
      }
      if (this.#buf.length < 4 + len) return;
      const wire = Buffer.from(this.#buf.subarray(0, 4 + len)); // own copy: it may be modified
      this.#buf = this.#buf.subarray(4 + len);
      this.onFrame(this.#index++, wire);
    }
  }
}

function rawResponse(status: number, body: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(`HTTP/1.1 ${status} ${http.STATUS_CODES[status] ?? "Error"}\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n`, "latin1"),
    body,
  ]);
}

/**
 * Starts an attacking proxy for `kind` in front of the exit at `upstreamUrl`, on 127.0.0.1 (ephemeral port).
 * @param log receives content-free event lines
 */
export async function startVpnAttackProxy(kind: VpnAttackKind, upstreamUrl: string, log: (line: string) => void): Promise<AttackProxy> {
  const up: Upstream = upstreamOf(upstreamUrl);
  const say = (s: string) => log(`plr-attack[${kind}]: ${s}\n`);
  const att = attestationTamperer(kind === "vpn-mitm-key" ? "mitm-key" : kind === "vpn-replay-quote" ? "replay-quote" : "none", up, say);
  const sockets = new Set<Socket>();
  const track = (s: Socket) => {
    sockets.add(s);
    s.once("close", () => sockets.delete(s));
  };

  /** Relays one upgraded tunnel, applying the stream attack to the s2c direction. */
  function relayTunnel(client: Socket, clientHead: Buffer, upstream: Socket, upHead: Buffer, upgradeToken: string): void {
    track(upstream);
    const kill = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on("error", kill);
    upstream.on("error", kill);
    client.write(`HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nupgrade: ${upgradeToken}\r\n\r\n`);
    // c2s: untouched.
    if (clientHead.length > 0) upstream.write(clientHead);
    client.pipe(upstream);
    // s2c: frame-length parsing only.
    let cut = false;
    const cutter = new FrameCutter(
      (i, wire) => {
        if (cut) return;
        if (kind === "vpn-tamper-stream" && i === 1) {
          const at = 4 + Math.floor((wire.length - 4) / 2);
          wire[at] = wire[at]! ^ 0x01;
          say("flipped one ciphertext byte in s2c frame 1 (first DATA)");
        }
        client.write(wire);
        if (kind === "vpn-truncate-stream" && i === 1) {
          cut = true;
          say("closed the client socket after s2c frame 1 (first DATA), no FIN");
          client.unpipe(upstream);
          client.end();
          upstream.destroy();
        }
      },
      (b) => {
        if (!cut) client.write(b);
      },
    );
    upstream.on("data", (c: Buffer) => cutter.push(c));
    upstream.on("end", () => {
      if (!cut) client.end();
    });
    upstream.on("close", () => {
      if (!cut) client.end();
    });
    if (upHead.length > 0) cutter.push(upHead);
  }

  const server = http.createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0];
    const fail = () => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end('{"error":"E_PROXY"}');
    };
    void (async () => {
      if (req.method === "GET" && path === "/v1/attestation") {
        req.resume();
        return att.handle(req, res);
      }
      const body = req.method === "POST" ? await readAll(req, MAX_REPLY) : (req.resume(), null);
      const r = await request(up, req.method ?? "GET", req.url!, { ...fwdHeaders(req.headers), ...(body ? { "content-length": String(body.length) } : {}) }, body);
      res.writeHead(r.statusCode ?? 502, fwdHeaders(r.headers));
      r.pipe(res);
    })().catch(fail);
  });

  server.on("upgrade", (req: http.IncomingMessage, client: Socket, head: Buffer) => {
    track(client);
    client.on("error", () => client.destroy());
    const token = typeof req.headers.upgrade === "string" ? req.headers.upgrade : "";
    const ureq = http.request({
      host: up.host,
      port: up.port,
      method: req.method ?? "GET",
      path: req.url ?? "/",
      headers: { connection: "Upgrade", upgrade: token },
      agent: false,
    });
    const timer = setTimeout(() => {
      ureq.destroy();
      client.destroy();
    }, UPGRADE_TIMEOUT_MS);
    ureq.on("error", () => {
      clearTimeout(timer);
      client.destroy();
    });
    ureq.on("response", (r: http.IncomingMessage) => {
      clearTimeout(timer);
      readAll(r, MAX_REPLY).then(
        (b) => client.end(rawResponse(r.statusCode ?? 502, b)),
        () => client.destroy(),
      );
    });
    ureq.on("upgrade", (r: http.IncomingMessage, upstream: Socket, upHead: Buffer) => {
      clearTimeout(timer);
      const upToken = typeof r.headers.upgrade === "string" ? r.headers.upgrade : "";
      if (client.destroyed) return void upstream.destroy();
      relayTunnel(client, head, upstream, upHead, upToken);
    });
    ureq.end();
  });

  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => ok());
  });
  const port = (server.address() as AddressInfo).port;
  say(`listening url=http://127.0.0.1:${port}`);
  let closing: Promise<void> | null = null;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      (closing ??= new Promise<void>((ok) => {
        server.close(() => ok());
        server.closeAllConnections();
        for (const s of sockets) s.destroy();
      })),
  };
}
