/**
 * ⚠️ Network attackers for the e2e scenarios (SPEC §13). The operator controls the network and the host but
 * cannot change the measured router code, so every attack here is an HTTP proxy in front of an HONEST,
 * APPROVED router:
 *
 * - `mitm-key`       rewrites `x25519` in attestation responses to its own key; if a (broken) client ever
 *                    sealed a prompt to that key it decrypts it, prints it ("stolen"), and relays the session
 *                    to the real router re-encrypting both directions.
 * - `replay-quote`   caches the first `/v1/attestation` response and serves it for every later nonce.
 * - `truncate-stream` drops the final (fin=1) SSE frame of `/v1/private/chat`.
 * - `tamper-stream`  flips one byte of a mid-stream frame's ciphertext.
 *
 * Proxy log lines (`plr-attack[<kind>]: …`) are content-free except where the attack itself succeeds in
 * stealing plaintext — which the scenarios assert never happens.
 *
 * The attestation attacks (`attestationTamperer`) and the HTTP helpers are shared with the VPN-exit attackers
 * in ./vpn-attacks.ts (SPEC-VPN §9.3).
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import { x25519 } from "@noble/curves/ed25519.js";
import { clientSeal, fromHex, isHex, openFrame, sealFrame, serverOpen, toHex } from "@plr/shared";

export const ATTACKS = ["mitm-key", "replay-quote", "truncate-stream", "tamper-stream"] as const;
export type AttackKind = (typeof ATTACKS)[number];

export function isAttack(v: string): v is AttackKind {
  return (ATTACKS as readonly string[]).includes(v);
}

export interface AttackProxy {
  url: string;
  close(): Promise<void>;
}

/** Bounds: the router accepts ≤ 1 MiB requests; attestation responses are a few KiB. */
const MAX_REQ = 2 * 1024 * 1024;
export const MAX_ATTESTATION = 256 * 1024;
const HOP_BY_HOP = new Set(["connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection", "te", "trailer", "host", "content-length"]);

export function readAll(stream: NodeJS.ReadableStream, max: number): Promise<Buffer> {
  return new Promise((ok, fail) => {
    const chunks: Buffer[] = [];
    let n = 0;
    stream.on("data", (c: Buffer) => {
      n += c.length;
      if (n > max) {
        fail(new Error("too large"));
        return;
      }
      chunks.push(c);
    });
    stream.on("end", () => ok(Buffer.concat(chunks)));
    stream.on("error", fail);
  });
}

export function fwdHeaders(h: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(h)) if (v !== undefined && !HOP_BY_HOP.has(k.toLowerCase())) out[k] = v;
  return out;
}

/** One SSE event of the router stream: `data: {"seq":n,"ct":"<base64>"}`. */
interface Frame {
  seq: number;
  ct: Buffer;
}

function parseFrame(event: string): Frame | null {
  const line = event.split("\n").find((l) => l.startsWith("data: "));
  if (!line) return null;
  try {
    const o = JSON.parse(line.slice(6)) as { seq?: unknown; ct?: unknown };
    if (typeof o.seq !== "number" || typeof o.ct !== "string") return null;
    return { seq: o.seq, ct: Buffer.from(o.ct, "base64") };
  } catch {
    return null;
  }
}

const formatFrame = (f: Frame) => `data: ${JSON.stringify({ seq: f.seq, ct: f.ct.toString("base64") })}\n\n`;

/** Splits an SSE byte stream into complete events (separated by a blank line). */
class SseSplitter {
  #buf = "";
  push(chunk: string): string[] {
    this.#buf += chunk.replace(/\r\n/g, "\n");
    const out: string[] = [];
    for (let i = this.#buf.indexOf("\n\n"); i >= 0; i = this.#buf.indexOf("\n\n")) {
      out.push(this.#buf.slice(0, i));
      this.#buf = this.#buf.slice(i + 2);
    }
    return out;
  }
}

export interface Upstream {
  host: string;
  port: number;
}

export function upstreamOf(url: string): Upstream {
  const u = new URL(url);
  if (u.protocol !== "http:") throw new Error("attack proxy: upstream must be http");
  return { host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port || 80) };
}

export function request(up: Upstream, method: string, path: string, headers: http.OutgoingHttpHeaders, body: Buffer | null): Promise<http.IncomingMessage> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: up.host, port: up.port, method, path, headers, agent: false }, ok);
    req.on("error", fail);
    req.end(body ?? undefined);
  });
}

/** Attestation-response attacks shared by the router and the VPN-exit proxies. */
export type AttestationAttack = "mitm-key" | "replay-quote" | "none";

export interface AttestationTamperer {
  /** Serves `GET /v1/attestation…` (forwarded upstream, rewritten / replayed according to the attack). */
  handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void>;
  /** mitm-key: the attacker's X25519 key pair. */
  readonly mitm: { sk: Uint8Array; pk: Uint8Array };
  /** mitm-key: the genuine (x25519, ed25519) keys of the last swapped response, if any. */
  realKeys(): { xp: Uint8Array; ep: Uint8Array } | null;
}

/**
 * `mitm-key` rewrites `x25519` in 200 attestation responses to the attacker's key; `replay-quote` caches the
 * first 200 response and serves it for every later nonce; `none` forwards unchanged.
 */
export function attestationTamperer(kind: AttestationAttack, up: Upstream, say: (s: string) => void): AttestationTamperer {
  const mitmSk = x25519.utils.randomSecretKey();
  const mitmPk = x25519.getPublicKey(mitmSk);
  let real: { xp: Uint8Array; ep: Uint8Array } | null = null;
  let cached: { status: number; headers: http.OutgoingHttpHeaders; body: Buffer } | null = null;

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (kind === "replay-quote" && cached) {
      say("replayed cached attestation");
      res.writeHead(cached.status, { ...cached.headers, "content-length": String(cached.body.length) });
      res.end(cached.body);
      return;
    }
    const r = await request(up, "GET", req.url!, fwdHeaders(req.headers), null);
    let body = await readAll(r, MAX_ATTESTATION);
    const headers = fwdHeaders(r.headers);
    if (r.statusCode === 200 && kind === "mitm-key") {
      const o = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
      if (isHex(o.x25519, 32) && isHex(o.ed25519, 32)) {
        real = { xp: fromHex(o.x25519, 32), ep: fromHex(o.ed25519, 32) };
        o.x25519 = toHex(mitmPk);
        body = Buffer.from(JSON.stringify(o));
        say("swapped x25519 in attestation response");
      }
    }
    if (r.statusCode === 200 && kind === "replay-quote" && !cached) {
      cached = { status: 200, headers, body };
      say("cached first attestation");
    }
    res.writeHead(r.statusCode ?? 502, { ...headers, "content-length": String(body.length) });
    res.end(body);
  }

  return { handle, mitm: { sk: mitmSk, pk: mitmPk }, realKeys: () => real };
}

/**
 * Starts an attacking proxy for `kind` in front of `upstreamUrl` on 127.0.0.1 (ephemeral port).
 * @param log receives content-free event lines
 */
export async function startAttackProxy(kind: AttackKind, upstreamUrl: string, log: (line: string) => void): Promise<AttackProxy> {
  const up = upstreamOf(upstreamUrl);
  const say = (s: string) => log(`plr-attack[${kind}]: ${s}\n`);
  const att = attestationTamperer(kind === "mitm-key" || kind === "replay-quote" ? kind : "none", up, say);
  const mitmSk = att.mitm.sk;
  const mitmPk = att.mitm.pk;

  /** mitm-key: try to open the client's request with the attacker key; relay re-encrypted if it worked. */
  async function handleMitmChat(req: http.IncomingMessage, res: http.ServerResponse, body: Buffer): Promise<void> {
    let env: { v: number; att_nonce: string; epk: string; ct: string };
    try {
      env = JSON.parse(body.toString("utf8")) as typeof env;
    } catch {
      return void pipeThrough(req, res, body);
    }
    const real = att.realKeys();
    if (!real || !isHex(env.att_nonce, 32) || !isHex(env.epk, 32) || typeof env.ct !== "string") {
      say("chat request not decryptable (no attestation seen)");
      return void pipeThrough(req, res, body);
    }
    const attNonce = fromHex(env.att_nonce, 32);
    let opened: ReturnType<typeof serverOpen>;
    try {
      opened = serverOpen({ xs: mitmSk, xp: mitmPk, ep: real.ep, attNonce, epk: fromHex(env.epk, 32), ct: Buffer.from(env.ct, "base64") });
    } catch {
      say("could not decrypt the request with the attacker key; forwarding unchanged");
      return void pipeThrough(req, res, body);
    }
    // The attack worked: this is what a client without attestation checks would leak.
    say(`STOLEN prompt: ${Buffer.from(opened.plaintext).toString("utf8")}`);
    const sealed = clientSeal({ xp: real.xp, ep: real.ep, attNonce, plaintext: opened.plaintext });
    const fwd = Buffer.from(JSON.stringify({ v: 1, att_nonce: env.att_nonce, epk: toHex(sealed.epk), ct: Buffer.from(sealed.ct).toString("base64") }));
    const r = await request(up, "POST", req.url!, { ...fwdHeaders(req.headers), "content-type": "application/json", "content-length": String(fwd.length) }, fwd);
    res.writeHead(r.statusCode ?? 502, fwdHeaders(r.headers));
    if (r.statusCode !== 200) return void r.pipe(res);
    const sp = new SseSplitter();
    r.setEncoding("utf8");
    r.on("data", (chunk: string) => {
      for (const ev of sp.push(chunk)) {
        const f = parseFrame(ev);
        if (!f) continue;
        for (const fin of [false, true]) {
          try {
            const pt = openFrame(sealed.kS2c, sealed.th, f.seq, fin, f.ct);
            res.write(formatFrame({ seq: f.seq, ct: Buffer.from(sealFrame(opened.kS2c, opened.th, f.seq, fin, pt)) }));
            break;
          } catch {
            /* try the other fin value */
          }
        }
      }
    });
    r.on("end", () => res.end());
    r.on("error", () => res.destroy());
  }

  function pipeThrough(req: http.IncomingMessage, res: http.ServerResponse, body: Buffer | null): Promise<void> {
    return request(up, req.method ?? "GET", req.url!, { ...fwdHeaders(req.headers), ...(body ? { "content-length": String(body.length) } : {}) }, body).then((r) => {
      res.writeHead(r.statusCode ?? 502, fwdHeaders(r.headers));
      r.pipe(res);
    });
  }

  /** truncate-stream / tamper-stream: rewrite the router's SSE frames (one event of look-ahead). */
  async function handleStreamAttack(req: http.IncomingMessage, res: http.ServerResponse, body: Buffer): Promise<void> {
    const r = await request(up, "POST", req.url!, { ...fwdHeaders(req.headers), "content-length": String(body.length) }, body);
    res.writeHead(r.statusCode ?? 502, fwdHeaders(r.headers));
    if (r.statusCode !== 200) return void r.pipe(res);
    const sp = new SseSplitter();
    let held: string | null = null;
    let tampered = false;
    const emit = (ev: string, isLast: boolean) => {
      if (kind === "truncate-stream" && isLast) {
        const f = parseFrame(ev);
        say(`dropped final frame seq=${f?.seq ?? "?"}`);
        return;
      }
      if (kind === "tamper-stream" && !tampered) {
        const f = parseFrame(ev);
        // Prefer a mid-stream frame (seq ≥ 1, not final); fall back to the last frame if the stream is short.
        if (f && f.ct.length > 0 && ((f.seq >= 1 && !isLast) || isLast)) {
          const i = Math.floor(f.ct.length / 2);
          f.ct[i] = f.ct[i]! ^ 0x01;
          tampered = true;
          say(`flipped one ciphertext byte in frame seq=${f.seq}`);
          res.write(formatFrame(f));
          return;
        }
      }
      res.write(ev + "\n\n");
    };
    r.setEncoding("utf8");
    r.on("data", (chunk: string) => {
      for (const ev of sp.push(chunk)) {
        if (held !== null) emit(held, false);
        held = ev;
      }
    });
    r.on("end", () => {
      if (held !== null) emit(held, true);
      res.end();
    });
    r.on("error", () => res.destroy());
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
      const body = req.method === "POST" ? await readAll(req, MAX_REQ) : (req.resume(), null);
      if (req.method === "POST" && path === "/v1/private/chat" && body) {
        if (kind === "mitm-key") return handleMitmChat(req, res, body);
        if (kind === "truncate-stream" || kind === "tamper-stream") return handleStreamAttack(req, res, body);
      }
      return pipeThrough(req, res, body);
    })().catch(fail);
  });
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => ok());
  });
  const port = (server.address() as AddressInfo).port;
  say(`listening url=http://127.0.0.1:${port} upstream=${upstreamUrl}`);
  let closing: Promise<void> | null = null;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      (closing ??= new Promise<void>((ok) => {
        server.close(() => ok());
        server.closeAllConnections();
      })),
  };
}
