/**
 * ⚠️ Shared pieces of the network attackers (./vpn-attacks.ts, SPEC-VPN §9.3). The operator controls the network and
 * the host but cannot change the measured exit code, so every attack is a proxy in front of an HONEST, APPROVED exit.
 * This module holds the HTTP helpers and the attestation-response attacks:
 *
 * - `mitm-key`     rewrites `x25519` in attestation responses to the attacker's own key.
 * - `replay-quote` caches the first `/v1/attestation` response and serves it for every later nonce.
 */
import http from "node:http";
import { x25519 } from "@noble/curves/ed25519.js";
import { fromHex, isHex, toHex } from "@plr/shared";

export interface AttackProxy {
  url: string;
  close(): Promise<void>;
}

/** Bound: attestation responses are a few KiB (INTEL bundles with collateral stay far below this). */
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

/** Attestation-response attacks of the VPN-exit proxies. */
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
