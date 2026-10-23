/** Test-side client for the router (independent of @plr/client): attest, verify, seal, read frames. */
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  FrameReader, MemoryRegistry, MockVerifier, clientSeal, fromHex, keyHash, osMeasurement, mockOsReport, toHex,
  verifyAttestation, verifyReceipt, type AttestationBundle, type Receipt, type VerifiedRouter,
} from "@plr/shared";

export async function attest(url: string, rootPub: Uint8Array, opts: { registered?: boolean } = {}): Promise<VerifiedRouter & { bundle: AttestationBundle }> {
  const nonce = randomBytes(32);
  const res = await fetch(`${url}/v1/attestation?nonce=${toHex(nonce)}`);
  if (res.status !== 200) throw new Error(`attestation status ${res.status}`);
  const bundle = (await res.json()) as AttestationBundle;
  const composeHash = toHex(sha256(new TextEncoder().encode(bundle.app_compose)));
  const os = toHex(osMeasurement(mockOsReport()));
  const xp = fromHex(bundle.x25519, 32), ep = fromHex(bundle.ed25519, 32);
  const kh = toHex(keyHash(xp, ep));
  const registry = new MemoryRegistry({
    root: { kind: "MOCK", p256: toHex(rootPub) },
    compose: [composeHash],
    os: [os],
    instances: opts.registered === false ? {} : {
      [kh]: { compose_hash: composeHash, os_measurement: os, x25519: bundle.x25519, ed25519: bundle.ed25519, operator: "op.test", org_id: null, registered_at_ms: Date.now(), expires_at_ms: Date.now() + 3_600_000, next_seq: 0 },
    },
  });
  const v = await verifyAttestation({ bundle, nonce, verifier: new MockVerifier(rootPub), registry, trustedRoot: rootPub });
  return { ...v, bundle };
}

export interface ChatOutcome {
  status: number;
  content: string;
  deltas: string[];
  receipt?: Receipt;
  sig?: string;
  error?: string;
  /** Raw SSE body (ciphertext only). */
  raw: string;
  th: Uint8Array;
  ct: Uint8Array;
  respCts: Uint8Array[];
}

export function seal(v: { x25519: Uint8Array; ed25519: Uint8Array }, plaintext: Uint8Array, attNonce = randomBytes(32)) {
  const s = clientSeal({ xp: v.x25519, ep: v.ed25519, attNonce, plaintext });
  const body = JSON.stringify({ v: 1, att_nonce: toHex(attNonce), epk: toHex(s.epk), ct: Buffer.from(s.ct).toString("base64") });
  return { ...s, attNonce, body };
}

export async function postChat(url: string, body: string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(`${url}/v1/private/chat`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
}

export async function readFrames(res: Response, kS2c: Uint8Array, th: Uint8Array): Promise<Omit<ChatOutcome, "ct" | "th">> {
  const raw = await res.text();
  const reader = new FrameReader(kS2c, th);
  const deltas: string[] = [];
  const respCts: Uint8Array[] = [];
  let receipt: Receipt | undefined, sig: string | undefined, error: string | undefined;
  for (const ev of raw.split("\n\n")) {
    if (!ev.startsWith("data: ")) continue;
    const f = JSON.parse(ev.slice(6)) as { seq: number; ct: string };
    const ct = new Uint8Array(Buffer.from(f.ct, "base64"));
    const { fin, plaintext } = reader.push(f.seq, ct);
    const m = JSON.parse(new TextDecoder().decode(plaintext));
    if (!fin) { respCts.push(ct); deltas.push(m.content); }
    else if (m.type === "receipt") { receipt = m.receipt; sig = m.sig; }
    else error = m.code;
  }
  reader.end();
  return { status: res.status, content: deltas.join(""), deltas, receipt, sig, error, raw, respCts };
}

export async function chat(url: string, v: { x25519: Uint8Array; ed25519: Uint8Array }, req: object): Promise<ChatOutcome> {
  const s = seal(v, new TextEncoder().encode(JSON.stringify(req)));
  const res = await postChat(url, s.body);
  if (res.status !== 200) return { status: res.status, content: "", deltas: [], error: ((await res.json()) as { error: string }).error, raw: "", th: s.th, ct: s.ct, respCts: [] };
  return { ...(await readFrames(res, s.kS2c, s.th)), th: s.th, ct: s.ct };
}

export function checkReceipt(o: ChatOutcome, v: { ed25519: Uint8Array; keyHash: Uint8Array; composeHash: Uint8Array }): boolean {
  if (!o.receipt || !o.sig) return false;
  const r = o.receipt;
  const respHash = sha256(new Uint8Array(Buffer.concat(o.respCts)));
  return verifyReceipt(r, o.sig, v.ed25519) && r.th === toHex(o.th) && r.req_hash === toHex(sha256(o.ct)) &&
    r.resp_hash === toHex(respHash) && r.key_hash === toHex(v.keyHash) && r.compose_hash === toHex(v.composeHash);
}
