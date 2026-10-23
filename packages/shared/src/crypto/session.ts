/** Request encryption and session key schedule (SPEC §6.3). */
import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { PlrError } from "../errors.js";
import { concatBytes, isAllZero, isBytes, utf8 } from "../bytes.js";

const SESSION_LABEL = utf8("PLR-v1/session");
const KEYS_INFO = utf8("PLR-v1/keys");
const ZERO_NONCE = new Uint8Array(12);
/** Poly1305 tag length. */
export const TAG_LEN = 16;

export interface SessionKeys {
  th: Uint8Array;
  kC2s: Uint8Array;
  kS2c: Uint8Array;
}

function need32(v: unknown): Uint8Array {
  if (!isBytes(v) || v.length !== 32) throw new PlrError("E_DECRYPT");
  return v;
}

/**
 * `th = SHA256("PLR-v1/session" ‖ attNonce ‖ epk ‖ xp ‖ ep)`,
 * `okm = HKDF-SHA256(shared, th, "PLR-v1/keys", 64)`. Rejects all-zero `shared` with E_DECRYPT.
 */
export function deriveSession(p: { shared: Uint8Array; attNonce: Uint8Array; epk: Uint8Array; xp: Uint8Array; ep: Uint8Array }): SessionKeys {
  const shared = need32(p?.shared);
  if (isAllZero(shared)) throw new PlrError("E_DECRYPT", "low-order point");
  const th = sha256(concatBytes(SESSION_LABEL, need32(p.attNonce), need32(p.epk), need32(p.xp), need32(p.ep)));
  const okm = hkdf(sha256, shared, th, KEYS_INFO, 64);
  const keys = { th, kC2s: okm.slice(0, 32), kS2c: okm.slice(32, 64) };
  okm.fill(0);
  return keys;
}

/**
 * X25519 with any failure (invalid / low-order point, all-zero output) mapped to E_DECRYPT.
 * Internal (also used by the VPN tunnel key schedule); not exported from the package index.
 */
export function ecdh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(sk, pk);
  } catch {
    throw new PlrError("E_DECRYPT", "key agreement failed");
  }
  if (shared.length !== 32 || isAllZero(shared)) throw new PlrError("E_DECRYPT", "low-order point");
  return shared;
}

/** Client side: fresh ephemeral X25519 key, encrypts `plaintext` to the attested router keys. */
export function clientSeal(p: { xp: Uint8Array; ep: Uint8Array; attNonce: Uint8Array; plaintext: Uint8Array }): {
  epk: Uint8Array;
  ct: Uint8Array;
  th: Uint8Array;
  kS2c: Uint8Array;
} {
  const xp = need32(p?.xp);
  const ep = need32(p.ep);
  const attNonce = need32(p.attNonce);
  if (!isBytes(p.plaintext)) throw new PlrError("E_BAD_INPUT", "plaintext must be bytes");
  const esk = x25519.utils.randomSecretKey();
  try {
    const epk = x25519.getPublicKey(esk);
    const shared = ecdh(esk, xp);
    const s = deriveSession({ shared, attNonce, epk, xp, ep });
    shared.fill(0);
    const ct = chacha20poly1305(s.kC2s, ZERO_NONCE, s.th).encrypt(p.plaintext);
    s.kC2s.fill(0);
    return { epk, ct, th: s.th, kS2c: s.kS2c };
  } finally {
    esk.fill(0);
  }
}

/** Server side: decrypts a request. Any failure → E_DECRYPT (no detail about which check failed). */
export function serverOpen(p: { xs: Uint8Array; xp: Uint8Array; ep: Uint8Array; attNonce: Uint8Array; epk: Uint8Array; ct: Uint8Array }): {
  plaintext: Uint8Array;
  th: Uint8Array;
  kS2c: Uint8Array;
} {
  const xs = need32(p?.xs);
  const xp = need32(p.xp);
  const ep = need32(p.ep);
  const attNonce = need32(p.attNonce);
  const epk = need32(p.epk);
  if (!isBytes(p.ct) || p.ct.length < TAG_LEN) throw new PlrError("E_DECRYPT");
  const shared = ecdh(xs, epk);
  const s = deriveSession({ shared, attNonce, epk, xp, ep });
  shared.fill(0);
  let plaintext: Uint8Array;
  try {
    plaintext = chacha20poly1305(s.kC2s, ZERO_NONCE, s.th).decrypt(p.ct);
  } catch {
    throw new PlrError("E_DECRYPT");
  } finally {
    s.kC2s.fill(0);
  }
  return { plaintext, th: s.th, kS2c: s.kS2c };
}
