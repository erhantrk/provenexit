/** Tunnel hello and key schedule (SPEC-VPN §4.1). */
import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { PlrError, type PlrErrorCode } from "../errors.js";
import { concatBytes, equalBytes, isAllZero, isBytes, utf8 } from "../bytes.js";
import { ecdh, type SessionKeys } from "../crypto/session.js";
import { TUNNEL } from "./constants.js";

const TUNNEL_LABEL = utf8("PLR-VPN-v1/tunnel");
const KEYS_INFO = utf8("PLR-VPN-v1/keys");

export type TunnelKeys = SessionKeys;

function need32(v: unknown, code: PlrErrorCode, what: string): Uint8Array {
  if (!isBytes(v) || v.length !== 32) throw new PlrError(code, `${what} must be 32 bytes`);
  return v;
}

/**
 * `th = SHA256("PLR-VPN-v1/tunnel" ‖ attNonce ‖ epk ‖ xp ‖ ep)`,
 * `okm = HKDF-SHA256(shared, th, "PLR-VPN-v1/keys", 64)`, `kC2s = okm[0:32]`, `kS2c = okm[32:64]`.
 * @throws PlrError E_DECRYPT for an all-zero shared secret, E_BAD_INPUT for wrongly sized inputs
 */
export function deriveTunnel(p: { shared: Uint8Array; attNonce: Uint8Array; epk: Uint8Array; xp: Uint8Array; ep: Uint8Array }): TunnelKeys {
  if (typeof p !== "object" || p === null) throw new PlrError("E_BAD_INPUT", "missing parameters");
  const shared = need32(p.shared, "E_BAD_INPUT", "shared");
  if (isAllZero(shared)) throw new PlrError("E_DECRYPT", "low-order point");
  const th = sha256(concatBytes(
    TUNNEL_LABEL,
    need32(p.attNonce, "E_BAD_INPUT", "attNonce"),
    need32(p.epk, "E_BAD_INPUT", "epk"),
    need32(p.xp, "E_BAD_INPUT", "xp"),
    need32(p.ep, "E_BAD_INPUT", "ep"),
  ));
  const okm = hkdf(sha256, shared, th, KEYS_INFO, 64);
  const keys = { th, kC2s: okm.slice(0, 32), kS2c: okm.slice(32, 64) };
  okm.fill(0);
  return keys;
}

/** `u8(1) ‖ attNonce(32) ‖ epk(32)` */
export function encodeHello(attNonce: Uint8Array, epk: Uint8Array): Uint8Array {
  return concatBytes(
    Uint8Array.of(TUNNEL.VERSION),
    need32(attNonce, "E_BAD_INPUT", "attNonce"),
    need32(epk, "E_BAD_INPUT", "epk"),
  );
}

/** Parses exactly {@link TUNNEL.HELLO_LEN} bytes. @throws PlrError E_TUNNEL_PROTOCOL */
export function parseHello(b: Uint8Array): { attNonce: Uint8Array; epk: Uint8Array } {
  if (!isBytes(b) || b.length !== TUNNEL.HELLO_LEN || b[0] !== TUNNEL.VERSION) {
    throw new PlrError("E_TUNNEL_PROTOCOL", "bad hello");
  }
  return { attNonce: b.slice(1, 33), epk: b.slice(33, 65) };
}

/** Client side: fresh ephemeral X25519 key per call; returns the hello to send and the tunnel keys. */
export function tunnelClientInit(p: { xp: Uint8Array; ep: Uint8Array; attNonce: Uint8Array }): TunnelKeys & { hello: Uint8Array } {
  if (typeof p !== "object" || p === null) throw new PlrError("E_BAD_INPUT", "missing parameters");
  const xp = need32(p.xp, "E_BAD_INPUT", "xp");
  const ep = need32(p.ep, "E_BAD_INPUT", "ep");
  const attNonce = need32(p.attNonce, "E_BAD_INPUT", "attNonce");
  const esk = x25519.utils.randomSecretKey();
  try {
    const epk = x25519.getPublicKey(esk);
    const shared = ecdh(esk, xp);
    try {
      const k = deriveTunnel({ shared, attNonce, epk, xp, ep });
      return { hello: encodeHello(attNonce, epk), th: k.th, kC2s: k.kC2s, kS2c: k.kS2c };
    } finally {
      shared.fill(0);
    }
  } finally {
    esk.fill(0);
  }
}

/**
 * Exit side: parses the hello and derives the tunnel keys from the exit's static X25519 secret.
 * @throws PlrError E_TUNNEL_PROTOCOL (malformed hello), E_DECRYPT (invalid / low-order epk),
 *         E_BAD_INPUT (malformed or mismatched own keys)
 */
export function tunnelServerInit(p: { xs: Uint8Array; xp: Uint8Array; ep: Uint8Array; hello: Uint8Array }): TunnelKeys & { attNonce: Uint8Array } {
  if (typeof p !== "object" || p === null) throw new PlrError("E_BAD_INPUT", "missing parameters");
  const xs = need32(p.xs, "E_BAD_INPUT", "xs");
  const xp = need32(p.xp, "E_BAD_INPUT", "xp");
  const ep = need32(p.ep, "E_BAD_INPUT", "ep");
  const { attNonce, epk } = parseHello(p.hello);
  // Our own key pair must be consistent, otherwise th would bind a key we cannot use.
  if (!equalBytes(x25519.getPublicKey(xs), xp)) throw new PlrError("E_BAD_INPUT", "xs does not match xp");
  const shared = ecdh(xs, epk);
  try {
    const k = deriveTunnel({ shared, attNonce, epk, xp, ep });
    return { attNonce, th: k.th, kC2s: k.kC2s, kS2c: k.kS2c };
  } finally {
    shared.fill(0);
  }
}
