/**
 * Tunnel handshake v2 and key schedule (SPEC-VPN §4.1, rev 2): client ephemeral + exit ephemeral X25519 keys.
 *
 *   dh1 = X25519(e_c, xp)   = X25519(xs, epk_c)   authenticates the attested exit
 *   dh2 = X25519(e_c, epk_s) = X25519(e_s, epk_c) per-tunnel freshness (replay protection) + forward secrecy
 *
 * Every ephemeral secret and intermediate DH output is zeroed as soon as the tunnel keys are derived.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { PlrError, type PlrErrorCode } from "../errors.js";
import { concatBytes, equalBytes, isAllZero, isBytes, utf8 } from "../bytes.js";
import { ecdh, type SessionKeys } from "../crypto/session.js";
import { TUNNEL } from "./constants.js";

const TUNNEL_LABEL = utf8("PLR-VPN-v2/tunnel");
const KEYS_INFO = utf8("PLR-VPN-v2/keys");

export type TunnelKeys = SessionKeys;

/** Client handshake state returned by {@link tunnelClientStart}. */
export interface TunnelClientHandshake {
  /** `u8(2) ‖ att_nonce ‖ epk_c` — the first {@link TUNNEL.HELLO_LEN} bytes the client sends. */
  readonly hello: Uint8Array;
  /**
   * Processes the exit's `server_hello` and derives the tunnel keys. Callable at most once; every call (also a
   * failing one) zeroes the client ephemeral secret.
   * @throws PlrError E_TUNNEL_PROTOCOL (malformed server_hello, or a second call), E_DECRYPT (low-order epk_s)
   */
  finish(serverHello: Uint8Array): TunnelKeys;
  /** Zeroes the client ephemeral secret without finishing (e.g. the socket closed first). Idempotent. */
  abort(): void;
}

/** Exit handshake result returned by {@link tunnelServerAccept}. */
export interface TunnelServerHandshake extends TunnelKeys {
  /** `u8(2) ‖ epk_s` — sent to the client right after a valid hello. */
  serverHello: Uint8Array;
  attNonce: Uint8Array;
}

function need32(v: unknown, code: PlrErrorCode, what: string): Uint8Array {
  if (!isBytes(v) || v.length !== 32) throw new PlrError(code, `${what} must be 32 bytes`);
  return v;
}

function requireParams(p: unknown): void {
  if (typeof p !== "object" || p === null) throw new PlrError("E_BAD_INPUT", "missing parameters");
}

/**
 * `th = SHA256("PLR-VPN-v2/tunnel" ‖ attNonce ‖ epkC ‖ epkS ‖ xp ‖ ep)`,
 * `okm = HKDF-SHA256(dh1 ‖ dh2, th, "PLR-VPN-v2/keys", 64)`, `kC2s = okm[0:32]`, `kS2c = okm[32:64]`.
 * Does not zero the caller's `dh1` / `dh2` (the caller owns them); zeroes its own copies.
 * @throws PlrError E_DECRYPT if `dh1` or `dh2` is all-zero, E_BAD_INPUT for wrongly sized inputs
 */
export function deriveTunnel(p: {
  dh1: Uint8Array; dh2: Uint8Array; attNonce: Uint8Array; epkC: Uint8Array; epkS: Uint8Array; xp: Uint8Array; ep: Uint8Array;
}): TunnelKeys {
  requireParams(p);
  const dh1 = need32(p.dh1, "E_BAD_INPUT", "dh1");
  const dh2 = need32(p.dh2, "E_BAD_INPUT", "dh2");
  const th = sha256(concatBytes(
    TUNNEL_LABEL,
    need32(p.attNonce, "E_BAD_INPUT", "attNonce"),
    need32(p.epkC, "E_BAD_INPUT", "epkC"),
    need32(p.epkS, "E_BAD_INPUT", "epkS"),
    need32(p.xp, "E_BAD_INPUT", "xp"),
    need32(p.ep, "E_BAD_INPUT", "ep"),
  ));
  // Both checks always run (no early exit revealing which one failed).
  const zero1 = isAllZero(dh1), zero2 = isAllZero(dh2);
  if (zero1 || zero2) throw new PlrError("E_DECRYPT", "low-order point");
  const ikm = concatBytes(dh1, dh2);
  try {
    const okm = hkdf(sha256, ikm, th, KEYS_INFO, 64);
    const keys = { th, kC2s: okm.slice(0, 32), kS2c: okm.slice(32, 64) };
    okm.fill(0);
    return keys;
  } finally {
    ikm.fill(0);
  }
}

/** `u8(2) ‖ attNonce(32) ‖ epkC(32)` @throws PlrError E_BAD_INPUT */
export function encodeHello(attNonce: Uint8Array, epkC: Uint8Array): Uint8Array {
  return concatBytes(
    Uint8Array.of(TUNNEL.VERSION),
    need32(attNonce, "E_BAD_INPUT", "attNonce"),
    need32(epkC, "E_BAD_INPUT", "epkC"),
  );
}

/** Parses exactly {@link TUNNEL.HELLO_LEN} bytes with version 2. @throws PlrError E_TUNNEL_PROTOCOL */
export function parseHello(b: Uint8Array): { attNonce: Uint8Array; epkC: Uint8Array } {
  if (!isBytes(b) || b.length !== TUNNEL.HELLO_LEN || b[0] !== TUNNEL.VERSION) {
    throw new PlrError("E_TUNNEL_PROTOCOL", "bad hello");
  }
  return { attNonce: b.slice(1, 33), epkC: b.slice(33, 65) };
}

/** `u8(2) ‖ epkS(32)` @throws PlrError E_BAD_INPUT */
export function encodeServerHello(epkS: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(TUNNEL.VERSION), need32(epkS, "E_BAD_INPUT", "epkS"));
}

/** Parses exactly {@link TUNNEL.SERVER_HELLO_LEN} bytes with version 2. @throws PlrError E_TUNNEL_PROTOCOL */
export function parseServerHello(b: Uint8Array): { epkS: Uint8Array } {
  if (!isBytes(b) || b.length !== TUNNEL.SERVER_HELLO_LEN || b[0] !== TUNNEL.VERSION) {
    throw new PlrError("E_TUNNEL_PROTOCOL", "bad server hello");
  }
  return { epkS: b.slice(1, 33) };
}

/**
 * Client side: creates a fresh ephemeral X25519 key and the hello. Keys are derived by `finish(serverHello)`.
 * @throws PlrError E_BAD_INPUT (malformed attested keys / nonce)
 */
export function tunnelClientStart(p: { xp: Uint8Array; ep: Uint8Array; attNonce: Uint8Array }): TunnelClientHandshake {
  requireParams(p);
  const xp = need32(p.xp, "E_BAD_INPUT", "xp").slice();
  const ep = need32(p.ep, "E_BAD_INPUT", "ep").slice();
  const attNonce = need32(p.attNonce, "E_BAD_INPUT", "attNonce").slice();
  const esk = x25519.utils.randomSecretKey();
  let epkC: Uint8Array;
  try {
    epkC = x25519.getPublicKey(esk);
  } catch (e) {
    esk.fill(0);
    throw e;
  }
  const hello = encodeHello(attNonce, epkC);
  let used = false;
  const abort = (): void => {
    used = true;
    esk.fill(0);
  };
  const finish = (serverHello: Uint8Array): TunnelKeys => {
    if (used) throw new PlrError("E_TUNNEL_PROTOCOL", "handshake already finished");
    used = true;
    let dh1: Uint8Array | undefined, dh2: Uint8Array | undefined;
    try {
      const { epkS } = parseServerHello(serverHello);
      dh1 = ecdh(esk, xp);
      dh2 = ecdh(esk, epkS);
      return deriveTunnel({ dh1, dh2, attNonce, epkC, epkS, xp, ep });
    } finally {
      esk.fill(0);
      dh1?.fill(0);
      dh2?.fill(0);
    }
  };
  return { hello: hello.slice(), finish, abort };
}

/**
 * Exit side: parses the client hello, creates a fresh ephemeral X25519 key and derives the tunnel keys from
 * the exit's static X25519 secret and the ephemeral. A replayed hello therefore yields different keys.
 * @throws PlrError E_TUNNEL_PROTOCOL (malformed hello), E_DECRYPT (invalid / low-order epk_c),
 *         E_BAD_INPUT (malformed or mismatched own keys)
 */
export function tunnelServerAccept(p: { xs: Uint8Array; xp: Uint8Array; ep: Uint8Array; hello: Uint8Array }): TunnelServerHandshake {
  requireParams(p);
  const { attNonce, epkC } = parseHello(p.hello);
  const xs = need32(p.xs, "E_BAD_INPUT", "xs");
  const xp = need32(p.xp, "E_BAD_INPUT", "xp");
  const ep = need32(p.ep, "E_BAD_INPUT", "ep");
  // Our own key pair must be consistent, otherwise th would bind a key we cannot use.
  if (!equalBytes(x25519.getPublicKey(xs), xp)) throw new PlrError("E_BAD_INPUT", "xs does not match xp");
  const ess = x25519.utils.randomSecretKey();
  let dh1: Uint8Array | undefined, dh2: Uint8Array | undefined;
  try {
    dh1 = ecdh(xs, epkC);
    const epkS = x25519.getPublicKey(ess);
    dh2 = ecdh(ess, epkC);
    const k = deriveTunnel({ dh1, dh2, attNonce, epkC, epkS, xp, ep });
    return { serverHello: encodeServerHello(epkS), attNonce, th: k.th, kC2s: k.kC2s, kS2c: k.kS2c };
  } finally {
    ess.fill(0);
    dh1?.fill(0);
    dh2?.fill(0);
  }
}
