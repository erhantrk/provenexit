/**
 * PLR-VPN-v1 session receipts (SPEC-VPN §5). Deliberately metadata-free: no destination, address, port,
 * byte count or client IP — only the tunnel hash, the build/key identity, a sequence number and two timestamps.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, fromHex, isBytes, isHex, isPlainObject, isUint, toHex, u64be, utf8 } from "../bytes.js";

export interface VpnReceipt {
  v: 1;
  th: string;
  compose_hash: string;
  key_hash: string;
  seq: number;
  ts_open_ms: number;
  ts_close_ms: number;
}

const VPN_RECEIPT_LABEL = utf8("PLR-VPN-v1/receipt");
const HASH_FIELDS = ["th", "compose_hash", "key_hash"] as const;
const VPN_RECEIPT_KEYS: ReadonlySet<string> = new Set(["v", ...HASH_FIELDS, "seq", "ts_open_ms", "ts_close_ms"]);

/**
 * Strict shape check: exactly the §5 fields, 32-byte lowercase hex hashes, non-negative safe integers and
 * `ts_open_ms ≤ ts_close_ms`.
 */
export function isVpnReceipt(r: unknown): r is VpnReceipt {
  if (!isPlainObject(r)) return false;
  const keys = Object.keys(r);
  if (keys.length !== VPN_RECEIPT_KEYS.size) return false;
  for (const k of keys) if (!VPN_RECEIPT_KEYS.has(k)) return false;
  if (r.v !== 1 || !isUint(r.seq) || !isUint(r.ts_open_ms) || !isUint(r.ts_close_ms)) return false;
  if (r.ts_open_ms > r.ts_close_ms) return false;
  return HASH_FIELDS.every((f) => isHex(r[f], 32));
}

/** `"PLR-VPN-v1/receipt" ‖ th ‖ compose_hash ‖ key_hash ‖ u64be(seq) ‖ u64be(ts_open_ms) ‖ u64be(ts_close_ms)` */
export function vpnReceiptMessage(r: VpnReceipt): Uint8Array {
  if (!isVpnReceipt(r)) throw new PlrError("E_BAD_INPUT", "malformed vpn receipt");
  return concatBytes(
    VPN_RECEIPT_LABEL,
    ...HASH_FIELDS.map((f) => fromHex(r[f], 32)),
    u64be(r.seq),
    u64be(r.ts_open_ms),
    u64be(r.ts_close_ms),
  );
}

/** Ed25519 signature over {@link vpnReceiptMessage}, as 128 lowercase hex chars. */
export function signVpnReceipt(r: VpnReceipt, edSecret: Uint8Array): string {
  if (!isBytes(edSecret) || edSecret.length !== 32) throw new PlrError("E_BAD_INPUT", "ed25519 secret must be 32 bytes");
  return toHex(ed25519.sign(vpnReceiptMessage(r), edSecret));
}

/** Strict (RFC 8032, non-ZIP-215) verification. Returns false on any malformed input; never throws. */
export function verifyVpnReceipt(r: VpnReceipt, sigHex: string, edPub: Uint8Array): boolean {
  try {
    if (!isHex(sigHex, 64) || !isBytes(edPub) || edPub.length !== 32) return false;
    return ed25519.verify(fromHex(sigHex, 64), vpnReceiptMessage(r), edPub, { zip215: false });
  } catch {
    return false;
  }
}

/** RFC 6962 leaf hash: `SHA256(0x00 ‖ vpn_receipt_msg)`. */
export function vpnReceiptLeaf(r: VpnReceipt): Uint8Array {
  return sha256(concatBytes(Uint8Array.of(0), vpnReceiptMessage(r)));
}
