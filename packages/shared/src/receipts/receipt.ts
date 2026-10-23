/** Signed per-request receipts (SPEC §8) and the anchor message (SPEC §7). */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, fromHex, isBytes, isHex, isPlainObject, isUint, toHex, u64be, utf8 } from "../bytes.js";
import { contractIdBytes } from "../tdx/measure.js";

export interface Receipt {
  v: 1;
  th: string;
  req_hash: string;
  resp_hash: string;
  compose_hash: string;
  key_hash: string;
  seq: number;
  ts_ms: number;
}

const RECEIPT_LABEL = utf8("PLR-v1/receipt");
const ANCHOR_LABEL = utf8("PLR-v1/anchor");
const HASH_FIELDS = ["th", "req_hash", "resp_hash", "compose_hash", "key_hash"] as const;
const RECEIPT_KEYS: ReadonlySet<string> = new Set(["v", ...HASH_FIELDS, "seq", "ts_ms"]);

/** Strict shape check: exactly the §8 fields, 32-byte lowercase hex hashes, non-negative safe integers. */
export function isReceipt(r: unknown): r is Receipt {
  if (!isPlainObject(r)) return false;
  for (const k of Object.keys(r)) if (!RECEIPT_KEYS.has(k)) return false;
  if (r.v !== 1 || !isUint(r.seq) || !isUint(r.ts_ms)) return false;
  return HASH_FIELDS.every((f) => isHex(r[f], 32));
}

/** `"PLR-v1/receipt" ‖ th ‖ req_hash ‖ resp_hash ‖ compose_hash ‖ key_hash ‖ u64be(seq) ‖ u64be(ts_ms)` */
export function receiptMessage(r: Receipt): Uint8Array {
  if (!isReceipt(r)) throw new PlrError("E_BAD_INPUT", "malformed receipt");
  return concatBytes(
    RECEIPT_LABEL,
    ...HASH_FIELDS.map((f) => fromHex(r[f], 32)),
    u64be(r.seq),
    u64be(r.ts_ms),
  );
}

/** Ed25519 signature over {@link receiptMessage}, as 128 lowercase hex chars. */
export function signReceipt(r: Receipt, edSecret: Uint8Array): string {
  if (!isBytes(edSecret) || edSecret.length !== 32) throw new PlrError("E_BAD_INPUT", "ed25519 secret must be 32 bytes");
  return toHex(ed25519.sign(receiptMessage(r), edSecret));
}

/** Strict (RFC 8032, non-ZIP-215) verification. Returns false on any malformed input; never throws. */
export function verifyReceipt(r: Receipt, sigHex: string, edPub: Uint8Array): boolean {
  try {
    if (!isHex(sigHex, 64) || !isBytes(edPub) || edPub.length !== 32) return false;
    return ed25519.verify(fromHex(sigHex, 64), receiptMessage(r), edPub, { zip215: false });
  } catch {
    return false;
  }
}

/** RFC 6962 leaf hash: `SHA256(0x00 ‖ receipt_msg)`. */
export function receiptLeaf(r: Receipt): Uint8Array {
  return sha256(concatBytes(Uint8Array.of(0), receiptMessage(r)));
}

/** `"PLR-v1/anchor" ‖ contractId ‖ keyHash ‖ root ‖ u64be(firstSeq) ‖ u64be(count)` */
export function anchorMessage(p: { contractId: string; keyHash: Uint8Array; root: Uint8Array; firstSeq: bigint; count: bigint }): Uint8Array {
  if (!isBytes(p?.keyHash) || p.keyHash.length !== 32) throw new PlrError("E_BAD_INPUT", "keyHash must be 32 bytes");
  if (!isBytes(p.root) || p.root.length !== 32) throw new PlrError("E_BAD_INPUT", "root must be 32 bytes");
  if (typeof p.firstSeq !== "bigint" || typeof p.count !== "bigint") throw new PlrError("E_BAD_INPUT", "firstSeq/count must be bigint");
  return concatBytes(ANCHOR_LABEL, contractIdBytes(p.contractId), p.keyHash, p.root, u64be(p.firstSeq), u64be(p.count));
}
