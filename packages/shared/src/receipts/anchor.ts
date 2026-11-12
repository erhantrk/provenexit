/** The anchor message (SPEC §7) that the instance signs for `anchor_receipts`. */
import { PlrError } from "../errors.js";
import { concatBytes, isBytes, u64be, utf8 } from "../bytes.js";
import { contractIdBytes } from "../tdx/measure.js";

const ANCHOR_LABEL = utf8("PLR-v1/anchor");

/** `"PLR-v1/anchor" ‖ contractId ‖ keyHash ‖ root ‖ u64be(firstSeq) ‖ u64be(count)` */
export function anchorMessage(p: { contractId: string; keyHash: Uint8Array; root: Uint8Array; firstSeq: bigint; count: bigint }): Uint8Array {
  if (!isBytes(p?.keyHash) || p.keyHash.length !== 32) throw new PlrError("E_BAD_INPUT", "keyHash must be 32 bytes");
  if (!isBytes(p.root) || p.root.length !== 32) throw new PlrError("E_BAD_INPUT", "root must be 32 bytes");
  if (typeof p.firstSeq !== "bigint" || typeof p.count !== "bigint") throw new PlrError("E_BAD_INPUT", "firstSeq/count must be bigint");
  return concatBytes(ANCHOR_LABEL, contractIdBytes(p.contractId), p.keyHash, p.root, u64be(p.firstSeq), u64be(p.count));
}
