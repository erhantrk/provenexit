/**
 * Per-instance receipt log (SPEC §8). Only receipt leaf hashes are retained, in memory; sequence numbers are
 * contiguous from 0. Anchored batches are recorded so inclusion proofs can be served (SPEC §6.4).
 */
import { merkleProof, merkleRoot, receiptLeaf, toHex, type Receipt } from "@plr/shared";

export interface AnchoredBatch {
  anchorId: number;
  firstSeq: number;
  count: number;
  root: Uint8Array;
}

export interface ProofResponse {
  anchor_id: number;
  first_seq: number;
  count: number;
  index: number;
  root: string;
  proof: string[];
}

/** Maximum receipts per anchor batch (contract bound, SPEC §7). */
export const MAX_BATCH = 10_000;

export class ReceiptLog {
  readonly #leaves: Uint8Array[] = [];
  readonly #batches: AnchoredBatch[] = [];
  #anchored = 0;

  /** Number of receipts issued so far (= next seq). */
  get size(): number {
    return this.#leaves.length;
  }

  /** Receipts `[0, anchoredCount)` are covered by confirmed on-chain anchors. */
  get anchoredCount(): number {
    return this.#anchored;
  }

  /** Allocates the next seq, signs the receipt and retains only its leaf hash. */
  issue(p: { th: Uint8Array; reqHash: Uint8Array; respHash: Uint8Array; composeHash: Uint8Array; keyHash: Uint8Array; sign: (r: Receipt) => string; nowMs: number }): { receipt: Receipt; sig: string } {
    const receipt: Receipt = {
      v: 1,
      th: toHex(p.th),
      req_hash: toHex(p.reqHash),
      resp_hash: toHex(p.respHash),
      compose_hash: toHex(p.composeHash),
      key_hash: toHex(p.keyHash),
      seq: this.#leaves.length,
      ts_ms: Math.floor(p.nowMs),
    };
    const sig = p.sign(receipt);
    this.#leaves.push(receiptLeaf(receipt));
    return { receipt, sig };
  }

  /** The next batch to anchor (at most MAX_BATCH receipts after the anchored prefix), or null if none pending. */
  pendingBatch(): { firstSeq: number; count: number; root: Uint8Array } | null {
    const count = Math.min(this.#leaves.length - this.#anchored, MAX_BATCH);
    if (count <= 0) return null;
    const firstSeq = this.#anchored;
    return { firstSeq, count, root: this.rootOf(firstSeq, count) };
  }

  /** RFC 6962 root over receipts `[firstSeq, firstSeq+count)`. */
  rootOf(firstSeq: number, count: number): Uint8Array {
    if (firstSeq < 0 || count < 1 || firstSeq + count > this.#leaves.length) throw new RangeError("range");
    return merkleRoot(this.#leaves.slice(firstSeq, firstSeq + count));
  }

  /** Records a confirmed anchor. Batches must be contiguous with the anchored prefix. */
  markAnchored(b: AnchoredBatch): void {
    if (b.firstSeq !== this.#anchored || b.count < 1 || b.firstSeq + b.count > this.#leaves.length) {
      throw new RangeError("non-contiguous anchor");
    }
    this.#batches.push({ ...b, root: b.root.slice() });
    this.#anchored += b.count;
  }

  /** Inclusion proof for `seq`, or null if it is not (yet) anchored. */
  proof(seq: number): ProofResponse | null {
    if (!Number.isSafeInteger(seq) || seq < 0 || seq >= this.#anchored) return null;
    let lo = 0;
    let hi = this.#batches.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const b = this.#batches[mid]!;
      if (seq < b.firstSeq) hi = mid - 1;
      else if (seq >= b.firstSeq + b.count) lo = mid + 1;
      else {
        const leaves = this.#leaves.slice(b.firstSeq, b.firstSeq + b.count);
        const index = seq - b.firstSeq;
        return {
          anchor_id: b.anchorId,
          first_seq: b.firstSeq,
          count: b.count,
          index,
          root: toHex(b.root),
          proof: merkleProof(leaves, index).map(toHex),
        };
      }
    }
    return null;
  }
}
