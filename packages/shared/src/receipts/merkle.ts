/** RFC 6962 §2.1 Merkle tree over pre-hashed 32-byte leaves (see `receiptLeaf`). */
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, equalBytes, isBytes, isUint } from "../bytes.js";

/** Proofs longer than this cannot belong to any tree addressable with safe integers. */
export const MAX_PROOF_LEN = 64;

const NODE_PREFIX = Uint8Array.of(1);

function node(l: Uint8Array, r: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE_PREFIX, l, r));
}

/** Largest power of two strictly less than n (n ≥ 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function checkLeaves(leaves: Uint8Array[]): void {
  if (!Array.isArray(leaves) || leaves.length === 0) throw new PlrError("E_BAD_INPUT", "empty tree");
  for (const l of leaves) if (!isBytes(l) || l.length !== 32) throw new PlrError("E_BAD_INPUT", "leaf must be 32 bytes");
}

function mth(leaves: Uint8Array[], lo: number, hi: number): Uint8Array {
  const n = hi - lo;
  if (n === 1) return leaves[lo]!;
  const k = split(n);
  return node(mth(leaves, lo, lo + k), mth(leaves, lo + k, hi));
}

/** MTH(D[n]) for n ≥ 1 leaf hashes. @throws PlrError E_BAD_INPUT on an empty tree or a bad leaf */
export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  checkLeaves(leaves);
  return mth(leaves, 0, leaves.length).slice();
}

/** RFC 6962 audit path PATH(index, D[n]), bottom-up. @throws PlrError E_BAD_INPUT */
export function merkleProof(leaves: Uint8Array[], index: number): Uint8Array[] {
  checkLeaves(leaves);
  if (!isUint(index) || index >= leaves.length) throw new PlrError("E_BAD_INPUT", "index out of range");
  const path: Uint8Array[] = [];
  const walk = (m: number, lo: number, hi: number): void => {
    const n = hi - lo;
    if (n === 1) return;
    const k = split(n);
    if (m < k) {
      walk(m, lo, lo + k);
      path.push(mth(leaves, lo + k, hi));
    } else {
      walk(m - k, lo + k, hi);
      path.push(mth(leaves, lo, lo + k));
    }
  };
  walk(index, 0, leaves.length);
  return path.map((p) => p.slice());
}

/** RFC 9162 §2.1.3.2 inclusion verification. Returns false on any malformed input; never throws. */
export function verifyMerkleProof(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[], root: Uint8Array): boolean {
  try {
    if (!isBytes(leaf) || leaf.length !== 32 || !isBytes(root) || root.length !== 32) return false;
    if (!isUint(index) || !isUint(size) || size === 0 || index >= size) return false;
    if (!Array.isArray(proof) || proof.length > MAX_PROOF_LEN) return false;
    let fn = index;
    let sn = size - 1;
    let r = leaf;
    for (const p of proof) {
      if (!isBytes(p) || p.length !== 32) return false;
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        r = node(p, r);
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      } else {
        r = node(r, p);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && equalBytes(r, root);
  } catch {
    return false;
  }
}
