/**
 * Receipt inclusion check against the on-chain anchor (SPEC §6.4, §8).
 *
 * The exit's `/v1/receipts/proof` reply is untrusted. Everything that positions the receipt inside the
 * Merkle tree — the batch's `first_seq` and `count`, hence the leaf `index` and tree `size`, and the `root` —
 * is taken FROM THE CHAIN (`get_anchor(anchor_id)`), never from the exit: `index = receipt.seq -
 * anchor.first_seq`, `size = anchor.count`. Exit-supplied values must agree with the chain, else the proof
 * is rejected (E_ANCHOR_MISMATCH). The anchor must belong to the receipt's instance (`key_hash`).
 */
import {
  MAX_PROOF_LEN,
  PlrError,
  fromHex,
  isHex,
  isVpnReceipt,
  verifyMerkleProof,
  vpnReceiptLeaf,
  type AnchorRecord,
  type RegistryReader,
  type VpnReceipt,
} from "@plr/shared";
import { isPlainObject } from "./util.js";
import { isRegistryRefusal } from "./near-registry.js";

const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** `GET /v1/receipts/proof` reply shape (SPEC §6.4). */
export interface ProofReply {
  anchor_id: number;
  first_seq: number;
  count: number;
  index: number;
  root: string;
  proof: string[];
}

/** A receipt proven to be included in an on-chain anchor. All positional values come from the chain. */
export interface AnchoredReceipt {
  anchorId: number;
  /** Merkle root as stored on-chain. */
  root: string;
  firstSeq: number;
  /** Tree size = on-chain anchor count. */
  count: number;
  /** Leaf index = receipt.seq − on-chain first_seq. */
  index: number;
  atMs: number;
}

const PROOF_KEYS = ["anchor_id", "count", "first_seq", "index", "proof", "root"] as const;

/** Strict shape check of the exit's proof reply (exact keys, safe integers, 32-byte hex hashes). */
export function parseProofReply(j: unknown): ProofReply {
  const bad = (): never => {
    throw new PlrError("E_BAD_RESPONSE", "malformed proof reply");
  };
  if (!isPlainObject(j)) return bad();
  const keys = Object.keys(j).sort();
  if (keys.length !== PROOF_KEYS.length || !keys.every((k, i) => k === PROOF_KEYS[i])) bad();
  const { anchor_id, first_seq, count, index, root, proof } = j;
  if (!isUint(anchor_id) || !isUint(first_seq) || !isUint(count) || !isUint(index)) bad();
  if (!isHex(root, 32) || !Array.isArray(proof) || proof.length > MAX_PROOF_LEN) bad();
  if (!(proof as unknown[]).every((h) => isHex(h, 32))) bad();
  return {
    anchor_id: anchor_id as number,
    first_seq: first_seq as number,
    count: count as number,
    index: index as number,
    root: root as string,
    proof: (proof as string[]).slice(),
  };
}

async function chainAnchor(registry: RegistryReader, id: number): Promise<AnchorRecord | null> {
  try {
    return await registry.getAnchor(id);
  } catch (e) {
    if (isRegistryRefusal(e)) throw e;
    throw new PlrError("E_REGISTRY_UNAVAILABLE", "get_anchor");
  }
}

/**
 * Verifies `reply` (exit-supplied) for a PLR-VPN-v1 session receipt (SPEC-VPN §5, leaf = `vpnReceiptLeaf`) against
 * `get_anchor(reply.anchor_id)` on the VPN registry.
 * @throws PlrError E_BAD_INPUT (receipt), E_BAD_RESPONSE (reply shape), E_NOT_ANCHORED (no such anchor),
 *         E_REGISTRY_UNAVAILABLE, E_ANCHOR_MISMATCH (any disagreement or a failing proof)
 */
export async function verifyVpnReceiptAnchored(p: { receipt: VpnReceipt; reply: unknown; registry: RegistryReader }): Promise<AnchoredReceipt> {
  if (!isVpnReceipt(p.receipt)) throw new PlrError("E_BAD_INPUT", "malformed receipt");
  return verifyLeafAnchored({ seq: p.receipt.seq, keyHash: p.receipt.key_hash, leaf: vpnReceiptLeaf(p.receipt), reply: p.reply, registry: p.registry });
}

/** Core check for any receipt kind: the leaf at chain-derived position `seq − first_seq` of the chain's root. */
async function verifyLeafAnchored(p: {
  seq: number;
  keyHash: string;
  leaf: Uint8Array;
  reply: unknown;
  registry: RegistryReader;
}): Promise<AnchoredReceipt> {
  const reply = parseProofReply(p.reply);
  const anchor = await chainAnchor(p.registry, reply.anchor_id);
  if (anchor === null) throw new PlrError("E_NOT_ANCHORED", "anchor not on chain");
  const mismatch = (why: string): never => {
    throw new PlrError("E_ANCHOR_MISMATCH", why);
  };
  if (anchor.id !== reply.anchor_id) mismatch("anchor id");
  if (anchor.key_hash !== p.keyHash) mismatch("anchor belongs to another instance");
  if (!isUint(anchor.first_seq) || !isUint(anchor.count) || anchor.count < 1) mismatch("on-chain anchor shape");
  const seq = p.seq;
  // Chain-derived position. `seq - first_seq` is only meaningful if seq lies inside the anchored range.
  if (seq < anchor.first_seq || seq - anchor.first_seq >= anchor.count) mismatch("receipt seq outside the anchored batch");
  const index = seq - anchor.first_seq;
  const size = anchor.count;
  if (reply.first_seq !== anchor.first_seq || reply.count !== size || reply.index !== index) mismatch("exit batch position");
  if (reply.root !== anchor.root) mismatch("exit root");
  const ok = verifyMerkleProof(
    p.leaf,
    index,
    size,
    reply.proof.map((h) => fromHex(h, 32)),
    fromHex(anchor.root, 32),
  );
  if (!ok) mismatch("inclusion proof");
  return { anchorId: anchor.id, root: anchor.root, firstSeq: anchor.first_seq, count: size, index, atMs: anchor.at_ms };
}
