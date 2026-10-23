// LOCKED — SPEC §7 (anchor), §8
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  receiptMessage, signReceipt, verifyReceipt, receiptLeaf, merkleRoot, merkleProof, verifyMerkleProof,
  anchorMessage, type Receipt,
} from "../src/index.js";
import { sha256, enc, cat, u64be, hex, unhex, randomBytes } from "./helpers.js";

const R = (seq = 3): Receipt => ({
  v: 1, th: "a1".repeat(32), req_hash: "b2".repeat(32), resp_hash: "c3".repeat(32),
  compose_hash: "d4".repeat(32), key_hash: "e5".repeat(32), seq, ts_ms: 1_700_000_000_123,
});

describe("receipts", () => {
  it("receiptMessage has the §8 binary layout", () => {
    const r = R();
    expect(receiptMessage(r)).toEqual(cat(
      enc("PLR-v1/receipt"), unhex(r.th), unhex(r.req_hash), unhex(r.resp_hash), unhex(r.compose_hash),
      unhex(r.key_hash), u64be(3), u64be(1_700_000_000_123),
    ));
    expect(receiptLeaf(r)).toEqual(sha256(cat(new Uint8Array([0]), receiptMessage(r))));
  });

  it("sign/verify with Ed25519, detects any field change", () => {
    const sk = ed25519.utils.randomSecretKey(), pk = ed25519.getPublicKey(sk);
    const r = R();
    const sig = signReceipt(r, sk);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(ed25519.verify(unhex(sig), receiptMessage(r), pk)).toBe(true);
    expect(verifyReceipt(r, sig, pk)).toBe(true);
    for (const k of ["th", "req_hash", "resp_hash", "compose_hash", "key_hash"] as const)
      expect(verifyReceipt({ ...r, [k]: "00".repeat(32) }, sig, pk)).toBe(false);
    expect(verifyReceipt({ ...r, seq: 4 }, sig, pk)).toBe(false);
    expect(verifyReceipt({ ...r, ts_ms: r.ts_ms + 1 }, sig, pk)).toBe(false);
    expect(verifyReceipt(r, sig, ed25519.getPublicKey(ed25519.utils.randomSecretKey()))).toBe(false);
    expect(verifyReceipt(r, "zz", pk)).toBe(false);
  });
});

// Independent RFC 6962 reference.
const node = (l: Uint8Array, r: Uint8Array) => sha256(cat(new Uint8Array([1]), l, r));
const k = (n: number) => { let p = 1; while (p * 2 < n) p *= 2; return p; };
const refRoot = (ls: Uint8Array[]): Uint8Array => ls.length === 1 ? ls[0]! : node(refRoot(ls.slice(0, k(ls.length))), refRoot(ls.slice(k(ls.length))));

describe("merkle (RFC 6962)", () => {
  it("roots match the reference for n = 1..33", () => {
    for (let n = 1; n <= 33; n++) {
      const ls = Array.from({ length: n }, () => randomBytes(32));
      expect(hex(merkleRoot(ls))).toBe(hex(refRoot(ls)));
    }
  });

  it("matches a fixed vector", () => {
    const ls = [0, 1, 2].map((i) => sha256(new Uint8Array([i])));
    expect(hex(merkleRoot(ls))).toBe(hex(node(node(ls[0]!, ls[1]!), ls[2]!)));
  });

  it("every proof verifies; wrong leaf/index/size/root/proof fail", () => {
    for (const n of [1, 2, 3, 5, 8, 13]) {
      const ls = Array.from({ length: n }, () => randomBytes(32));
      const root = merkleRoot(ls);
      for (let i = 0; i < n; i++) {
        const p = merkleProof(ls, i);
        expect(verifyMerkleProof(ls[i]!, i, n, p, root)).toBe(true);
        expect(verifyMerkleProof(randomBytes(32), i, n, p, root)).toBe(false);
        if (n > 1) expect(verifyMerkleProof(ls[i]!, (i + 1) % n, n, p, root)).toBe(false);
        expect(verifyMerkleProof(ls[i]!, i, n, p, randomBytes(32))).toBe(false);
        if (p.length) expect(verifyMerkleProof(ls[i]!, i, n, [...p.slice(1), randomBytes(32)], root)).toBe(false);
        expect(verifyMerkleProof(ls[i]!, i, n, [...p, randomBytes(32)], root)).toBe(false);
      }
      expect(verifyMerkleProof(ls[0]!, n, n, merkleProof(ls, 0), root)).toBe(false);
    }
  });

  it("rejects empty trees and out-of-range indices", () => {
    expect(() => merkleRoot([])).toThrow();
    expect(() => merkleProof([randomBytes(32)], 1)).toThrow();
  });
});

describe("anchorMessage", () => {
  it("has the §7 layout", () => {
    const kh = randomBytes(32), root = randomBytes(32);
    expect(anchorMessage({ contractId: "registry.test.near", keyHash: kh, root, firstSeq: 5n, count: 2n })).toEqual(
      cat(enc("PLR-v1/anchor"), enc("registry.test.near"), kh, root, u64be(5), u64be(2)),
    );
  });
});
