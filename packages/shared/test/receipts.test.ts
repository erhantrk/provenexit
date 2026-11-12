// LOCKED — SPEC §7 (anchor), §8 (Merkle)
import { describe, it, expect } from "vitest";
import { merkleRoot, merkleProof, verifyMerkleProof, anchorMessage } from "../src/index.js";
import { sha256, enc, cat, u64be, hex, unhex, randomBytes } from "./helpers.js";

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
