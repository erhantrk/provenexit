// LOCKED — SPEC-CHAINS §7 (Zcash v5 transparent transactions; ZIP-225 / ZIP-244 / ZIP-317)
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import {
  zcashTxid, zcashSighash, SIGHASH, buildSignedTransparentTx, hash160, p2pkhScript, opReturnScript, tAddress, parseTAddress,
  zip317Fee, PlrError,
} from "../src/index.js";
import { cat, hex, unhex, randomBytes } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const VEC = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "vectors", "zip_0244.json"), "utf8")).slice(2) as unknown[][];
type V = { tx: string; txid: string; amounts: number[]; spks: string[]; input: number | null; shielded: string; all: string | null; none: string | null; single: string | null; allAny: string | null };
const vectors: V[] = VEC.map((r) => ({
  tx: r[0] as string, txid: r[1] as string, amounts: r[3] as number[], spks: r[4] as string[], input: r[5] as number | null,
  shielded: r[6] as string, all: r[7] as string | null, none: r[8] as string | null, single: r[9] as string | null, allAny: r[10] as string | null,
}));

describe("ZIP-244 test vectors (all 10, incl. Sapling/Orchard bundles)", () => {
  it("has the vectors", () => expect(vectors.length).toBe(10));
  vectors.forEach((v, i) => {
    it(`vector ${i}: txid and sighashes`, () => {
      const tx = unhex(v.tx);
      expect(hex(zcashTxid(tx))).toBe(v.txid);
      const p = { amounts: v.amounts.map((a) => BigInt(a)), scriptPubKeys: v.spks.map(unhex) };
      expect(hex(zcashSighash(tx, { ...p, inputIndex: null, hashType: SIGHASH.ALL }))).toBe(v.shielded);
      if (v.input !== null) {
        expect(hex(zcashSighash(tx, { ...p, inputIndex: v.input, hashType: SIGHASH.ALL }))).toBe(v.all);
        if (v.none) expect(hex(zcashSighash(tx, { ...p, inputIndex: v.input, hashType: SIGHASH.NONE }))).toBe(v.none);
        if (v.single) expect(hex(zcashSighash(tx, { ...p, inputIndex: v.input, hashType: SIGHASH.SINGLE }))).toBe(v.single);
        if (v.allAny) expect(hex(zcashSighash(tx, { ...p, inputIndex: v.input, hashType: SIGHASH.ALL | SIGHASH.ANYONECANPAY }))).toBe(v.allAny);
      }
    });
  });
});

describe("addresses and scripts", () => {
  it("hash160 = RIPEMD160(SHA256(x))", () => {
    const b = randomBytes(33);
    expect(hash160(b)).toEqual(ripemd160(sha256(b)));
  });
  it("P2PKH and OP_RETURN scripts", () => {
    const h = randomBytes(20);
    expect(p2pkhScript(h)).toEqual(cat(new Uint8Array([0x76, 0xa9, 0x14]), h, new Uint8Array([0x88, 0xac])));
    expect(opReturnScript(new Uint8Array([1, 2, 3]))).toEqual(new Uint8Array([0x6a, 3, 1, 2, 3]));
    const d80 = randomBytes(80);
    expect(opReturnScript(d80)).toEqual(cat(new Uint8Array([0x6a, 0x4c, 80]), d80));
    expect(opReturnScript(randomBytes(76)).slice(0, 3)).toEqual(new Uint8Array([0x6a, 0x4c, 76]));
    expect(opReturnScript(randomBytes(75)).slice(0, 2)).toEqual(new Uint8Array([0x6a, 75]));
    expect(code(() => opReturnScript(randomBytes(81)))).toBe("E_BAD_INPUT");
  });
  it("t-addresses round-trip with the right prefixes", () => {
    const h = randomBytes(20);
    const t = tAddress(h, "regtest");
    expect(t.startsWith("tm")).toBe(true);
    expect(tAddress(h, "testnet")).toBe(t);
    expect(tAddress(h, "mainnet").startsWith("t1")).toBe(true);
    expect(parseTAddress(t)).toEqual({ network: "test", hash160: h });
    expect(parseTAddress(tAddress(h, "mainnet"))).toEqual({ network: "mainnet", hash160: h });
    expect(tAddress(unhex("0000000000000000000000000000000000000000"), "mainnet")).toBe("t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs");
    const bad = t.slice(0, -1) + (t.endsWith("a") ? "b" : "a");
    expect(code(() => parseTAddress(bad))).toBe("E_BAD_INPUT");
    expect(code(() => parseTAddress("t2ABC"))).toBe("E_BAD_INPUT");
  });
});

describe("ZIP-317 fee", () => {
  it("minimum two logical actions; OP_RETURN of 80 bytes costs three output actions", () => {
    expect(zip317Fee({ inputs: 1, outputScripts: [p2pkhScript(randomBytes(20))] })).toBe(10_000n);
    expect(zip317Fee({ inputs: 1, outputScripts: [opReturnScript(randomBytes(80)), p2pkhScript(randomBytes(20))] })).toBe(20_000n);
    expect(zip317Fee({ inputs: 5, outputScripts: [p2pkhScript(randomBytes(20))] })).toBe(25_000n);
  });
});

describe("buildSignedTransparentTx", () => {
  const sk = secp256k1.utils.randomSecretKey();
  const pub = secp256k1.getPublicKey(sk, true);
  const spk = p2pkhScript(hash160(pub));
  const prev = randomBytes(32);
  const build = () => buildSignedTransparentTx({
    branchId: 0x4dec4df0, expiryHeight: 1000,
    inputs: [{ txid: prev, vout: 0, amount: 625_000_000n, secretKey: sk }],
    outputs: [{ amount: 0n, script: opReturnScript(new Uint8Array([0x50, 0x4c, 0x52, 0x31, 1])) }, { amount: 624_980_000n, script: spk }],
  });

  it("produces a v5 tx whose input signature verifies against its own ZIP-244 sighash", () => {
    const tx = build();
    expect(hex(tx.slice(0, 4))).toBe("05000080");             // v5 + overwintered
    expect(hex(tx.slice(4, 8))).toBe("0a27a726");             // version group id
    expect(hex(tx.slice(8, 12))).toBe("f04dec4d");            // branch id, little endian
    // locate scriptSig: header 20 bytes, then compactSize(1 input), prevout (32+4), compactSize(script len)
    const sigLen = tx[20 + 1 + 36]!;
    const script = tx.slice(20 + 1 + 36 + 1, 20 + 1 + 36 + 1 + sigLen);
    const derLen = script[0]!;
    const der = script.slice(1, 1 + derLen);
    expect(der[der.length - 1]).toBe(SIGHASH.ALL);
    expect(script[1 + derLen]).toBe(33);
    expect(script.slice(2 + derLen, 2 + derLen + 33)).toEqual(pub);
    const digest = zcashSighash(tx, { inputIndex: 0, hashType: SIGHASH.ALL, amounts: [625_000_000n], scriptPubKeys: [spk] });
    const sig = secp256k1.Signature.fromBytes(der.slice(0, -1), "der");
    expect(secp256k1.verify(sig.toBytes("compact"), digest, pub, { prehash: false, lowS: true })).toBe(true);
    expect(zcashTxid(tx).length).toBe(32);
  });

  it("rejects outputs exceeding inputs and bad keys", () => {
    expect(() => buildSignedTransparentTx({ branchId: 1, expiryHeight: 1, inputs: [{ txid: prev, vout: 0, amount: 10n, secretKey: sk }], outputs: [{ amount: 11n, script: spk }] })).toThrow(PlrError);
    expect(() => buildSignedTransparentTx({ branchId: 1, expiryHeight: 1, inputs: [{ txid: prev, vout: 0, amount: 10n, secretKey: new Uint8Array(32) }], outputs: [{ amount: 1n, script: spk }] })).toThrow(PlrError);
  });
});
