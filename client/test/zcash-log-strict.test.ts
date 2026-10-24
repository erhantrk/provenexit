// Review-fix regressions for the shared Zcash pieces (packages/shared/test is locked, so they live here):
// the strict ZcashLog of SPEC-CHAINS §7 (prevout authorship, Ed25519-matched anchor signatures), the capped store
// for unapproved authors' registration slots, and the raw block / any-version transaction parser.
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import {
  PlrError, ZCASH_LOG, ZcashLog, anchorMessage, buildZcashBlock, concatBytes, encodeZcashRecord, fromHex, hash160, keyHash,
  opReturnScript, p2pkhScript, parseAnyZcashTx, parseZcashBlock, tAddress, toHex, zcashTxidToRpc, type ZcashBlock, type ZcashRecord,
} from "@plr/shared";

const push = (b: Uint8Array) => Uint8Array.from([b.length, ...b]);
function party() {
  const pub = new Uint8Array(33);
  pub[0] = 0x03;
  pub.set(randomBytes(32), 1);
  const h = hash160(pub);
  return { pub, h160: toHex(h), addr: tAddress(h, "regtest") };
}
type P = ReturnType<typeof party>;
const owner = party(), op = party(), op2 = party(), stranger = party();

/** Record tx JSON (strict-ready: prevout = P2PKH(author), SIGHASH_ALL). */
function rtx(who: P, r: ZcashRecord) {
  const sig = Uint8Array.from(randomBytes(71));
  sig[70] = 1;
  return {
    txid: toHex(randomBytes(32)),
    vin: [{ scriptSig: { hex: toHex(concatBytes(push(sig), push(who.pub))) }, prevout: { scriptPubKey: { hex: toHex(p2pkhScript(fromHex(who.h160, 20))) } } }],
    vout: [{ scriptPubKey: { hex: toHex(opReturnScript(encodeZcashRecord(r))) } }],
  };
}
let H = 0;
const block = (tx: ReturnType<typeof rtx>[]): ZcashBlock => ({ height: ++H, time: 1_800_000_000 + H * 75, tx });
const log = (strict: boolean) => {
  H = 0;
  return new ZcashLog({ network: "regtest", owner: owner.addr, strict });
};
function inst() {
  const xp = x25519.getPublicKey(x25519.utils.randomSecretKey());
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  return { x: toHex(xp), e: toHex(ep), es, kh: toHex(keyHash(xp, ep)) };
}
const regs = (who: P, k: ReturnType<typeof inst>, q = "99".repeat(32)): ReturnType<typeof rtx>[] => [
  rtx(who, { type: "reg_keys", x25519: k.x, ed25519: k.e }),
  rtx(who, { type: "reg_measure", key_hash: k.kh, compose_hash: "c1".repeat(32) }),
  rtx(who, { type: "reg_os", key_hash: k.kh, os_measurement: "05".repeat(32) }),
  rtx(who, { type: "reg_quote", key_hash: k.kh, quote_sha256: q }),
];

describe("strict ZcashLog", () => {
  it("requires every input's prevout to be P2PKH(author) with SIGHASH_ALL", () => {
    const L = log(true);
    const t = rtx(owner, { type: "allow_compose", hash: "ab".repeat(32) });
    const noPrev = { ...t, vin: [{ scriptSig: t.vin[0]!.scriptSig }] };
    const anyone = { ...t, vin: [{ ...t.vin[0]!, prevout: { scriptPubKey: { hex: "6d51" } } }] };
    L.apply(block([noPrev as never, anyone]));
    expect(L.isComposeAllowed("ab".repeat(32))).toBe(false);
    L.apply(block([t]));
    expect(L.isComposeAllowed("ab".repeat(32))).toBe(true);
    // the literal (non-strict) reader still accepts the SPEC-CHAINS §7 shape alone (locked behaviour)
    const N = log(false);
    N.apply(block([anyone]));
    expect(N.isComposeAllowed("ab".repeat(32))).toBe(true);
  });

  it("a stale signature never attaches to another batch, whatever the in-block order (retried anchor)", () => {
    for (const sigsFirst of ["s1", "s2"] as const) {
      const L = log(true);
      const k = inst();
      L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })]));
      L.apply(block(regs(op, k)));
      const sign = (root: string, count: number) => toHex(ed25519.sign(anchorMessage({ contractId: L.contractId, keyHash: fromHex(k.kh, 32), root: fromHex(root, 32), firstSeq: 0n, count: BigInt(count) }), k.es));
      const a1 = rtx(op, { type: "anchor", key_hash: k.kh, root: "a1".repeat(32), first_seq: 0, count: 5 });
      const a2 = rtx(op, { type: "anchor", key_hash: k.kh, root: "a2".repeat(32), first_seq: 0, count: 8 });
      const s1 = rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig: sign("a1".repeat(32), 5) });
      const s2 = rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig: sign("a2".repeat(32), 8) });
      L.apply(block([a2, a1])); // A2 lands before the still-pending A1
      L.apply(block(sigsFirst === "s1" ? [s1, s2] : [s2, s1]));
      expect(L.anchorCount()).toBe(1);
      const a = L.getAnchor(0)!;
      const msg = anchorMessage({ contractId: L.contractId, keyHash: fromHex(k.kh, 32), root: fromHex(a.root, 32), firstSeq: 0n, count: BigInt(a.count) });
      expect(ed25519.verify(fromHex(a.sig!, 64), msg, fromHex(k.e, 32))).toBe(true);
      expect(a.count).toBe(sigsFirst === "s1" ? 5 : 8);
      expect(L.getInstance(k.kh)!.next_seq).toBe(a.count);
    }
  });

  it("selection and anchor authorship stay SPEC-CHAINS §5; only a valid instance signature completes an anchor", () => {
    for (const strict of [false, true]) {
      const L = log(strict);
      const k = inst();
      L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "a" }), rtx(owner, { type: "approve_operator", hash160: op2.h160, org_id: "b" })]));
      L.apply(block(regs(op2, k, "77".repeat(32)))); // earliest completed: op2
      L.apply(block(regs(op, k)));
      expect(L.getInstance(k.kh)!.operator).toBe(op2.addr);
      expect(L.registrationQuoteHash(k.kh)).toBe("77".repeat(32));
      const sign = (root: string, first: number, count: number) =>
        toHex(ed25519.sign(anchorMessage({ contractId: L.contractId, keyHash: fromHex(k.kh, 32), root: fromHex(root, 32), firstSeq: BigInt(first), count: BigInt(count) }), k.es));
      // not the selected instance's operator: ignored even with a valid signature
      L.apply(block([rtx(op, { type: "anchor", key_hash: k.kh, root: "aa".repeat(32), first_seq: 0, count: 2 })]));
      L.apply(block([rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig: sign("aa".repeat(32), 0, 2) })]));
      expect(L.anchorCount()).toBe(0);
      // the selected operator with a garbage signature: ignored only by the strict log
      L.apply(block([rtx(op2, { type: "anchor", key_hash: k.kh, root: "bb".repeat(32), first_seq: 0, count: 1 })]));
      L.apply(block([rtx(op2, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig: "cd".repeat(64) })]));
      expect(L.anchorCount()).toBe(strict ? 0 : 1);
      if (!strict) continue;
      // ... and accepted once the instance key signed it
      L.apply(block([rtx(op2, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig: sign("bb".repeat(32), 0, 1) })]));
      expect(L.anchorCount()).toBe(1);
      expect(L.getInstance(k.kh)!.next_seq).toBe(1);
      // an unapproved stranger's complete registration never becomes the instance
      L.apply(block([rtx(owner, { type: "revoke_operator", hash160: op2.h160 }), rtx(owner, { type: "revoke_operator", hash160: op.h160 })]));
      L.apply(block(regs(stranger, k)));
      expect(L.getInstance(k.kh)).toBeNull();
    }
  });
});

describe("unapproved authors cannot exhaust registration tracking", () => {
  for (const strict of [false, true]) {
    it(`100 001 stranger reg_os records do not block an approved operator (strict=${strict})`, () => {
      const L = log(strict);
      L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })]));
      const spam: ReturnType<typeof rtx>[] = [];
      for (let i = 0; i < 100_001; i++) spam.push(rtx(stranger, { type: "reg_os", key_hash: toHex(sha256(Uint8Array.of(i & 255, (i >> 8) & 255, i >> 16))), os_measurement: "05".repeat(32) }));
      for (let i = 0; i < spam.length; i += 20_000) L.apply(block(spam.slice(i, i + 20_000)));
      const k = inst();
      L.apply(block(regs(op, k)));
      expect(L.getInstance(k.kh)).toMatchObject({ operator: op.addr });
      expect(ZCASH_LOG.MAX_UNAPPROVED_REGISTRATIONS).toBeLessThan(100_001);
    }, 60_000);
  }
});

// ---------------------------------------------------------------- raw parser

const le32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const le64 = (n: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, n, true); return b; };
const dsha = (b: Uint8Array) => sha256(sha256(b));
const vinVout = (script: Uint8Array) => concatBytes(
  Uint8Array.of(1), new Uint8Array(32).fill(3), le32(1), Uint8Array.of(2, 0x51, 0x51), le32(0xffffffff),
  Uint8Array.of(1), le64(5n), Uint8Array.of(script.length), script,
);

describe("raw transactions of every version and raw blocks", () => {
  const script = p2pkhScript(new Uint8Array(20).fill(1));
  const v1 = concatBytes(le32(1), vinVout(script), le32(0));
  const v2 = concatBytes(le32(2), vinVout(script), le32(0), Uint8Array.of(1), new Uint8Array(1802), new Uint8Array(96));
  const v3 = concatBytes(le32(0x80000003), le32(0x03c48270), vinVout(script), le32(0), le32(0), Uint8Array.of(0));
  const v4 = concatBytes(le32(0x80000004), le32(0x892f2085), vinVout(script), le32(0), le32(0), le64(0n),
    Uint8Array.of(1), new Uint8Array(384), Uint8Array.of(1), new Uint8Array(948), Uint8Array.of(1), new Uint8Array(1698), new Uint8Array(96), new Uint8Array(64));

  it("parses v1–v4 transparent parts and txids (SHA256d), skipping shielded data", () => {
    for (const raw of [v1, v2, v3, v4]) {
      const t = parseAnyZcashTx(raw);
      expect(t.vout.map((o) => toHex(o.script))).toEqual([toHex(script)]);
      expect(t.vin[0]!.prevIndex).toBe(1);
      expect(toHex(t.txid)).toBe(toHex(dsha(raw)));
      expect(t.coinbase).toBe(false);
    }
  });

  it("parses a block of mixed versions; the hash commits to the header; malformed bytes throw PlrError only", () => {
    const { raw, hash } = buildZcashBlock({ prev: "11".repeat(32), time: 1234, txs: [v1, v4, v2] });
    const b = parseZcashBlock(raw);
    expect(b).toMatchObject({ hash, prev: "11".repeat(32), time: 1234 });
    expect(b.tx.map((t) => zcashTxidToRpc(t.txid))).toEqual([v1, v4, v2].map((r) => zcashTxidToRpc(dsha(r))));
    expect(() => parseZcashBlock(raw.subarray(0, raw.length - 1))).toThrow(PlrError);
    expect(() => parseZcashBlock(concatBytes(raw, Uint8Array.of(0)))).toThrow(PlrError);
    for (let i = 0; i < 300; i++) {
      const junk = Uint8Array.from(randomBytes(i * 7));
      try { parseZcashBlock(junk); } catch (e) { expect(e).toBeInstanceOf(PlrError); }
      try { parseAnyZcashTx(junk); } catch (e) { expect(e).toBeInstanceOf(PlrError); }
    }
    for (let cut = 0; cut < v4.length; cut += 97) expect(() => parseAnyZcashTx(v4.subarray(0, cut))).toThrow(PlrError);
  });
});
