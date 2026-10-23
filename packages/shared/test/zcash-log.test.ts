// LOCKED — SPEC-CHAINS §5, §7 (Zcash tier-C record log), driven with synthetic Zebra `getblock <hash> 2` blocks.
import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  encodeZcashRecord, decodeZcashRecord, ZcashLog, hash160, tAddress, opReturnScript, keyHash, PlrError,
  type ZcashRecord, type ZcashBlock,
} from "../src/index.js";
import { cat, enc, hex, randomBytes } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const push = (b: Uint8Array) => cat(new Uint8Array([b.length]), b);

function party() {
  const sk = secp256k1.utils.randomSecretKey();
  const pub = secp256k1.getPublicKey(sk, true);
  const h = hash160(pub);
  return { pub, h160: hex(h), addr: tAddress(h, "regtest") };
}
const owner = party(), op = party(), op2 = party(), stranger = party(), newOwner = party();

let txn = 0;
/** A record transaction signed (scriptSig = <sig> <pubkey>) by `who`, with `nIn` inputs. */
function rtx(who: ReturnType<typeof party>, r: ZcashRecord | Uint8Array, o: { nIn?: number; extraOpReturn?: boolean; otherPub?: boolean; coinbase?: boolean } = {}) {
  const payload = r instanceof Uint8Array ? r : encodeZcashRecord(r);
  const ss = () => hex(cat(push(randomBytes(71)), push(o.otherPub ? party().pub : who.pub)));
  const vin = o.coinbase ? [{ coinbase: "51" }] : Array.from({ length: o.nIn ?? 1 }, (_, i) => ({ scriptSig: { hex: i === 0 ? hex(cat(push(randomBytes(71)), push(who.pub))) : ss() } }));
  const vout = [{ scriptPubKey: { hex: hex(opReturnScript(payload)) } }, { scriptPubKey: { hex: "76a914" + who.h160 + "88ac" } }];
  if (o.extraOpReturn) vout.push({ scriptPubKey: { hex: hex(opReturnScript(payload)) } });
  return { txid: (++txn).toString(16).padStart(64, "0"), vin, vout };
}
let H = 0;
const T0 = 1_800_000_000;
const block = (txs: ReturnType<typeof rtx>[], timeOffset = 0): ZcashBlock => ({ height: ++H, time: T0 + H * 75 + timeOffset, tx: txs });
const fresh = () => { H = 0; return new ZcashLog({ network: "regtest", owner: owner.addr }); };

const keys = () => { const x = randomBytes(32), e = randomBytes(32); return { x: hex(x), e: hex(e), kh: hex(keyHash(x, e)) }; };
const regAll = (who: ReturnType<typeof party>, k: ReturnType<typeof keys>, compose = "c1".repeat(32), os = "05".repeat(32), q = "99".repeat(32)) => [
  rtx(who, { type: "reg_keys", x25519: k.x, ed25519: k.e }),
  rtx(who, { type: "reg_measure", key_hash: k.kh, compose_hash: compose }),
  rtx(who, { type: "reg_os", key_hash: k.kh, os_measurement: os }),
  rtx(who, { type: "reg_quote", key_hash: k.kh, quote_sha256: q }),
];

describe("record codec", () => {
  const samples: ZcashRecord[] = [
    { type: "allow_compose", hash: "ab".repeat(32) }, { type: "revoke_compose", hash: "ab".repeat(32) },
    { type: "allow_os", hash: "cd".repeat(32) }, { type: "revoke_os", hash: "cd".repeat(32) },
    { type: "set_root", kind: "MOCK", p256: "11".repeat(64) }, { type: "set_root", kind: "INTEL", p256: "22".repeat(64) },
    { type: "approve_operator", hash160: "33".repeat(20), org_id: "acme-hosting.eu" }, { type: "revoke_operator", hash160: "33".repeat(20) },
    { type: "transfer_owner", hash160: "44".repeat(20) },
    { type: "reg_keys", x25519: "55".repeat(32), ed25519: "66".repeat(32) },
    { type: "reg_measure", key_hash: "77".repeat(32), compose_hash: "88".repeat(32) },
    { type: "reg_os", key_hash: "77".repeat(32), os_measurement: "99".repeat(32) },
    { type: "reg_quote", key_hash: "77".repeat(32), quote_sha256: "aa".repeat(32) },
    { type: "anchor", key_hash: "77".repeat(32), root: "bb".repeat(32), first_seq: 4_000_000_000, count: 10_000 },
    { type: "anchor_sig", key_prefix: "77".repeat(8), sig: "cc".repeat(64) },
  ];
  for (const r of samples) it(`${r.type} round-trips and fits OP_RETURN`, () => {
    const b = encodeZcashRecord(r);
    expect(b.length).toBeLessThanOrEqual(80);
    expect(Buffer.from(b.slice(0, 4)).toString()).toBe("PLR1");
    expect(decodeZcashRecord(b)).toEqual(r);
  });
  it("exact bytes for allow_compose and anchor", () => {
    expect(encodeZcashRecord({ type: "allow_compose", hash: "ab".repeat(32) })).toEqual(cat(enc("PLR1"), new Uint8Array([0x01]), new Uint8Array(32).fill(0xab)));
    const a = encodeZcashRecord({ type: "anchor", key_hash: "77".repeat(32), root: "bb".repeat(32), first_seq: 258, count: 3 });
    expect(a.length).toBe(4 + 1 + 32 + 32 + 4 + 2);
    expect(Array.from(a.slice(-6))).toEqual([0, 0, 1, 2, 0, 3]);
  });
  it("decode never throws and rejects malformed payloads", () => {
    expect(decodeZcashRecord(new Uint8Array())).toBeNull();
    expect(decodeZcashRecord(enc("PLR2"))).toBeNull();
    expect(decodeZcashRecord(cat(enc("PLR1"), new Uint8Array([0x01]), new Uint8Array(31)))).toBeNull();   // short
    expect(decodeZcashRecord(cat(enc("PLR1"), new Uint8Array([0x01]), new Uint8Array(33)))).toBeNull();   // long
    expect(decodeZcashRecord(cat(enc("PLR1"), new Uint8Array([0x7f]), new Uint8Array(32)))).toBeNull();   // unknown type
    expect(decodeZcashRecord(cat(enc("PLR1"), new Uint8Array([0x05, 9]), new Uint8Array(64)))).toBeNull(); // bad root kind
    for (let i = 0; i < 200; i++) expect(() => decodeZcashRecord(randomBytes(i % 81))).not.toThrow();
  });
  it("encode validates", () => {
    expect(code(() => encodeZcashRecord({ type: "approve_operator", hash160: "33".repeat(20), org_id: "Org" }))).toBe("E_BAD_INPUT");
    expect(code(() => encodeZcashRecord({ type: "approve_operator", hash160: "33".repeat(20), org_id: "o".repeat(49) }))).toBe("E_BAD_INPUT");
    expect(code(() => encodeZcashRecord({ type: "allow_compose", hash: "AB".repeat(32) }))).toBe("E_BAD_INPUT");
    expect(code(() => encodeZcashRecord({ type: "anchor", key_hash: "77".repeat(32), root: "bb".repeat(32), first_seq: 0, count: 0 }))).toBe("E_BAD_INPUT");
  });
});

describe("ZcashLog — owner policy", () => {
  it("identifies the registry and starts empty", () => {
    const L = fresh();
    expect(L.contractId).toBe(`zcash:regtest:${owner.addr}`);
    expect(L.getRoot()).toBeNull();
    expect(L.isComposeAllowed("ab".repeat(32))).toBe(false);
  });
  it("applies owner records in (height, tx index) order and ignores everyone else", () => {
    const L = fresh();
    const h = "ab".repeat(32);
    L.apply(block([rtx(stranger, { type: "allow_compose", hash: h })]));
    expect(L.isComposeAllowed(h)).toBe(false);
    L.apply(block([rtx(owner, { type: "allow_compose", hash: h }), rtx(owner, { type: "revoke_compose", hash: h }), rtx(owner, { type: "allow_os", hash: h })]));
    expect(L.isComposeAllowed(h)).toBe(false);
    expect(L.isOsAllowed(h)).toBe(true);
    L.apply(block([rtx(owner, { type: "allow_compose", hash: h }), rtx(owner, { type: "set_root", kind: "MOCK", p256: "11".repeat(64) })]));
    expect(L.isComposeAllowed(h)).toBe(true);
    expect(L.getRoot()).toEqual({ kind: "MOCK", p256: "11".repeat(64) });
  });
  it("skips coinbase, multi-OP_RETURN, mixed-signer and garbage transactions; re-applied heights are no-ops", () => {
    const L = fresh();
    const h = "ab".repeat(32);
    L.apply(block([
      rtx(owner, { type: "allow_compose", hash: h }, { coinbase: true }),
      rtx(owner, { type: "allow_compose", hash: h }, { extraOpReturn: true }),
      rtx(owner, { type: "allow_compose", hash: h }, { nIn: 2, otherPub: true }),
      rtx(owner, randomBytes(40)),
    ]));
    expect(L.isComposeAllowed(h)).toBe(false);
    const b = block([rtx(owner, { type: "allow_compose", hash: h }, { nIn: 3 })]);
    L.apply(b);
    expect(L.isComposeAllowed(h)).toBe(true);
    L.apply({ ...b, tx: [rtx(owner, { type: "revoke_compose", hash: h })] }); // same height again
    expect(L.isComposeAllowed(h)).toBe(true);
    expect(L.height).toBe(b.height);
  });
  it("transfer_owner hands policy to the new owner", () => {
    const L = fresh();
    const h = "ef".repeat(32);
    L.apply(block([rtx(owner, { type: "transfer_owner", hash160: newOwner.h160 })]));
    L.apply(block([rtx(owner, { type: "allow_compose", hash: h })]));
    expect(L.isComposeAllowed(h)).toBe(false);
    L.apply(block([rtx(newOwner, { type: "allow_compose", hash: h })]));
    expect(L.isComposeAllowed(h)).toBe(true);
  });
});

describe("ZcashLog — instances", () => {
  it("a complete registration by an approved operator is an instance; org is live", () => {
    const L = fresh();
    const k = keys();
    L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })]));
    L.apply(block(regAll(op, k).slice(0, 3)));
    expect(L.getInstance(k.kh)).toBeNull();                  // reg_quote missing
    const b = block(regAll(op, k).slice(3));
    L.apply(b);
    const rec = L.getInstance(k.kh)!;
    expect(rec).toMatchObject({ compose_hash: "c1".repeat(32), os_measurement: "05".repeat(32), x25519: k.x, ed25519: k.e, operator: op.addr, org_id: "org-a", next_seq: 0 });
    expect(rec.registered_at_ms).toBe(b.time * 1000);
    expect(rec.expires_at_ms).toBe(b.time * 1000 + 86_400_000);
    expect(L.registrationQuoteHash(k.kh)).toBe("99".repeat(32));
    L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-z" })]));
    expect(L.getInstance(k.kh)!.org_id).toBe("org-z");
    L.apply(block([rtx(owner, { type: "revoke_operator", hash160: op.h160 })]));
    expect(L.getInstance(k.kh)).toBeNull();                  // unapproved operator ⇒ not registered
  });
  it("registrations by unapproved operators are ignored", () => {
    const L = fresh();
    const k = keys();
    L.apply(block(regAll(stranger, k)));
    expect(L.getInstance(k.kh)).toBeNull();
  });
  it("parts must come from one operator, and reg_keys must hash to the key", () => {
    const L = fresh();
    const k = keys();
    L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" }), rtx(owner, { type: "approve_operator", hash160: op2.h160, org_id: "org-b" })]));
    const a = regAll(op, k), b = regAll(op2, k);
    L.apply(block([a[0]!, a[1]!, b[2]!, b[3]!]));
    expect(L.getInstance(k.kh)).toBeNull();
    const k2 = keys();
    L.apply(block([rtx(op, { type: "reg_keys", x25519: k2.x, ed25519: k.e }), ...regAll(op, k2).slice(1)]));
    expect(L.getInstance(k2.kh)).toBeNull();                 // reg_keys does not hash to k2
  });
  it("the earliest completed approved registration wins; a later copy by another approved operator cannot take over", () => {
    const L = fresh();
    const k = keys();
    L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" }), rtx(owner, { type: "approve_operator", hash160: op2.h160, org_id: "org-b" })]));
    L.apply(block(regAll(op, k)));
    L.apply(block(regAll(op2, k)));
    expect(L.getInstance(k.kh)!.operator).toBe(op.addr);
  });
  it("expires after the TTL; a repeated reg_quote refreshes it", () => {
    const L = fresh();
    const k = keys();
    L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })]));
    L.apply(block(regAll(op, k)));
    L.apply(block([], 90_000));                               // > 1 day (86 400 s) later
    expect(L.getInstance(k.kh)).toBeNull();
    L.apply(block([rtx(op, { type: "reg_quote", key_hash: k.kh, quote_sha256: "98".repeat(32) })], 90_000));
    expect(L.getInstance(k.kh)).not.toBeNull();
    expect(L.registrationQuoteHash(k.kh)).toBe("98".repeat(32));
  });
});

describe("ZcashLog — anchors", () => {
  const setup = () => {
    const L = fresh();
    const k = keys();
    L.apply(block([rtx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })]));
    L.apply(block(regAll(op, k)));
    return { L, k };
  };
  const sig = "dd".repeat(64);
  it("an anchor is accepted with its signature record; next_seq advances; ids count from 0", () => {
    const { L, k } = setup();
    L.apply(block([rtx(op, { type: "anchor", key_hash: k.kh, root: "aa".repeat(32), first_seq: 0, count: 3 }), rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig })]));
    expect(L.anchorCount()).toBe(1);
    expect(L.getAnchor(0)).toMatchObject({ id: 0, key_hash: k.kh, root: "aa".repeat(32), first_seq: 0, count: 3, sig });
    expect(L.getInstance(k.kh)!.next_seq).toBe(3);
    expect(L.getAnchor(1)).toBeNull();
  });
  it("ignores gaps, rewinds, other authors, unsigned anchors after 10 blocks", () => {
    const { L, k } = setup();
    L.apply(block([rtx(op, { type: "anchor", key_hash: k.kh, root: "aa".repeat(32), first_seq: 5, count: 1 }), rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig })]));
    L.apply(block([rtx(stranger, { type: "anchor", key_hash: k.kh, root: "aa".repeat(32), first_seq: 0, count: 1 }), rtx(stranger, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig })]));
    expect(L.anchorCount()).toBe(0);
    L.apply(block([rtx(op, { type: "anchor", key_hash: k.kh, root: "aa".repeat(32), first_seq: 0, count: 2 })]));
    for (let i = 0; i < 11; i++) L.apply(block([]));
    L.apply(block([rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig })]));
    expect(L.anchorCount()).toBe(0);
    L.apply(block([rtx(op, { type: "anchor", key_hash: k.kh, root: "ab".repeat(32), first_seq: 0, count: 2 })]));
    L.apply(block([rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig })]));
    expect(L.anchorCount()).toBe(1);
    expect(L.getAnchor(0)!.root).toBe("ab".repeat(32));
    L.apply(block([rtx(op, { type: "anchor", key_hash: k.kh, root: "ac".repeat(32), first_seq: 0, count: 1 }), rtx(op, { type: "anchor_sig", key_prefix: k.kh.slice(0, 16), sig })]));
    expect(L.anchorCount()).toBe(1);                         // rewind ignored
  });
});
