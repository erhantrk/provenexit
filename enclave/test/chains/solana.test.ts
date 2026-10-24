// SolanaRegistryWriter (SPEC-CHAINS §4, §11): config, instruction encoding, local pre-checks, error mapping,
// send + confirm against a fake RPC. The live path (lookup tables, real program) is exercised by the e2e chain suite.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { AddressLookupTableProgram, Keypair, PublicKey, SYSVAR_CLOCK_PUBKEY, SystemProgram, VersionedTransaction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { MockRoot, MockTdxAttester, PlrError, anchorMessage, fromHex, keyHash, registrationReportData, toHex, utf8 } from "@plr/shared";
import {
  SOLANA_LAYOUT, SolanaProgramError, SolanaRegistryWriter, encodeAnchorReceipts, encodeRegisterInstance, loadSolanaConfig,
  parseSolanaSecret, programError, programErrorCode,
} from "../../src/chains/solana.js";
import { startFakeSolana, type FakeSolana } from "./solana-fake-rpc.js";

const PROGRAM = Keypair.generate().publicKey;
const STATE = Keypair.generate().publicKey;
const OP = Keypair.generate();
const SYSVAR_OWNER = "Sysvar1111111111111111111111111111111111111";
const NOW_S = 1_700_000_000;

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof PlrError || e instanceof SolanaProgramError) return e.code;
    throw e;
  }
  return "NO_THROW";
}

function clock(unixS: number): Uint8Array {
  const b = Buffer.alloc(40);
  b.writeBigInt64LE(BigInt(unixS), 32);
  return b;
}
function stateData(anchors: number): Uint8Array {
  const b = Buffer.alloc(SOLANA_LAYOUT.STATE_LEN);
  b[0] = 1;
  b[66] = 1;
  b.writeBigUInt64LE(BigInt(anchors), 139);
  return b;
}
function instData(o: { ed: Uint8Array; operator: PublicKey; expiresMs: number; nextSeq: number }): Uint8Array {
  const b = Buffer.alloc(SOLANA_LAYOUT.INSTANCE_LEN);
  b[0] = 5;
  b.fill(0x11, 1, 33);
  Buffer.from(o.ed).copy(b, 33);
  b.fill(0xc0, 65, 97);
  b.fill(0x05, 97, 129);
  o.operator.toBuffer().copy(b, 129);
  b.writeBigUInt64LE(1n, 161);
  b.writeBigUInt64LE(BigInt(o.expiresMs), 169);
  b.writeBigUInt64LE(BigInt(o.nextSeq), 177);
  return b;
}

describe("loadSolanaConfig", () => {
  const env = { PLR_SOLANA_RPC: "http://127.0.0.1:8899", PLR_SOLANA_PROGRAM: PROGRAM.toBase58(), PLR_SOLANA_REGISTRY: STATE.toBase58(), PLR_SOLANA_KEY: toHex(OP.secretKey) };
  it("is all-or-nothing and strictly validated", () => {
    expect(loadSolanaConfig({})).toBeNull();
    expect(loadSolanaConfig(env)).toEqual({ rpcUrl: env.PLR_SOLANA_RPC, programId: env.PLR_SOLANA_PROGRAM, registry: env.PLR_SOLANA_REGISTRY, key: env.PLR_SOLANA_KEY });
    expect(() => loadSolanaConfig({ ...env, PLR_SOLANA_KEY: "" })).toThrow(PlrError);
    expect(() => loadSolanaConfig({ ...env, PLR_SOLANA_RPC: "ftp://x" })).toThrow(PlrError);
    expect(() => loadSolanaConfig({ ...env, PLR_SOLANA_PROGRAM: "0OIl" })).toThrow(PlrError);
    expect(() => loadSolanaConfig({ ...env, PLR_SOLANA_REGISTRY: `${STATE.toBase58()} ` })).toThrow(PlrError);
    expect(() => loadSolanaConfig({ ...env, PLR_SOLANA_KEY: toHex(OP.secretKey).slice(0, 64) })).toThrow(PlrError);
    // the public half must match the seed
    const k = Buffer.from(OP.secretKey);
    k[63]! ^= 1;
    expect(() => loadSolanaConfig({ ...env, PLR_SOLANA_KEY: k.toString("hex") })).toThrow(PlrError);
    // a VPN-specific registry variable
    const vpn = { ...env, PLR_SOLANA_REGISTRY: undefined, PLR_SOLANA_VPN_REGISTRY: STATE.toBase58() };
    expect(loadSolanaConfig(vpn, "PLR_SOLANA_VPN_REGISTRY")?.registry).toBe(STATE.toBase58());
    expect(parseSolanaSecret(toHex(OP.secretKey)).publicKey.equals(OP.publicKey)).toBe(true);
  });
});

describe("instruction encoding (SPEC-CHAINS §11)", () => {
  it("RegisterInstance = 10 ‖ x ‖ ed ‖ compose ‖ os ‖ quote[828]", () => {
    const f = (b: number) => new Uint8Array(32).fill(b);
    const d = encodeRegisterInstance(f(1), f(2), f(3), f(4), new Uint8Array(828).fill(9));
    expect(d.length).toBe(1 + 128 + 828);
    expect(d[0]).toBe(10);
    expect([d[1], d[33], d[65], d[97], d[129], d[956]]).toEqual([1, 2, 3, 4, 9, 9]);
    expect(() => encodeRegisterInstance(f(1), f(2), f(3), f(4), new Uint8Array(827))).toThrow(/E_QUOTE_FORMAT/);
    expect(() => encodeRegisterInstance(f(1), f(2), f(3), new Uint8Array(31), new Uint8Array(828))).toThrow(PlrError);
  });
  it("AnchorReceipts = 11 ‖ key_hash ‖ root ‖ u64le first_seq ‖ u64le count ‖ sig[64]", () => {
    const d = encodeAnchorReceipts(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 0x0102, 3, new Uint8Array(64).fill(7));
    expect(d.length).toBe(1 + 64 + 16 + 64);
    expect(d[0]).toBe(11);
    expect(toHex(d.subarray(65, 81))).toBe("0201000000000000" + "0300000000000000");
    expect(d[81]).toBe(7);
  });
  it("maps Custom(n) with the §10 numbering", () => {
    const e = (n: number) => ({ InstructionError: [0, { Custom: n }] });
    expect(programErrorCode(e(1))).toBe("E_UNAUTHORIZED");
    expect(programErrorCode(e(2))).toBe("E_ZERO_HASH");
    expect(programErrorCode(e(4))).toBe("E_OPERATOR_UNAPPROVED");
    expect(programErrorCode(e(7))).toBe("E_SEQ");
    expect(programErrorCode(e(9))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(programErrorCode(e(10))).toBeNull();
    expect(programErrorCode({ InstructionError: [0, "InvalidArgument"] })).toBeNull();
    expect(programErrorCode("AccountNotFound")).toBeNull();
    expect(programError("E_SEQ")).toBeInstanceOf(PlrError);
    const u = programError("E_UNAUTHORIZED");
    expect(u).toBeInstanceOf(SolanaProgramError);
    expect(u.message).toBe("E_UNAUTHORIZED"); // the instance logger extracts the code from the message
  });
});

describe("SolanaRegistryWriter", () => {
  let F: FakeSolana;
  let W: SolanaRegistryWriter;
  const edSk = ed25519.utils.randomSecretKey();
  const ed = ed25519.getPublicKey(edSk);
  const x = new Uint8Array(32).fill(0x11);
  const kh = toHex(keyHash(x, ed));
  const instPda = () => W.pdas.instance(fromHex(kh, 32)).toBase58();
  const sigFor = (firstSeq: number, count: number, contractId = W.contractId) =>
    toHex(ed25519.sign(anchorMessage({ contractId, keyHash: fromHex(kh, 32), root: new Uint8Array(32).fill(0xaa), firstSeq: BigInt(firstSeq), count: BigInt(count) }), edSk));
  const anchorArgs = (firstSeq = 4, count = 2) => ({ key_hash: kh, root: "aa".repeat(32), first_seq: firstSeq, count, sig: sigFor(firstSeq, count) });

  beforeAll(async () => {
    F = await startFakeSolana();
  });
  afterAll(async () => F.close());
  beforeEach(() => {
    F.accounts.clear();
    F.sent.length = 0;
    F.simulated.length = 0;
    F.calls.length = 0;
    F.simErr = null;
    F.status = { err: null, confirmationStatus: "confirmed" };
    W = new SolanaRegistryWriter({ rpcUrl: F.url, programId: PROGRAM.toBase58(), registry: STATE.toBase58(), key: toHex(OP.secretKey), pollMs: 5, resendMs: 20, confirmTimeoutMs: 500 });
    F.accounts.set(SYSVAR_CLOCK_PUBKEY.toBase58(), { owner: SYSVAR_OWNER, data: clock(NOW_S) });
    F.accounts.set(STATE.toBase58(), { owner: PROGRAM.toBase58(), data: stateData(3) });
    F.accounts.set(instPda(), { owner: PROGRAM.toBase58(), data: instData({ ed, operator: OP.publicKey, expiresMs: NOW_S * 1000 + 60_000, nextSeq: 4 }) });
  });

  it("has the §3 identifiers", () => {
    expect(W.contractId).toBe(`solana:${STATE.toBase58()}`);
    expect(W.operatorId).toBe(OP.publicKey.toBase58());
    expect(() => new SolanaRegistryWriter({ rpcUrl: "file:///x", programId: PROGRAM.toBase58(), registry: STATE.toBase58(), key: OP })).toThrow(PlrError);
  });

  it("reads instance state in chain (Clock) time", async () => {
    expect(await W.getInstanceNextSeq(kh)).toBe(4);
    expect(await W.getInstanceOperator(kh)).toBe(OP.publicKey.toBase58());
    expect(await W.anchorCount()).toBe(3);
    F.accounts.set(SYSVAR_CLOCK_PUBKEY.toBase58(), { owner: SYSVAR_OWNER, data: clock(NOW_S + 60) });
    expect(await W.getInstanceNextSeq(kh)).toBeNull();
    expect(await W.getInstanceOperator("00".repeat(31) + "01")).toBeNull();
    F.accounts.set(instPda(), { owner: Keypair.generate().publicKey.toBase58(), data: new Uint8Array(1013) });
    expect(await codeOf(W.getInstanceNextSeq(kh))).toBe("E_REGISTRY_UNAVAILABLE");
  });

  it("decodes anchors", async () => {
    const b = Buffer.alloc(SOLANA_LAYOUT.ANCHOR_LEN);
    b[0] = 6;
    Buffer.from(kh, "hex").copy(b, 1);
    b.fill(0xaa, 33, 65);
    b.writeBigUInt64LE(4n, 65);
    b.writeBigUInt64LE(2n, 73);
    F.accounts.set(W.pdas.anchor(2).toBase58(), { owner: PROGRAM.toBase58(), data: b });
    expect(await W.getAnchor(2)).toEqual({ id: 2, key_hash: kh, root: "aa".repeat(32), first_seq: 4, count: 2 });
    expect(await W.getAnchor(5)).toBeNull();
  });

  it("refuses to register a quote not bound to (contractId, own operator), before any RPC", async () => {
    const root = MockRoot.generate();
    const att = new MockTdxAttester({ root, composeBytes: utf8("{}") });
    const other = Keypair.generate().publicKey.toBase58();
    const { quote, eventLog } = await att.getQuote(registrationReportData(x, ed, W.contractId, other));
    const args = { quote: toHex(quote), event_log: eventLog, app_compose: "{}", x25519: toHex(x), ed25519: toHex(ed) };
    expect(await codeOf(W.registerInstance(args))).toBe("E_REPORT_DATA");
    const q2 = await att.getQuote(registrationReportData(x, ed, "solana:11111111111111111111111111111111", W.operatorId));
    expect(await codeOf(W.registerInstance({ ...args, quote: toHex(q2.quote) }))).toBe("E_REPORT_DATA");
    expect(F.calls).toEqual([]);
    expect(await codeOf(W.registerInstance({ ...args, x25519: "zz" }))).toBe("E_BAD_INPUT");
    // bound correctly but the operator is not approved: refused without creating a lookup table
    const q3 = await att.getQuote(registrationReportData(x, ed, W.contractId, W.operatorId));
    expect(await codeOf(W.registerInstance({ ...args, quote: toHex(q3.quote) }))).toBe("E_OPERATOR_UNAPPROVED");
    expect(F.sent).toEqual([]);
  });

  it("passes the current holder's op PDA when another operator holds the key (squat recovery after revocation)", async () => {
    const root = MockRoot.generate();
    const att = new MockTdxAttester({ root, composeBytes: utf8("{}") });
    const { quote, eventLog } = await att.getQuote(registrationReportData(x, ed, W.contractId, W.operatorId));
    const args = { quote: toHex(quote), event_log: eventLog, app_compose: "{}", x25519: toHex(x), ed25519: toHex(ed) };
    const opData = Buffer.alloc(SOLANA_LAYOUT.OPERATOR_LEN);
    opData[0] = SOLANA_LAYOUT.TAG_OPERATOR;
    opData[1] = 1;
    F.accounts.set(W.pdas.operator(OP.publicKey).toBase58(), { owner: PROGRAM.toBase58(), data: opData });
    // a lookup table (recentSlot = the fake's slot 50) already holding the four static addresses, usable now
    const [, table] = AddressLookupTableProgram.createLookupTable({ authority: OP.publicKey, payer: OP.publicKey, recentSlot: 50 });
    const addrs = [STATE, W.pdas.operator(OP.publicKey), W.pdas.instance(fromHex(kh, 32)), SystemProgram.programId];
    const alt = Buffer.alloc(56 + 32 * addrs.length);
    alt.writeUInt32LE(1, 0);
    alt.writeBigUInt64LE(0xffff_ffff_ffff_ffffn, 4);
    alt.writeBigUInt64LE(10n, 12);
    alt[21] = 1;
    OP.publicKey.toBuffer().copy(alt, 22);
    addrs.forEach((a, i) => a.toBuffer().copy(alt, 56 + 32 * i));
    F.accounts.set(table.toBase58(), { owner: AddressLookupTableProgram.programId.toBase58(), data: alt });
    const accountsOfLastRegister = () => {
      const tx = VersionedTransaction.deserialize(F.sent[F.sent.length - 1]!);
      const m = tx.message;
      const ix = m.compiledInstructions.find((c) => m.staticAccountKeys[c.programIdIndex]!.equals(PROGRAM))!;
      return { ix, statics: m.staticAccountKeys.map((k) => k.toBase58()) };
    };
    // held by another (expired or not) operator: its op PDA is appended as a static key, so the program can check it
    const squatter = Keypair.generate().publicKey;
    F.accounts.set(instPda(), { owner: PROGRAM.toBase58(), data: instData({ ed, operator: squatter, expiresMs: NOW_S * 1000 - 1, nextSeq: 7 }) });
    expect(await codeOf(W.registerInstance(args))).toBe("E_REGISTRY_UNAVAILABLE"); // the fake ledger never changes: not visible
    let { ix, statics } = accountsOfLastRegister();
    expect(ix.accountKeyIndexes.length).toBe(6);
    expect(statics[ix.accountKeyIndexes[5]!]).toBe(W.pdas.operator(squatter).toBase58());
    expect(F.sent[F.sent.length - 1]!.length).toBeLessThanOrEqual(1232); // fits a packet with the extra static key
    // held by us: the plain five accounts
    F.sent.length = 0;
    F.accounts.set(instPda(), { owner: PROGRAM.toBase58(), data: instData({ ed, operator: OP.publicKey, expiresMs: NOW_S * 1000 + 60_000, nextSeq: 4 }) });
    expect(await codeOf(W.registerInstance(args))).toBe("E_REGISTRY_UNAVAILABLE");
    ({ ix } = accountsOfLastRegister());
    expect(ix.accountKeyIndexes.length).toBe(5);
    expect(F.sent[0]!.length).toBeLessThanOrEqual(1232);
  });

  it("anchors at the next anchor id and returns it", async () => {
    const id = await W.anchorReceipts(anchorArgs());
    expect(id).toBe(3);
    expect(F.sent.length).toBe(1);
    const tx = VersionedTransaction.deserialize(F.sent[0]!);
    const keys = tx.message.staticAccountKeys.map((k) => k.toBase58());
    const ix = tx.message.compiledInstructions[0]!;
    expect(keys[ix.programIdIndex]).toBe(PROGRAM.toBase58());
    const accts = ix.accountKeyIndexes.map((i) => keys[i]);
    expect(accts).toEqual([
      STATE.toBase58(), OP.publicKey.toBase58(), instPda(), W.pdas.anchor(3).toBase58(),
      W.pdas.compose(new Uint8Array(32).fill(0xc0)).toBase58(), W.pdas.os(new Uint8Array(32).fill(0x05)).toBase58(),
      "11111111111111111111111111111111",
    ]);
    expect(Buffer.from(ix.data).equals(encodeAnchorReceipts(fromHex(kh, 32), new Uint8Array(32).fill(0xaa), 4, 2, fromHex(anchorArgs().sig, 64)))).toBe(true);
    expect(tx.signatures.length).toBe(1);
    expect(F.simulated.length).toBe(1); // simulated before sending
  });

  it("checks the anchor locally first (sig, seq, operator, registration)", async () => {
    expect(await codeOf(W.anchorReceipts({ ...anchorArgs(), sig: sigFor(4, 2, "solana:other") }))).toBe("E_ANCHOR_SIG");
    expect(await codeOf(W.anchorReceipts(anchorArgs(5, 2)))).toBe("E_SEQ");
    expect(await codeOf(W.anchorReceipts({ ...anchorArgs(), count: 0 }))).toBe("E_BAD_INPUT");
    expect(await codeOf(W.anchorReceipts({ ...anchorArgs(), count: 10_001 }))).toBe("E_BAD_INPUT");
    F.accounts.set(instPda(), { owner: PROGRAM.toBase58(), data: instData({ ed, operator: Keypair.generate().publicKey, expiresMs: NOW_S * 1000 + 60_000, nextSeq: 4 }) });
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_INSTANCE_NOT_REGISTERED");
    F.accounts.delete(instPda());
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_INSTANCE_NOT_REGISTERED");
    expect(F.sent).toEqual([]);
  });

  it("maps program refusals from simulation and from the confirmed status", async () => {
    F.simErr = { InstructionError: [0, { Custom: 9 }] };
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(F.sent).toEqual([]);
    F.simErr = { InstructionError: [0, { Custom: 1 }] };
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_UNAUTHORIZED");
    F.simErr = "AccountNotFound";
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_REGISTRY_UNAVAILABLE");
    F.simErr = null;
    F.status = { err: { InstructionError: [0, { Custom: 7 }] }, confirmationStatus: "confirmed" };
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_SEQ");
  });

  it("bounds confirmation (timeout, expired blockhash) and re-sends while waiting", async () => {
    F.status = null;
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_REGISTRY_UNAVAILABLE");
    expect(F.sent.length).toBeGreaterThan(1);
    F.sent.length = 0;
    F.blockHeight = 101;
    const t0 = Date.now();
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_REGISTRY_UNAVAILABLE");
    expect(Date.now() - t0).toBeLessThan(400);
    F.blockHeight = 10;
    F.status = { err: null, confirmationStatus: "processed" };
    expect(await codeOf(W.anchorReceipts(anchorArgs()))).toBe("E_REGISTRY_UNAVAILABLE");
  });

  it("an unreachable RPC is E_REGISTRY_UNAVAILABLE", async () => {
    const dead = new SolanaRegistryWriter({ rpcUrl: "http://127.0.0.1:9", programId: PROGRAM.toBase58(), registry: STATE.toBase58(), key: OP, rpcTimeoutMs: 500 });
    expect(await codeOf(dead.anchorCount())).toBe("E_REGISTRY_UNAVAILABLE");
    expect(await codeOf(dead.getInstanceNextSeq(kh))).toBe("E_REGISTRY_UNAVAILABLE");
  });
});
