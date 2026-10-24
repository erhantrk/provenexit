import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Address, Keypair, StrKey, xdr } from "@stellar/stellar-sdk";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { MockRoot, MockTdxAttester, PlrError, keyHash, registrationReportData, toHex, utf8 } from "@plr/shared";
import { StellarContractError, StellarRegistryWriter, createStellarWriter, loadStellar, stellarContractErrorOf } from "../../src/chains/stellar.js";
import { scStructOf, signedBy, startFakeStellar, type FakeStellar, type SimHandler } from "./stellar-fake.js";

const PP = "Standalone Network ; February 2017";
const C = StrKey.encodeContract(Buffer.alloc(32, 3));
const kp = Keypair.random();
const b = (n: number, len = 32) => xdr.ScVal.scvBytes(new Uint8Array(len).fill(n));
const u64 = (n: number) => xdr.ScVal.scvU64(BigInt(n));
const h = (n: number) => toHex(new Uint8Array(32).fill(n));

const ENV = { PLR_STELLAR_RPC: "http://127.0.0.1:8000/rpc", PLR_STELLAR_PASSPHRASE: PP, PLR_STELLAR_REGISTRY: C, PLR_STELLAR_KEY: kp.secret() };

describe("loadStellar (PLR_STELLAR_*)", () => {
  it("none set ⇒ null; all set ⇒ config", () => {
    expect(loadStellar({})).toBeNull();
    expect(loadStellar(ENV)).toEqual({ rpcUrl: ENV.PLR_STELLAR_RPC, networkPassphrase: PP, registry: C, key: kp.secret() });
  });
  it("partial or invalid ⇒ E_BAD_INPUT naming the variable, never the secret", () => {
    const cases: Record<string, string | undefined>[] = [
      { ...ENV, PLR_STELLAR_KEY: undefined },
      { ...ENV, PLR_STELLAR_RPC: "ftp://x" },
      { ...ENV, PLR_STELLAR_RPC: "http://u:p@127.0.0.1/rpc" },
      { ...ENV, PLR_STELLAR_PASSPHRASE: "bad\nline" },
      { ...ENV, PLR_STELLAR_REGISTRY: kp.publicKey() },
      { ...ENV, PLR_STELLAR_KEY: kp.publicKey() },
      // last character always changed (a random secret may already end in "A"): breaks the strkey checksum
      { ...ENV, PLR_STELLAR_KEY: kp.secret().slice(0, -1) + (kp.secret().endsWith("A") ? "B" : "A") },
    ];
    for (const env of cases) {
      let err: unknown;
      try { loadStellar(env); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(PlrError);
      expect((err as PlrError).code).toBe("E_BAD_INPUT");
      expect((err as Error).message).not.toContain(kp.secret());
    }
  });
  it("uses the given registry variable (VPN exit: PLR_STELLAR_VPN_REGISTRY)", () => {
    const vpn = StrKey.encodeContract(Buffer.alloc(32, 4));
    const env = { ...ENV, PLR_STELLAR_REGISTRY: undefined, PLR_STELLAR_VPN_REGISTRY: vpn };
    expect(loadStellar(env, "PLR_STELLAR_VPN_REGISTRY")?.registry).toBe(vpn);
  });
});

describe("StellarRegistryWriter", () => {
  let rpc: FakeStellar;
  let handler: SimHandler = () => xdr.ScVal.scvVoid();
  let w: StellarRegistryWriter;
  beforeAll(async () => {
    rpc = await startFakeStellar(PP, (fn, a) => handler(fn, a));
  });
  afterAll(async () => rpc?.close());
  beforeEach(() => {
    w = new StellarRegistryWriter({ rpcUrl: rpc.url, networkPassphrase: PP, registry: C, key: kp.secret(), confirmTimeoutMs: 300, pollMs: 20, timeoutMs: 2000, maxSubmitAttempts: 3 });
    rpc.sent.length = 0;
    rpc.sims.length = 0;
    rpc.sendStatus = "PENDING";
    rpc.restoreFee = null;
  });

  it("identifiers per SPEC-CHAINS §3", () => {
    expect(w.contractId).toBe(`stellar:${C}`);
    expect(w.operatorId).toBe(kp.publicKey());
    expect(createStellarWriter({ rpcUrl: rpc.url, networkPassphrase: PP, registry: C, key: kp.secret() }).contractId).toBe(`stellar:${C}`);
    expect((w as { reuseRegistrationQuote?: boolean }).reuseRegistrationQuote).toBeUndefined();
  });

  it("validates its options", () => {
    const o = { rpcUrl: rpc.url, networkPassphrase: PP, registry: C, key: kp.secret() };
    expect(() => new StellarRegistryWriter({ ...o, rpcUrl: "nope" })).toThrow(PlrError);
    expect(() => new StellarRegistryWriter({ ...o, registry: kp.publicKey() })).toThrow(PlrError);
    expect(() => new StellarRegistryWriter({ ...o, key: "S" })).toThrow(PlrError);
    expect(() => new StellarRegistryWriter({ ...o, networkPassphrase: "" })).toThrow(PlrError);
    expect(() => new StellarRegistryWriter({ ...o, confirmTimeoutMs: 0 })).toThrow(PlrError);
  });

  it("reads back instance, anchors and counts", async () => {
    handler = (fn, args) => {
      switch (fn) {
        case "get_instance":
          return scStructOf({
            compose_hash: b(1), os_measurement: b(2), x25519: b(3), ed25519: b(4), operator: new Address(kp.publicKey()).toScVal(),
            registered_at_ms: u64(1), expires_at_ms: u64(2), next_seq: u64(7),
          });
        case "anchor_count": return u64(2);
        case "get_anchor":
          return args[0]!.type === "scvU64" && args[0]!.u64 === 1n
            ? scStructOf({ key_hash: b(9), root: b(8), first_seq: u64(4), count: u64(3), at_ms: u64(5), sig: b(6, 64) })
            : xdr.ScVal.scvVoid();
        default: return xdr.ScVal.scvVoid();
      }
    };
    expect(await w.getInstanceNextSeq(h(9))).toBe(7);
    expect(await w.getInstanceOperator(h(9))).toBe(kp.publicKey());
    expect(await w.anchorCount()).toBe(2);
    expect(await w.getAnchor(1)).toEqual({ id: 1, key_hash: h(9), root: h(8), first_seq: 4, count: 3 });
    expect(await w.getAnchor(0)).toBeNull();
    handler = () => xdr.ScVal.scvVoid();
    expect(await w.getInstanceNextSeq(h(9))).toBeNull();
    expect(await w.getInstanceOperator(h(9))).toBeNull();
  });

  it("malformed views ⇒ E_BAD_RESPONSE", async () => {
    handler = () => xdr.ScVal.scvU32(3);
    await expect(w.anchorCount()).rejects.toMatchObject({ code: "E_BAD_RESPONSE" });
    await expect(w.getInstanceNextSeq(h(9))).rejects.toMatchObject({ code: "E_BAD_RESPONSE" });
    handler = () => scStructOf({ key_hash: b(9) });
    await expect(w.getAnchor(0)).rejects.toMatchObject({ code: "E_BAD_RESPONSE" });
  });

  it("maps contract errors (Error(Contract, #n)) to PLR codes", async () => {
    expect(stellarContractErrorOf("HostError: Error(Contract, #7)")).toBe("E_SEQ");
    handler = () => ({ error: "HostError: Error(Contract, #7)\nEvent log" });
    const args = { key_hash: h(9), root: h(8), first_seq: 0, count: 1, sig: toHex(new Uint8Array(64)) };
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_SEQ" });
    handler = () => ({ error: "HostError: Error(Contract, #8)" });
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_INSTANCE_NOT_REGISTERED" });
    handler = () => ({ error: "HostError: Error(Contract, #1)" });
    const e = await w.anchorReceipts(args).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(StellarContractError);
    expect((e as Error).message).toMatch(/^E_UNAUTHORIZED/);
    handler = () => ({ error: "HostError: Error(Budget, ExceededLimit)" });
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    expect(rpc.sent).toHaveLength(0); // nothing submitted when simulation fails
  });

  it("validates anchor args before any RPC", async () => {
    const ok = { key_hash: h(9), root: h(8), first_seq: 0, count: 1, sig: toHex(new Uint8Array(64)) };
    for (const bad of [{ ...ok, count: 0 }, { ...ok, count: 10_001 }, { ...ok, first_seq: -1 }, { ...ok, sig: "00" }, { ...ok, key_hash: "zz" }]) {
      await expect(w.anchorReceipts(bad)).rejects.toMatchObject({ code: "E_BAD_INPUT" });
    }
    expect(rpc.sims).toHaveLength(0);
  });

  it("signs with the operator key, bounded confirmation, retries TRY_AGAIN_LATER", async () => {
    handler = () => u64(0);
    const args = { key_hash: h(9), root: h(8), first_seq: 0, count: 1, sig: toHex(new Uint8Array(64)) };
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" }); // never confirmed (NOT_FOUND)
    expect(rpc.sent).toHaveLength(1);
    const tx = rpc.sent[0]!;
    expect(tx.source).toBe(kp.publicKey());
    expect(signedBy(tx, kp)).toBe(true);
    rpc.sent.length = 0;
    rpc.sendStatus = "TRY_AGAIN_LATER";
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    expect(rpc.sent).toHaveLength(3); // maxSubmitAttempts
    rpc.sent.length = 0;
    rpc.sendStatus = "ERROR";
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    expect(rpc.sent).toHaveLength(1); // a non-sequence error is not retried
  });

  it("archived state: restores the footprint before submitting (bounded); views use the simulated result", async () => {
    handler = () => u64(3);
    rpc.restoreFee = "5000";
    expect(await w.anchorCount()).toBe(3);
    expect(rpc.sent).toHaveLength(0);
    const args = { key_hash: h(9), root: h(8), first_seq: 0, count: 1, sig: toHex(new Uint8Array(64)) };
    // the fake never confirms: the restore times out (bounded) and nothing else is submitted
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    expect(rpc.sent).toHaveLength(1);
    const tx = rpc.sent[0]!;
    expect(tx.operations.map((o) => o.type)).toEqual(["restoreFootprint"]);
    expect(tx.source).toBe(kp.publicKey());
    expect(tx.sequence).toBe("42"); // the account's next sequence number (not consumed by the simulated invocation)
    expect(tx.fee).toBe(String(1000 + 5000));
    expect(signedBy(tx, kp)).toBe(true);
    // a restore the network refuses is not retried
    rpc.sent.length = 0;
    rpc.sendStatus = "ERROR";
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    expect(rpc.sent).toHaveLength(1);
    // a malformed preamble is refused before anything is sent
    rpc.sent.length = 0;
    rpc.restoreFee = "-1";
    await expect(w.anchorReceipts(args)).rejects.toMatchObject({ code: "E_BAD_RESPONSE" });
    expect(rpc.sent).toHaveLength(0);
  });

  it("registration: refuses a quote not bound to this registry + operator before submitting", async () => {
    const root = MockRoot.fromSecret(new Uint8Array(32).fill(1));
    const att = new MockTdxAttester({ root, composeBytes: utf8("{}\n") });
    const xs = x25519.utils.randomSecretKey(), es = ed25519.utils.randomSecretKey();
    const xp = x25519.getPublicKey(xs), ep = ed25519.getPublicKey(es);
    const base = { event_log: [], app_compose: "{}\n", x25519: toHex(xp), ed25519: toHex(ep) };
    const other = Keypair.random().publicKey();
    const { quote: wrongOp } = await att.getQuote(registrationReportData(xp, ep, w.contractId, other));
    await expect(w.registerInstance({ ...base, quote: toHex(wrongOp) })).rejects.toMatchObject({ code: "E_REPORT_DATA" });
    const { quote: wrongReg } = await att.getQuote(registrationReportData(xp, ep, `stellar:${StrKey.encodeContract(Buffer.alloc(32, 5))}`, w.operatorId));
    await expect(w.registerInstance({ ...base, quote: toHex(wrongReg) })).rejects.toMatchObject({ code: "E_REPORT_DATA" });
    await expect(w.registerInstance({ ...base, quote: "zz" })).rejects.toMatchObject({ code: "E_BAD_INPUT" });
    expect(rpc.sims).toHaveLength(0);

    // A bound quote is submitted as register_instance(operator, x, ed, sha256(compose), osMeasurement, quote).
    let seen: xdr.ScVal[] = [];
    handler = (fn, a) => {
      if (fn === "register_instance") seen = a;
      return xdr.ScVal.scvVoid();
    };
    const { quote } = await att.getQuote(registrationReportData(xp, ep, w.contractId, w.operatorId));
    await expect(w.registerInstance({ ...base, quote: toHex(quote) })).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" }); // fake never confirms
    expect(seen).toHaveLength(6);
    expect(Address.fromScVal(seen[0]!).toString()).toBe(kp.publicKey());
    expect(seen[5]!.type === "scvBytes" && toHex(seen[5]!.bytes.value)).toBe(toHex(quote));
    expect(toHex(keyHash(xp, ep))).toHaveLength(64);
  });
});
