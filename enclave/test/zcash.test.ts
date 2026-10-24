import { afterEach, describe, expect, it } from "vitest";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  MockRoot, MockTdxAttester, PlrError, ZcashLog, anchorMessage, decodeZcashRecord, encodeZcashRecord, fromHex, hash160, opReturnData,
  opReturnScript, osMeasurement, parseQuote, registrationReportData, tAddress, toHex, zip317Fee, type Receipt, type ZcashRecord,
} from "@plr/shared";
import { Anchorer } from "../src/anchor.js";
import { createRegistryWriter } from "../src/chains.js";
import { composeBytes, makeCompose } from "../src/compose.js";
import { loadConfig } from "../src/config.js";
import { RouterKeys } from "../src/keys.js";
import { HttpLlmClient } from "../src/llm.js";
import { Logger } from "../src/log.js";
import { COMBO_EXIT_ENV_ALLOWLIST, COMBO_ROUTER_ENV_ALLOWLIST, EXIT_ENV_ALLOWLIST, ROUTER_ENV_ALLOWLIST, comboProcessEnvs } from "../src/mock-tdx/host.js";
import { NearRegistryWriter } from "../src/near.js";
import { ReceiptLog } from "../src/receipts.js";
import { createRouter } from "../src/router.js";
import { loadExitConfig } from "../src/vpn/config.js";
import { ZcashRegistryWriter, ZebraRpc } from "../src/zcash.js";
import { BRANCH_ID, FakeZebra, coinbaseRaw } from "./zebra-fake.js";

const COMPOSE = composeBytes(makeCompose({ kind: "mock", modelSha256: "11".repeat(32), runtime: "node", bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", runtimeSha256: "33".repeat(32), nodeSha256: "33".repeat(32) }));
const COIN = 100_000_000n;

const newKey = () => secp256k1.utils.randomSecretKey();
const h160Of = (sk: Uint8Array) => hash160(secp256k1.getPublicKey(sk, true));
const addrOf = (sk: Uint8Array) => tAddress(h160Of(sk), "regtest");

const nodes: FakeZebra[] = [];
const writers: ZcashRegistryWriter[] = [];
afterEach(async () => {
  for (const w of writers.splice(0)) w.close();
  for (const n of nodes.splice(0)) await n.stop();
});

async function setup(o: { coins?: number; autoMineMs?: number | null; random?: () => number; approve?: boolean } = {}) {
  const node = new FakeZebra();
  nodes.push(node);
  await node.start();
  const ownerSk = newKey();
  const opSk = newKey();
  node.fund(h160Of(ownerSk), Array.from({ length: 5 }, () => COIN));
  node.fund(h160Of(opSk), Array.from({ length: o.coins ?? 10 }, () => COIN));
  const owner = addrOf(ownerSk);
  const writer = new ZcashRegistryWriter({
    rpc: node.url, network: "regtest", owner, key: toHex(opSk), pollMs: 5, confirmTimeoutMs: 5_000, coinTimeoutMs: 2_000,
    ...(o.random ? { random: o.random } : {}),
  });
  writers.push(writer);
  if (o.approve !== false) {
    node.post(ownerSk, opReturnScript(encodeZcashRecord({ type: "approve_operator", hash160: toHex(h160Of(opSk)), org_id: "org-a" })));
    node.mine();
  }
  node.accepted.splice(0); // count only the writer's own submissions from here on
  if (o.autoMineMs !== null) node.autoMine(o.autoMineMs ?? 20);
  const root = MockRoot.generate();
  const attester = new MockTdxAttester({ root, composeBytes: COMPOSE });
  const keys = RouterKeys.generate();
  /** An independent reader over the fake chain's blocks (what clients do). */
  const reader = () => {
    const log = new ZcashLog({ network: "regtest", owner });
    for (const b of node.blockJson()) log.apply(b as never);
    return log;
  };
  const registerArgs = async (operator = writer.operatorId) => {
    const { quote, eventLog } = await attester.getQuote(registrationReportData(keys.x25519, keys.ed25519, writer.contractId, operator));
    return { quote: toHex(quote), event_log: eventLog, app_compose: new TextDecoder().decode(COMPOSE), x25519: toHex(keys.x25519), ed25519: toHex(keys.ed25519) };
  };
  return { node, ownerSk, opSk, owner, writer, attester, keys, reader, registerArgs };
}

const recordsOf = (txs: { tx: { vout: { script: Uint8Array }[] } }[]): ZcashRecord[] =>
  txs.map((s) => {
    const o = s.tx.vout.find((v) => v.script[0] === 0x6a)!;
    return decodeZcashRecord(opReturnData(o.script)!)!;
  });

describe("ZcashRegistryWriter: identity (SPEC-CHAINS §3)", () => {
  it("contractId = zcash:<network>:<owner>, operatorId = the key's t-address", async () => {
    const t = await setup({ autoMineMs: null });
    expect(t.writer.contractId).toBe(`zcash:regtest:${t.owner}`);
    expect(t.writer.operatorId).toBe(addrOf(t.opSk));
    expect(t.writer.reuseRegistrationQuote).toBe(true);
    expect(() => new ZcashRegistryWriter({ rpc: t.node.url, network: "mainnet", owner: t.owner, key: toHex(t.opSk) })).toThrow(PlrError);
    expect(() => new ZcashRegistryWriter({ rpc: t.node.url, network: "regtest", owner: t.owner, key: "00".repeat(32) })).toThrow(PlrError);
  });
});

describe("ZcashRegistryWriter: registration (SPEC-CHAINS §4, §5)", () => {
  it("posts reg_keys / reg_measure / reg_os / reg_quote as signed v5 txs that decode back and complete the registration", async () => {
    const t = await setup();
    const args = await t.registerArgs();
    await t.writer.registerInstance(args);
    expect(t.node.accepted).toHaveLength(4);
    const recs = recordsOf(t.node.accepted);
    const kh = toHex(t.keys.keyHash);
    const q = fromHex(args.quote);
    expect(recs).toEqual(expect.arrayContaining([
      { type: "reg_keys", x25519: args.x25519, ed25519: args.ed25519 },
      { type: "reg_measure", key_hash: kh, compose_hash: toHex(sha256(COMPOSE)) },
      { type: "reg_os", key_hash: kh, os_measurement: toHex(osMeasurement(parseQuote(q).report)) },
      { type: "reg_quote", key_hash: kh, quote_sha256: toHex(sha256(q)) },
    ]));
    // An independent reader (the client's rules) sees the instance under our operator.
    const log = t.reader();
    const inst = log.getInstance(kh)!;
    expect(inst).not.toBeNull();
    expect(inst.operator).toBe(t.writer.operatorId);
    expect(inst.org_id).toBe("org-a");
    expect(log.registrationQuoteHash(kh)).toBe(toHex(sha256(q)));
    expect(await t.writer.getInstanceOperator(kh)).toBe(t.writer.operatorId);
    expect(await t.writer.getInstanceNextSeq(kh)).toBe(0);
  });

  it("every tx: one input of ours, OP_RETURN + change, branch id from getblockchaininfo, ZIP-317 fee, expiry tip+40", async () => {
    const t = await setup({ autoMineMs: null });
    const tip = t.node.tip;
    const p = t.writer.registerInstance(await t.registerArgs());
    await waitFor(() => t.node.mempool.length === 4);
    for (const s of t.node.accepted) {
      expect(s.tx.consensusBranchId).toBe(BRANCH_ID);
      expect(s.tx.expiryHeight).toBe(tip + 40);
      expect(s.tx.vin).toHaveLength(1);
      expect(s.tx.vout).toHaveLength(2);
      expect(s.fee).toBe(zip317Fee({ inputs: 1, outputScripts: s.tx.vout.map((o) => o.script) }));
      expect(s.tx.vout[1]!.value).toBe(COIN - s.fee);
      expect(toHex(s.tx.vout[1]!.script)).toBe(t.node.utxos.get(s.spends[0]!)!.script); // change back to us
    }
    t.node.mine();
    await p;
  });

  it("never spends an input of a pending tx; waits for a coin when all are reserved", async () => {
    const t = await setup({ autoMineMs: null, coins: 2, random: () => 0 });
    const p = t.writer.registerInstance(await t.registerArgs()).catch((e: unknown) => e);
    await waitFor(() => t.node.mempool.length === 2);
    // Both coins are spent by pending txs: the writer must not pick them again (random() = 0 would).
    const spends = t.node.accepted.flatMap((s) => s.spends);
    expect(new Set(spends).size).toBe(2);
    expect(t.writer.reservedOutpoints.sort()).toEqual([...spends].sort());
    await new Promise((r) => setTimeout(r, 100));
    expect(t.node.accepted).toHaveLength(2);
    expect(t.node.rejected).toEqual([]);
    // Mining confirms the change outputs: the writer continues with them.
    t.node.mine();
    await waitFor(() => t.node.mempool.length === 2);
    t.node.mine();
    expect(await p).toBeUndefined();
    expect(t.node.accepted).toHaveLength(4);
    expect(new Set(t.node.accepted.flatMap((s) => s.spends)).size).toBe(4);
    expect(t.reader().getInstance(toHex(t.keys.keyHash))).not.toBeNull();
  });

  it("no spendable coin within the bound ⇒ E_REGISTRY_UNAVAILABLE (and coins below fee + min change are never used)", async () => {
    const t = await setup({ autoMineMs: null, coins: 0 });
    t.node.fund(h160Of(t.opSk), [20_000n, 25_000n]);
    const e = await t.writer.registerInstance(await t.registerArgs()).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(PlrError);
    expect((e as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
    expect(t.node.accepted).toHaveLength(0);
  });

  it("a coin taken by another process (same key) is skipped after the node rejects the conflict", async () => {
    const t = await setup({ autoMineMs: null, coins: 3, random: () => 0 });
    const other = new ZcashRegistryWriter({ rpc: t.node.url, network: "regtest", owner: t.owner, key: toHex(t.opSk), random: () => 0, pollMs: 5 });
    writers.push(other);
    const coins = await other.listUtxos();
    const first = other.selectCoin(coins, 0n)!;
    // Spend the coin the writer would choose first (lowest txid) from "another process".
    t.node.post(t.opSk, opReturnScript(encodeZcashRecord({ type: "allow_os", hash: "ab".repeat(32) })), `${first.txid}:${first.vout}`);
    expect(t.node.mempool[0]!.spends).toEqual([`${first.txid}:${first.vout}`]);
    const p = t.writer.registerInstance(await t.registerArgs()).catch((e: unknown) => e);
    await waitFor(() => t.node.rejected.length >= 1 && t.node.mempool.length === 3);
    expect(t.node.rejected).toContain("mempool conflict");
    t.node.autoMine(10);
    expect(await p).toBeUndefined();
  });

  it("re-registration posts nothing when all records are fresh; a due refresh re-posts only reg_quote (same hash)", async () => {
    const t = await setup();
    const args = await t.registerArgs();
    await t.writer.registerInstance(args);
    expect(t.node.accepted).toHaveLength(4);
    await t.writer.registerInstance(args);
    expect(t.node.accepted).toHaveLength(4);
    const refresher = new ZcashRegistryWriter({ rpc: t.node.url, network: "regtest", owner: t.owner, key: toHex(t.opSk), pollMs: 5, refreshAfterMs: 0 });
    writers.push(refresher);
    await refresher.registerInstance(args);
    expect(t.node.accepted).toHaveLength(5);
    expect(recordsOf([t.node.accepted[4]!])).toEqual([{ type: "reg_quote", key_hash: toHex(t.keys.keyHash), quote_sha256: toHex(sha256(fromHex(args.quote))) }]);
  });

  it("refuses a quote not bound to (contractId, own operator) — nothing is posted", async () => {
    const t = await setup({ autoMineMs: null });
    const e = await t.writer.registerInstance(await t.registerArgs(addrOf(newKey()))).catch((x: unknown) => x);
    expect((e as PlrError).code).toBe("E_REPORT_DATA");
    expect(t.node.accepted).toHaveLength(0);
  });

  it("records not confirmed in time ⇒ E_REGISTRY_UNAVAILABLE; the retry waits for the pending txs instead of re-posting", async () => {
    const t = await setup({ autoMineMs: null });
    const short = new ZcashRegistryWriter({ rpc: t.node.url, network: "regtest", owner: t.owner, key: toHex(t.opSk), pollMs: 5, confirmTimeoutMs: 50 });
    writers.push(short);
    const args = await t.registerArgs();
    expect(((await short.registerInstance(args).catch((x: unknown) => x)) as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
    expect(t.node.accepted).toHaveLength(4);
    t.node.mine();
    await short.registerInstance(args);
    expect(t.node.accepted).toHaveLength(4);
  });
});

describe("ZcashRegistryWriter: chain data is never trusted", () => {
  it("malformed RPC results fail closed with a PlrError", async () => {
    const t = await setup({ autoMineMs: null });
    for (const [m, v] of [["getblockcount", "x"], ["getblockhash", 7], ["getblock", { height: "1", tx: {} }], ["getblock", null]] as const) {
      const w = new ZcashRegistryWriter({ rpc: t.node.url, network: "regtest", owner: t.owner, key: toHex(t.opSk) });
      t.node.overrides = { [m]: () => v };
      const e = await w.anchorCount().catch((x: unknown) => x);
      expect(e, m).toBeInstanceOf(PlrError);
      expect((e as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
    }
    t.node.overrides = { getaddressutxos: () => [null, 1, { txid: "zz" }, { txid: "ab".repeat(32), outputIndex: 0, script: "00", satoshis: 1e8, height: 1 }] };
    expect(await t.writer.listUtxos()).toEqual([]);
    t.node.overrides = { getblockchaininfo: () => ({ consensus: {} }) };
    expect(((await t.writer.registerInstance(await t.registerArgs()).catch((x: unknown) => x)) as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
  });

  it("garbage transactions in blocks are skipped (records from strangers never count as ours)", async () => {
    const t = await setup();
    const stranger = newKey();
    t.node.fund(h160Of(stranger), [COIN]);
    const kh = toHex(t.keys.keyHash);
    t.node.post(stranger, opReturnScript(encodeZcashRecord({ type: "reg_measure", key_hash: kh, compose_hash: "00".repeat(32) })));
    // a coinbase carrying a record-looking OP_RETURN, and a record-shaped coinbase output: never records
    t.node.sealRaw([coinbaseRaw([]), coinbaseRaw([{ amount: 0n, script: opReturnScript(encodeZcashRecord({ type: "reg_measure", key_hash: kh, compose_hash: "00".repeat(32) })) }])]);
    await t.writer.registerInstance(await t.registerArgs());
    expect(t.reader().getInstance(kh)?.compose_hash).toBe(toHex(sha256(COMPOSE)));
  });

  it("rpc credentials in the URL become a basic-auth header", async () => {
    const t = await setup({ autoMineMs: null });
    const u = new URL(t.node.url);
    u.username = "user";
    u.password = "p@ss";
    await new ZebraRpc(u.toString()).call("getblockcount");
    expect(t.node.lastAuth).toBe(`Basic ${Buffer.from("user:p@ss").toString("base64")}`);
  });
});

describe("Anchorer on Zcash (registration, registration_quote, anchors)", () => {
  function anchorerFor(t: Awaited<ReturnType<typeof setup>>, receipts: ReceiptLog) {
    const lines: string[] = [];
    let quotes = 0;
    const attester = { getQuote: (rd: Uint8Array) => { quotes++; return t.attester.getQuote(rd); } };
    const anchorer = new Anchorer({ chain: t.writer, attester, keys: t.keys, receipts, composeBytes: COMPOSE, log: new Logger("plr-router", (l) => lines.push(l)), intervalMs: 50 });
    return { anchorer, lines, quotes: () => quotes };
  }
  const issue = (t: Awaited<ReturnType<typeof setup>>, receipts: ReceiptLog, n: number) => {
    const out: Receipt[] = [];
    for (let i = 0; i < n; i++) {
      out.push(receipts.issue({ th: randomBytes(32), reqHash: randomBytes(32), respHash: randomBytes(32), composeHash: sha256(COMPOSE), keyHash: t.keys.keyHash, sign: (r) => t.keys.signReceipt(r), nowMs: Date.now() }).receipt);
    }
    return out;
  };

  it("registers, serves the registration quote, refreshes with the same quote, anchors with a verifiable anchor_sig", async () => {
    const t = await setup();
    const receipts = new ReceiptLog();
    const a = anchorerFor(t, receipts);
    expect(a.anchorer.registrationQuote).toBeNull();
    expect(await a.anchorer.register()).toBe(true);
    const rq = a.anchorer.registrationQuote!;
    const kh = toHex(t.keys.keyHash);
    expect(toHex(sha256(rq))).toBe(t.reader().registrationQuoteHash(kh));
    expect(toHex(parseQuote(rq).report.reportData)).toBe(toHex(registrationReportData(t.keys.x25519, t.keys.ed25519, t.writer.contractId, t.writer.operatorId)));
    expect(await a.anchorer.register()).toBe(true); // refresh
    expect(a.quotes()).toBe(1);
    expect(toHex(a.anchorer.registrationQuote!)).toBe(toHex(rq));

    issue(t, receipts, 3);
    await a.anchorer.anchorOnce();
    expect(receipts.anchoredCount).toBe(3);
    const log = t.reader();
    expect(log.anchorCount()).toBe(1);
    const an = log.getAnchor(0)!;
    expect([an.key_hash, an.first_seq, an.count]).toEqual([kh, 0, 3]);
    const msg = anchorMessage({ contractId: t.writer.contractId, keyHash: t.keys.keyHash, root: fromHex(an.root, 32), firstSeq: 0n, count: 3n });
    expect(ed25519.verify(fromHex(an.sig!, 64), msg, t.keys.ed25519)).toBe(true);
    expect(log.getInstance(kh)!.next_seq).toBe(3);
    // anchor then anchor_sig, in separate (consecutive) blocks
    const types = recordsOf(t.node.accepted).map((r) => r.type);
    expect(types.slice(-2)).toEqual(["anchor", "anchor_sig"]);

    issue(t, receipts, 2);
    await a.anchorer.anchorOnce();
    expect(receipts.anchoredCount).toBe(5);
    expect(t.reader().getAnchor(1)!.first_seq).toBe(3);
    expect(a.lines.filter((l) => l.includes("anchor_failed"))).toEqual([]);
  });

  it("an unapproved operator: registration records land but no instance is visible; anchoring reports not registered", async () => {
    const t = await setup({ approve: false });
    const receipts = new ReceiptLog();
    const a = anchorerFor(t, receipts);
    expect(await a.anchorer.register()).toBe(true);
    expect(t.reader().getInstance(toHex(t.keys.keyHash))).toBeNull();
    issue(t, receipts, 1);
    const e = await t.writer.anchorReceipts({ key_hash: toHex(t.keys.keyHash), root: "00".repeat(32), first_seq: 0, count: 1, sig: "00".repeat(64) }).catch((x: unknown) => x);
    expect((e as PlrError).code).toBe("E_INSTANCE_NOT_REGISTERED");
  });

  it("anchor args are checked locally: wrong first_seq ⇒ E_SEQ, bad signature ⇒ E_ANCHOR_SIG, nothing posted", async () => {
    const t = await setup();
    await t.writer.registerInstance(await t.registerArgs());
    const n = t.node.accepted.length;
    const kh = toHex(t.keys.keyHash);
    const root = toHex(randomBytes(32));
    const sig = toHex(t.keys.sign(anchorMessage({ contractId: t.writer.contractId, keyHash: t.keys.keyHash, root: fromHex(root, 32), firstSeq: 0n, count: 1n })));
    expect(((await t.writer.anchorReceipts({ key_hash: kh, root, first_seq: 1, count: 1, sig }).catch((x: unknown) => x)) as PlrError).code).toBe("E_SEQ");
    expect(((await t.writer.anchorReceipts({ key_hash: kh, root, first_seq: 0, count: 2, sig }).catch((x: unknown) => x)) as PlrError).code).toBe("E_ANCHOR_SIG");
    expect(t.node.accepted).toHaveLength(n);
    expect(await t.writer.anchorReceipts({ key_hash: kh, root, first_seq: 0, count: 1, sig })).toBe(0);
  });
});

describe("/v1/attestation registration_quote (SPEC-CHAINS §4)", () => {
  it("absent before registration, the registration quote (hex) after", async () => {
    const root = MockRoot.generate();
    const attester = new MockTdxAttester({ root, composeBytes: COMPOSE });
    const keys = RouterKeys.generate();
    let rq: Uint8Array | null = null;
    const server = createRouter({ attester, keys, composeBytes: COMPOSE, llm: new HttpLlmClient(1), receipts: new ReceiptLog(), log: new Logger("plr-router", () => undefined), registrationQuote: () => rq });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", () => ok()));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const get = async () => (await (await fetch(`${url}/v1/attestation?nonce=${toHex(randomBytes(32))}`)).json()) as Record<string, unknown>;
      expect("registration_quote" in (await get())).toBe(false);
      rq = (await attester.getQuote(keys.registrationReportData("zcash:regtest:x", "op"))).quote;
      expect((await get()).registration_quote).toBe(toHex(rq));
      rq = new Uint8Array(3); // malformed provider output is never served
      expect("registration_quote" in (await get())).toBe(false);
    } finally {
      await closeServer(server);
    }
  });
});

const closeServer = (s: http.Server) => new Promise<void>((ok) => { s.close(() => ok()); s.closeAllConnections(); });

async function waitFor(pred: () => boolean, ms = 5_000): Promise<void> {
  const end = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("PLR_CHAIN config and host env (SPEC-CHAINS §4, §5)", () => {
  const base = { PLR_TDX_SOCKET: "/tmp/q.sock", PLR_APP_COMPOSE_PATH: "/tmp/c.json" };
  const owner = addrOf(newKey());
  const vpnOwner = addrOf(newKey());
  const z = { PLR_CHAIN: "zcash", PLR_ZCASH_RPC: "http://127.0.0.1:18232", PLR_ZCASH_NETWORK: "regtest", PLR_ZCASH_OWNER: owner, PLR_ZCASH_KEY: "11".repeat(32) };

  it("default near; zcash selects the Zcash writer with contractId zcash:<network>:<owner>", () => {
    expect(loadConfig(base).registry).toBeNull();
    const c = loadConfig({ ...base, ...z, PLR_ZCASH_START_HEIGHT: "5" });
    expect([c.nearConfigError, c.near, c.registry?.chain]).toEqual([false, null, "zcash"]);
    if (c.registry?.chain !== "zcash") throw new Error("unreachable");
    expect(c.registry.zcash.startHeight).toBe(5);
    const w = createRegistryWriter(c.registry);
    expect(w).toBeInstanceOf(ZcashRegistryWriter);
    expect(w.contractId).toBe(`zcash:regtest:${owner}`);
    const near = loadConfig({ ...base, PLR_NEAR_RPC: "http://127.0.0.1:3030", PLR_REGISTRY: "registry.test.near", PLR_OPERATOR_ID: "op.test.near", PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64) });
    expect(near.registry?.chain).toBe("near");
    expect(createRegistryWriter(near.registry!)).toBeInstanceOf(NearRegistryWriter);
  });

  it("invalid, partial or unsupported chain settings disable registration (fail closed)", () => {
    for (const bad of [
      { PLR_CHAIN: "dogecoin" }, { PLR_CHAIN: "evm", PLR_EVM_RPC: "http://127.0.0.1:8545" }, { ...z, PLR_ZCASH_KEY: "" }, { ...z, PLR_ZCASH_NETWORK: "mainnet" },
      { ...z, PLR_ZCASH_OWNER: "t1notanaddress" }, { ...z, PLR_ZCASH_RPC: "file:///etc/passwd" }, { ...z, PLR_ZCASH_KEY: "zz" },
      { ...z, PLR_ZCASH_START_HEIGHT: "-1" },
    ]) {
      const c = loadConfig({ ...base, ...bad });
      expect([c.registry, c.near, c.nearConfigError], JSON.stringify(bad)).toEqual([null, null, true]);
    }
  });

  it("the exit registers on PLR_ZCASH_VPN_OWNER, else PLR_ZCASH_OWNER", () => {
    const a = loadExitConfig({ ...base, ...z });
    const b = loadExitConfig({ ...base, ...z, PLR_ZCASH_VPN_OWNER: vpnOwner });
    expect(a.registry?.chain === "zcash" && a.registry.zcash.owner).toBe(owner);
    expect(b.registry?.chain === "zcash" && b.registry.zcash.owner).toBe(vpnOwner);
  });

  it("host allowlists forward PLR_CHAIN and PLR_ZCASH_*; a combo exit never gets the LLM registry owner", () => {
    for (const k of ["PLR_CHAIN", "PLR_ZCASH_RPC", "PLR_ZCASH_NETWORK", "PLR_ZCASH_OWNER", "PLR_ZCASH_KEY", "PLR_ZCASH_START_HEIGHT"]) {
      expect(ROUTER_ENV_ALLOWLIST).toContain(k);
      expect(EXIT_ENV_ALLOWLIST).toContain(k);
      expect(COMBO_ROUTER_ENV_ALLOWLIST).toContain(k);
    }
    expect(EXIT_ENV_ALLOWLIST).toContain("PLR_ZCASH_VPN_OWNER");
    expect(ROUTER_ENV_ALLOWLIST).not.toContain("PLR_ZCASH_VPN_OWNER" as never);
    expect(COMBO_EXIT_ENV_ALLOWLIST).not.toContain("PLR_ZCASH_OWNER" as never);
    const envs = comboProcessEnvs({
      hostEnv: { ...z, PLR_ZCASH_VPN_OWNER: vpnOwner }, nodeEnv: {}, socketPath: "/s", routerComposePath: "/r", vpnComposePath: "/v", routerPort: 1, llmPort: 2, llmApiKey: "k", runDir: "/d",
    });
    expect([envs.router.PLR_ZCASH_OWNER, envs.router.PLR_ZCASH_VPN_OWNER]).toEqual([owner, undefined]);
    expect([envs.exit.PLR_ZCASH_OWNER, envs.exit.PLR_ZCASH_VPN_OWNER, envs.exit.PLR_CHAIN]).toEqual([undefined, vpnOwner, "zcash"]);
  });
});

// ------------------------------------------------------------------------------------------------- review fixes

describe("review fixes: Zcash writer", () => {
  const anchorArgs = (t: Awaited<ReturnType<typeof setup>>, root: string, count: number, firstSeq = 0) => ({
    key_hash: toHex(t.keys.keyHash), root, first_seq: firstSeq, count,
    sig: toHex(t.keys.sign(anchorMessage({ contractId: t.writer.contractId, keyHash: t.keys.keyHash, root: fromHex(root, 32), firstSeq: BigInt(firstSeq), count: BigInt(count) }))),
  });
  const kinds = (t: Awaited<ReturnType<typeof setup>>) => recordsOf(t.node.accepted).map((r) => r.type);

  it("a timed-out anchor is finished, never raced by a new anchor for the same first_seq; its anchor_sig expires inside the window", async () => {
    const t = await setup();
    await t.writer.registerInstance(await t.registerArgs());
    t.node.stopMining();
    const short = new ZcashRegistryWriter({ rpc: t.node.url, network: "regtest", owner: t.owner, key: toHex(t.opSk), pollMs: 5, confirmTimeoutMs: 60 });
    writers.push(short);
    t.node.accepted.splice(0);
    const e1 = await short.anchorReceipts(anchorArgs(t, "a1".repeat(32), 5)).catch((x: unknown) => x);
    expect((e1 as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
    expect(kinds(t)).toEqual(["anchor"]);
    // The next interval has more receipts: while A1 can still be mined, nothing new is posted.
    const e2 = await short.anchorReceipts(anchorArgs(t, "a2".repeat(32), 8)).catch((x: unknown) => x);
    expect((e2 as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
    expect(kinds(t)).toEqual(["anchor"]);
    t.node.autoMine(10);
    expect(await short.anchorReceipts(anchorArgs(t, "a2".repeat(32), 8))).toBeNull(); // finished A1; caller resyncs
    expect(kinds(t)).toEqual(["anchor", "anchor_sig"]);
    const a = short.log.getAnchor(0)!;
    expect(a).toMatchObject({ root: "a1".repeat(32), count: 5, first_seq: 0 });
    const msg = anchorMessage({ contractId: t.writer.contractId, keyHash: t.keys.keyHash, root: fromHex(a.root, 32), firstSeq: 0n, count: 5n });
    expect(ed25519.verify(fromHex(a.sig!, 64), msg, t.keys.ed25519)).toBe(true);
    const anchorTx = t.node.accepted[0]!;
    const minedAt = t.node.blocks.find((b) => b.tx.some((x) => x.txid === anchorTx.txid))!.height;
    expect(t.node.accepted[1]!.tx.expiryHeight).toBeLessThanOrEqual(minedAt + 10);
    // and the next batch continues from next_seq = 5
    expect(await short.anchorReceipts(anchorArgs(t, "a3".repeat(32), 3, 5))).toBe(1);
  });

  it("an approved rival copying our public registration records first is the §5 instance: we see the mismatch and never anchor", async () => {
    const t = await setup();
    const rivalSk = newKey();
    t.node.fund(h160Of(rivalSk), Array.from({ length: 6 }, () => COIN));
    t.node.post(t.ownerSk, opReturnScript(encodeZcashRecord({ type: "approve_operator", hash160: toHex(h160Of(rivalSk)), org_id: "rival" })));
    t.node.mine();
    const args = await t.registerArgs();
    const kh = toHex(t.keys.keyHash);
    for (const r of [
      { type: "reg_keys", x25519: args.x25519, ed25519: args.ed25519 },
      { type: "reg_measure", key_hash: kh, compose_hash: toHex(sha256(COMPOSE)) },
      { type: "reg_os", key_hash: kh, os_measurement: toHex(osMeasurement(parseQuote(fromHex(args.quote)).report)) },
      { type: "reg_quote", key_hash: kh, quote_sha256: "77".repeat(32) },
    ] as ZcashRecord[]) t.node.post(rivalSk, opReturnScript(encodeZcashRecord(r)));
    t.node.mine();
    await t.writer.registerInstance(args);
    expect(t.reader().getInstance(kh)!.operator).toBe(addrOf(rivalSk)); // SPEC-CHAINS §5 "earliest"
    expect(await t.writer.getInstanceOperator(kh)).toBe(addrOf(rivalSk)); // the writer reads exactly what clients read
    const n = t.node.accepted.length;
    const e = await t.writer.anchorReceipts(anchorArgs(t, "aa".repeat(32), 2)).catch((x: unknown) => x);
    expect((e as PlrError).code).toBe("E_INSTANCE_NOT_REGISTERED"); // readers would ignore our anchor: nothing posted
    expect(t.node.accepted.length).toBe(n);
  });

  it("ZebraRpc bounds chunked replies (no content-length) while streaming", async () => {
    const { createServer } = await import("node:http");
    const srv: http.Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write(`{"jsonrpc":"2.0","id":1,"result":"${"ab".repeat(1000)}`);
      res.end(`${"cd".repeat(1000)}"}`);
    });
    await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", () => ok()));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      const e = await new ZebraRpc(url, { maxResponseBytes: 3000 }).call("getblock", ["00", 0]).catch((x: unknown) => x);
      expect((e as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
      expect(typeof (await new ZebraRpc(url, { maxResponseBytes: 10_000 }).call("getblock", ["00", 0]))).toBe("string");
    } finally {
      srv.closeAllConnections();
      await new Promise<void>((ok) => srv.close(() => ok()));
    }
  });
});
