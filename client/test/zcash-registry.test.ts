// ZcashRegistry (SPEC-CHAINS §5 tier C) over a fake Zebra JSON-RPC, the rev 1.4 registration-evidence rule and
// anchor signatures in the client (SPEC-CHAINS §2), and PLR_CHAIN=zcash in the CLI.
import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import {
  CHECKS,
  MemoryRegistry,
  MockRoot,
  MockTdxAttester,
  PlrError,
  REGISTRATION_EVIDENCE_CHECK,
  anchorMessage,
  encodeZcashRecord,
  fromHex,
  opReturnScript,
  p2pkhScript,
  zcashTxidFromRpc,
  keyHash,
  merkleProof,
  merkleRoot,
  mockOsReport,
  osMeasurement,
  receiptLeaf,
  registrationReportData,
  reportData,
  toHex,
  type AnchorRecord,
  type AttestationBundle,
  type Receipt,
  type RegistryReader,
} from "@plr/shared";
import {
  NearRegistry,
  PrivateClient,
  ZcashRegistry,
  checkLines,
  loadConfig,
  loadVpnConfig,
  parseZcashContractId,
  registryTier,
  runCli,
  verifyReceiptAnchored,
} from "../src/index.js";
import { COMPOSE } from "./fake-router.js";
import { coinbaseTx, p2pkhScriptSig, party, rawTx, recordTx, startFakeZebra, type FakeZebra, type Party } from "./fake-zebra.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof PlrError) return e.code;
    return `ERR:${(e as Error).name}`;
  }
  return "NO_THROW";
}

async function zebra(): Promise<FakeZebra> {
  const z = await startFakeZebra();
  closers.push(z.close);
  return z;
}

const owner = party();
const op = party();
const op2 = party();
const stranger = party();
const CONTRACT = `zcash:regtest:${owner.addr}`;
const h32 = (b: number) => b.toString(16).padStart(2, "0").repeat(32);
const reader = (z: FakeZebra, o: Partial<ConstructorParameters<typeof ZcashRegistry>[0]> = {}) =>
  new ZcashRegistry({ rpcUrl: z.url, network: "regtest", owner: owner.addr, cacheMs: 0, ...o });

/** A TD instance (router) with keys, a session-quote attester and its registration quote for `operator`. */
async function instance(operator: Party = op) {
  const root = MockRoot.generate();
  const composeBytes = new TextEncoder().encode(COMPOSE);
  const attester = new MockTdxAttester({ root, composeBytes, debug: false });
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  const kh = toHex(keyHash(xp, ep));
  const composeHash = toHex(sha256(composeBytes));
  const osHash = toHex(osMeasurement(mockOsReport()));
  const regQuote = (await attester.getQuote(registrationReportData(xp, ep, CONTRACT, operator.addr))).quote;
  return { root, attester, xp, ep, es, kh, composeHash, osHash, regQuote };
}
type Inst = Awaited<ReturnType<typeof instance>>;

/** Owner policy for `inst` + the operator's complete registration, in one block each (like a real writer). */
function publish(z: FakeZebra, inst: Inst, o: { operator?: Party; quoteSha?: string; approve?: boolean } = {}) {
  const operator = o.operator ?? op;
  z.mine([
    coinbaseTx(),
    recordTx(owner, { type: "set_root", kind: "MOCK", p256: toHex(inst.root.publicKey) }),
    recordTx(owner, { type: "allow_compose", hash: inst.composeHash }),
    recordTx(owner, { type: "allow_os", hash: inst.osHash }),
  ]);
  if (o.approve !== false) z.mine([recordTx(owner, { type: "approve_operator", hash160: operator.h160, org_id: "org-a" })]);
  z.mine([
    recordTx(operator, { type: "reg_keys", x25519: toHex(inst.xp), ed25519: toHex(inst.ep) }),
    recordTx(operator, { type: "reg_measure", key_hash: inst.kh, compose_hash: inst.composeHash }),
    recordTx(operator, { type: "reg_os", key_hash: inst.kh, os_measurement: inst.osHash }),
  ]);
  z.mine([recordTx(operator, { type: "reg_quote", key_hash: inst.kh, quote_sha256: o.quoteSha ?? toHex(sha256(inst.regQuote)) })]);
}

describe("ZcashRegistry — construction", () => {
  it("is a tier-C reader with the SPEC-CHAINS §3 contract id", async () => {
    const z = await zebra();
    const r = reader(z);
    expect(r.chain).toBe("zcash");
    expect(r.verifiesOnChain).toBe(false);
    expect(r.contractId).toBe(CONTRACT);
    expect(registryTier(r)).toBe("C");
    expect(parseZcashContractId(CONTRACT)).toEqual({ network: "regtest", owner: owner.addr });
    expect(parseZcashContractId(`zcash:mainnet:${owner.addr}`)).toBeNull(); // a test address on mainnet
    expect(parseZcashContractId(`evm:1:0x${"00".repeat(20)}`)).toBeNull();
  });

  it("validates options like NearRegistry (https, or http to loopback only; no credentials)", () => {
    const base = { network: "regtest" as const, owner: owner.addr };
    const bad = (o: Record<string, unknown>) => {
      try {
        new ZcashRegistry({ ...base, rpcUrl: "http://127.0.0.1:1", ...o } as never);
        return "NO_THROW";
      } catch (e) {
        return (e as PlrError).code;
      }
    };
    expect(bad({ rpcUrl: "http://zebra.example.com:8232" })).toBe("E_BAD_INPUT");
    expect(bad({ rpcUrl: "http://u:p@127.0.0.1:1" })).toBe("E_BAD_INPUT");
    expect(bad({ rpcUrl: "ftp://127.0.0.1" })).toBe("E_BAD_INPUT");
    expect(bad({ network: "main" })).toBe("E_BAD_INPUT");
    expect(bad({ network: "mainnet" })).toBe("E_BAD_INPUT"); // owner is a test-network address
    expect(bad({ owner: "tmNotAnAddress" })).toBe("E_BAD_INPUT");
    expect(bad({ startHeight: -1 })).toBe("E_BAD_INPUT");
    expect(bad({ timeoutMs: 0 })).toBe("E_BAD_INPUT");
    expect(bad({ minConfirmations: 0 })).toBe("E_BAD_INPUT");
    expect(bad({})).toBe("NO_THROW");
    expect(bad({ rpcUrl: "https://zebra.example.com" })).toBe("NO_THROW");
  });

  it("NearRegistry is tier A: verifiesOnChain, no registration quote to return", async () => {
    const n = new NearRegistry({ rpcUrl: "http://127.0.0.1:1", contractId: "registry.test.near" });
    expect(n.verifiesOnChain).toBe(true);
    expect(registryTier(n)).toBe("A");
    expect(await n.getRegistrationQuote("ab".repeat(32), new Uint8Array([1]))).toBeNull();
  });
});

describe("ZcashRegistry — reading the record log", () => {
  it("reflects owner policy, ignores strangers, and catches up with new blocks on each query", async () => {
    const z = await zebra();
    const r = reader(z);
    expect(await r.isComposeAllowed(h32(1))).toBe(false);
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(1) }), recordTx(stranger, { type: "allow_compose", hash: h32(2) })]);
    expect(await r.isComposeAllowed(h32(1))).toBe(true);
    expect(await r.isComposeAllowed(h32(2))).toBe(false);
    z.mine([recordTx(owner, { type: "revoke_compose", hash: h32(1) }), recordTx(owner, { type: "allow_os", hash: h32(3) })]);
    expect(await r.isComposeAllowed(h32(1))).toBe(false);
    expect(await r.isOsAllowed(h32(3))).toBe(true);
    expect(r.height).toBe(2);
    // malformed hashes are never allowed and never reach the node
    const before = z.calls.length;
    expect(await r.isComposeAllowed("AB".repeat(32))).toBe(false);
    expect(await r.getInstance("zz")).toBeNull();
    expect(await r.getAnchor(-1)).toBeNull();
    expect(z.calls.length).toBe(before);
  });

  it("getInstance: complete registration by a currently approved operator only", async () => {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst, { approve: false });
    const r = reader(z);
    expect(await r.getInstance(inst.kh)).toBeNull(); // operator not approved
    z.mine([recordTx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })]);
    const rec = await r.getInstance(inst.kh);
    expect(rec).toMatchObject({ operator: op.addr, org_id: "org-a", compose_hash: inst.composeHash, os_measurement: inst.osHash, next_seq: 0 });
    expect(rec!.expires_at_ms - rec!.registered_at_ms).toBe(86_400_000);
    expect(await r.getOperator(op.addr)).toBe("org-a");
    z.mine([recordTx(owner, { type: "revoke_operator", hash160: op.h160 })]);
    expect(await r.getInstance(inst.kh)).toBeNull();
  });

  it("rebases chain times to the local clock (regtest blocks carry 2011 timestamps), expiry decided in chain time", async () => {
    const z = await zebra();
    const inst = await instance();
    const T = 1_296_688_604; // what Zebra regtest really reports
    z.mine([recordTx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" })], T);
    z.mine([
      recordTx(op, { type: "reg_keys", x25519: toHex(inst.xp), ed25519: toHex(inst.ep) }),
      recordTx(op, { type: "reg_measure", key_hash: inst.kh, compose_hash: inst.composeHash }),
      recordTx(op, { type: "reg_os", key_hash: inst.kh, os_measurement: inst.osHash }),
      recordTx(op, { type: "reg_quote", key_hash: inst.kh, quote_sha256: h32(5) }),
    ], T + 2);
    z.mine([], T + 600); // 10 chain minutes later
    let now = 5_000_000_000_000;
    const r = reader(z, { now: () => now });
    const rec = (await r.getInstance(inst.kh))!;
    expect(rec.registered_at_ms).toBe(now - 598_000);
    expect(rec.expires_at_ms).toBe(now - 598_000 + 86_400_000);
    now += 1000;
    expect((await r.getInstance(inst.kh))!.expires_at_ms).toBe(now - 598_000 + 86_400_000);
    z.mine([], T + 2 + 86_400); // chain time passes the expiry
    expect(await r.getInstance(inst.kh)).toBeNull();
  });

  it("getRoot rejects until the owner sets one (fail closed)", async () => {
    const z = await zebra();
    const r = reader(z);
    expect(await code(r.getRoot())).toBe("ERR:ZcashRegistryError");
    z.mine([recordTx(owner, { type: "set_root", kind: "MOCK", p256: "11".repeat(64) })]);
    expect(await r.getRoot()).toEqual({ kind: "MOCK", p256: "11".repeat(64) });
  });

  it("getRegistrationQuote returns `offered` only if it matches the on-chain SHA-256 commitment", async () => {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst);
    const r = reader(z);
    const got = await r.getRegistrationQuote(inst.kh, inst.regQuote);
    expect(got).toEqual(inst.regQuote);
    expect(got).not.toBe(inst.regQuote); // a copy
    const tampered = inst.regQuote.slice();
    tampered[100]! ^= 1;
    expect(await r.getRegistrationQuote(inst.kh, tampered)).toBeNull();
    expect(await r.getRegistrationQuote(inst.kh)).toBeNull();
    expect(await r.getRegistrationQuote(inst.kh, new Uint8Array())).toBeNull();
    expect(await r.getRegistrationQuote("ee".repeat(32), inst.regQuote)).toBeNull();
    // the commitment is plain SHA-256 of the quote bytes
    expect(toHex(sha256(inst.regQuote))).toBe(createHash("sha256").update(inst.regQuote).digest("hex"));
  });

  it("skips malformed transactions and records without failing the query", async () => {
    const z = await zebra();
    const payload = (r: Parameters<typeof encodeZcashRecord>[0]) => opReturnScript(encodeZcashRecord(r));
    const fund = coinbaseTx([p2pkhScript(fromHex(owner.h160, 20))]);
    const spend = (scriptSig: Uint8Array, vout: { script: Uint8Array }[]) => rawTx([{ prev: zcashTxidFromRpc(fund.txid), index: 0, scriptSig }], vout);
    z.mine([
      spend(new Uint8Array([0x51]), [{ script: payload({ type: "allow_compose", hash: h32(8) }) }]),                    // not <sig> <pubkey>
      spend(p2pkhScriptSig(owner.pub), [{ script: payload({ type: "allow_compose", hash: h32(8) }) }, { script: payload({ type: "allow_os", hash: h32(8) }) }]), // two OP_RETURNs
      spend(p2pkhScriptSig(owner.pub), [{ script: opReturnScript(new Uint8Array([0x50, 0x4c, 0x52, 0x31])) }]),          // truncated record
      spend(p2pkhScriptSig(owner.pub), [{ script: new Uint8Array([0x6a, 0x4c]) }]),                                    // broken push
      recordTx(owner, { type: "allow_compose", hash: h32(7) }),
    ]);
    const r = reader(z);
    expect(await r.isComposeAllowed(h32(7))).toBe(true);
    expect(await r.isComposeAllowed(h32(8))).toBe(false);
    expect(await r.isOsAllowed(h32(8))).toBe(false);
  });

  it("anchors: contiguous, signed via 0x21 (Ed25519-checked by the strict reader), exposed with their sig", async () => {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst);
    const good = toHex(ed25519.sign(anchorMessage({ contractId: CONTRACT, keyHash: fromHex(inst.kh, 32), root: fromHex(h32(9), 32), firstSeq: 0n, count: 2n }), inst.es));
    z.mine([recordTx(op, { type: "anchor", key_hash: inst.kh, root: h32(9), first_seq: 0, count: 2 })]);
    z.mine([recordTx(op, { type: "anchor_sig", key_prefix: inst.kh.slice(0, 16), sig: "cd".repeat(64) })]); // not a valid signature: ignored
    z.mine([recordTx(op, { type: "anchor_sig", key_prefix: inst.kh.slice(0, 16), sig: good })]);
    const r = reader(z);
    expect(await r.anchorCount()).toBe(1);
    expect(await r.getAnchor(0)).toMatchObject({ id: 0, key_hash: inst.kh, root: h32(9), first_seq: 0, count: 2, sig: good });
    expect(await r.getAnchor(1)).toBeNull();
    expect((await r.getInstance(inst.kh))!.next_seq).toBe(2);
  });
});

describe("ZcashRegistry — bounded, cached, fail-closed catch-up", () => {
  it("RPC errors, HTTP errors, malformed replies and timeouts reject (never stale answers)", async () => {
    const z = await zebra();
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(1) })]);
    const r = reader(z, { timeoutMs: 300 });
    expect(await r.isComposeAllowed(h32(1))).toBe(true);
    z.mine([recordTx(owner, { type: "revoke_compose", hash: h32(1) })]);
    const cases: ((m: string) => ReturnType<NonNullable<FakeZebra["override"]>>)[] = [
      (m) => (m === "getblockcount" ? { status: 200, body: { jsonrpc: "2.0", id: 0, error: { code: -1, message: "x" } } } : undefined),
      (m) => (m === "getblockcount" ? { status: 500, body: { jsonrpc: "2.0", id: 0, result: 2 } } : undefined),
      (m) => (m === "getblockcount" ? { status: 200, body: "not json-rpc" } : undefined),
      (m) => (m === "getblockcount" ? { status: 200, body: { jsonrpc: "2.0", id: 999_999, result: 2 } } : undefined), // wrong id
      (m) => (m === "getblockcount" ? "hang" : undefined),
      (m) => (m === "getblockhash" ? { status: 200, body: { jsonrpc: "2.0", id: 0, result: "XYZ" } } : undefined),
    ];
    for (const c of cases) {
      z.override = (m) => c(m);
      expect(await code(r.isComposeAllowed(h32(1)))).toBe("ERR:ZcashRegistryError");
    }
    // getblock answering another block / a malformed block
    z.override = (m, p) => (m === "getblock" ? { status: 200, body: { jsonrpc: "2.0", id: 0, result: { hash: p[0], height: 99, time: 1, tx: [] } } } : undefined);
    expect(await code(r.isComposeAllowed(h32(1)))).toBe("ERR:ZcashRegistryError");
    z.override = undefined;
    expect(await r.isComposeAllowed(h32(1))).toBe(false);
  });

  it("rejects when a catch-up exceeds its block budget, keeping progress for the next query", async () => {
    const z = await zebra();
    for (let i = 0; i < 25; i++) z.mine([recordTx(owner, { type: "allow_os", hash: h32(i + 1) })]);
    const r = reader(z, { maxBlocksPerSync: 10 });
    expect(await code(r.isOsAllowed(h32(25)))).toBe("ERR:ZcashRegistryError");
    expect(r.height).toBe(9); // genesis (0) .. 9
    expect(await code(r.isOsAllowed(h32(25)))).toBe("ERR:ZcashRegistryError");
    expect(await r.isOsAllowed(h32(25))).toBe(true);
  });

  it("concurrent queries share one catch-up; cacheMs reuses it", async () => {
    const z = await zebra();
    z.mine([recordTx(owner, { type: "allow_os", hash: h32(1) })]);
    let t = 0;
    const r = reader(z, { cacheMs: 1000, now: () => t });
    await Promise.all([r.isOsAllowed(h32(1)), r.isComposeAllowed(h32(1)), r.getInstance(h32(2)), r.anchorCount()]);
    expect(z.calls.filter((c) => c.method === "getblockcount").length).toBe(1);
    t = 500;
    await r.isOsAllowed(h32(1));
    expect(z.calls.filter((c) => c.method === "getblockcount").length).toBe(1);
    t = 1500;
    await r.isOsAllowed(h32(1));
    expect(z.calls.filter((c) => c.method === "getblockcount").length).toBe(2);
  });

  it("starts at startHeight and applies only blocks with minConfirmations", async () => {
    const z = await zebra();
    z.mine([recordTx(owner, { type: "allow_os", hash: h32(1) })]); // height 1: before the start
    z.mine([recordTx(owner, { type: "allow_os", hash: h32(2) })]); // height 2
    const r = reader(z, { startHeight: 2, minConfirmations: 2 });
    expect(await r.isOsAllowed(h32(2))).toBe(false); // 1 confirmation only
    z.mine();
    expect(await r.isOsAllowed(h32(2))).toBe(true);
    expect(await r.isOsAllowed(h32(1))).toBe(false);
    expect(z.calls.some((c) => c.method === "getblockhash" && c.params[0] === 1)).toBe(false);
  });

  it("rebuilds the log after a reorg replaced applied blocks", async () => {
    const z = await zebra();
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(1) })]);
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(2) })]);
    const r = reader(z);
    expect(await r.isComposeAllowed(h32(2))).toBe(true);
    z.truncate(1);
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(3) })]);
    expect(await r.isComposeAllowed(h32(2))).toBe(false);
    expect(await r.isComposeAllowed(h32(3))).toBe(true);
    expect(await r.isComposeAllowed(h32(1))).toBe(true);
    // a chain shorter than what was applied is also handled
    z.truncate(0);
    expect(await r.isComposeAllowed(h32(1))).toBe(false);
  });
});

// ---------------------------------------------------------------- client: registration evidence + anchor sigs

type QuoteMode = "ok" | "absent" | "malformed" | "tampered";

/** Minimal router: `/v1/attestation` (with `registration_quote`) and `/v1/receipts/proof` for a 3-receipt batch. */
function routerFor(inst: Inst, o: { quote?: QuoteMode } = {}) {
  const receipts: Receipt[] = [0, 1, 2].map((seq) => ({
    v: 1,
    th: h32(0x10 + seq),
    req_hash: h32(0x20 + seq),
    resp_hash: h32(0x30 + seq),
    compose_hash: inst.composeHash,
    key_hash: inst.kh,
    seq,
    ts_ms: 1_700_000_000_000 + seq,
  }));
  const leaves = receipts.map(receiptLeaf);
  const root = toHex(merkleRoot(leaves));
  const state = { quote: o.quote ?? ("ok" as QuoteMode) };
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const handle = async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    if (url.pathname === "/v1/attestation") {
      const nonce = fromHex(url.searchParams.get("nonce") ?? "", 32);
      const { quote, eventLog } = await inst.attester.getQuote(reportData(inst.xp, inst.ep, nonce));
      const b: AttestationBundle = { v: "PLR-v1", root_kind: "MOCK", quote: toHex(quote), event_log: eventLog, app_compose: COMPOSE, x25519: toHex(inst.xp), ed25519: toHex(inst.ep) };
      if (state.quote === "ok") b.registration_quote = toHex(inst.regQuote);
      if (state.quote === "malformed") b.registration_quote = "XYZ";
      if (state.quote === "tampered") {
        const t = inst.regQuote.slice();
        t[200]! ^= 1;
        b.registration_quote = toHex(t);
      }
      return json(200, b);
    }
    if (url.pathname === "/v1/receipts/proof") {
      const seq = Number(url.searchParams.get("seq"));
      return json(200, { anchor_id: 0, first_seq: 0, count: 3, index: seq, root, proof: merkleProof(leaves, seq).map(toHex) });
    }
    return json(404, { error: "E_NOT_FOUND" });
  };
  const signAnchor = (contractId = CONTRACT, key = inst.es) =>
    toHex(ed25519.sign(anchorMessage({ contractId, keyHash: fromHex(inst.kh, 32), root: fromHex(root, 32), firstSeq: 0n, count: 3n }), key));
  return { receipts, root, state, handle, fetch: ((i: RequestInfo | URL, init?: RequestInit) => handle(new Request(i, init))) as typeof fetch, signAnchor };
}

async function listen(handle: (r: Request) => Promise<Response>): Promise<string> {
  const server: Server = createServer((req, res) => {
    void (async () => {
      const resp = await handle(new Request(`http://${req.headers.host}${req.url}`, { method: req.method ?? "GET" }));
      res.writeHead(resp.status, Object.fromEntries(resp.headers));
      res.end(Buffer.from(await resp.arrayBuffer()));
    })();
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  closers.push(() => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("client on a tier-C registry: registration evidence (SPEC-CHAINS §2)", () => {
  it("verifies with the bundle's registration_quote and reports the evidence check", async () => {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst);
    const R = routerFor(inst);
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: reader(z), trustedRoot: inst.root.publicKey, fetch: R.fetch });
    const v = await c.attest();
    expect(v.checks).toEqual([...Object.values(CHECKS), REGISTRATION_EVIDENCE_CHECK]);
  });

  for (const mode of ["absent", "malformed", "tampered"] as const) {
    it(`registration_quote ${mode} → E_REGISTRATION_EVIDENCE`, async () => {
      const z = await zebra();
      const inst = await instance();
      publish(z, inst);
      const R = routerFor(inst, { quote: mode });
      const c = new PrivateClient({ routerUrl: "http://router.test", registry: reader(z), trustedRoot: inst.root.publicKey, fetch: R.fetch });
      expect(await code(c.attest())).toBe("E_REGISTRATION_EVIDENCE");
    });
  }

  it("a committed quote bound to another operator → E_REGISTRATION_EVIDENCE", async () => {
    const z = await zebra();
    const inst = await instance(op2); // quote binds op2, but op registers (and commits) it
    publish(z, inst);
    const R = routerFor(inst);
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: reader(z), trustedRoot: inst.root.publicKey, fetch: R.fetch });
    expect(await code(c.attest())).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("node failure while fetching the evidence → E_REGISTRY_UNAVAILABLE", async () => {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst);
    const R = routerFor(inst);
    const reg = reader(z);
    let n = 0;
    const flaky: RegistryReader = {
      chain: reg.chain,
      contractId: reg.contractId,
      verifiesOnChain: false,
      getRoot: () => reg.getRoot(),
      isComposeAllowed: (h) => reg.isComposeAllowed(h),
      isOsAllowed: (h) => reg.isOsAllowed(h),
      getInstance: (k) => reg.getInstance(k),
      getAnchor: (i) => reg.getAnchor(i),
      getRegistrationQuote: () => (n++, Promise.reject(new Error("down"))),
    };
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: flaky, trustedRoot: inst.root.publicKey, fetch: R.fetch });
    expect(await code(c.attest())).toBe("E_REGISTRY_UNAVAILABLE");
    expect(n).toBe(1);
  });
});

describe("verifyAnchored on tier B/C: the anchor's Ed25519 signature (SPEC-CHAINS §2)", () => {
  async function setup(sig: (R: ReturnType<typeof routerFor>) => string) {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst);
    const R = routerFor(inst);
    z.mine([recordTx(op, { type: "anchor", key_hash: inst.kh, root: R.root, first_seq: 0, count: 3 })]);
    z.mine([recordTx(op, { type: "anchor_sig", key_prefix: inst.kh.slice(0, 16), sig: sig(R) })]);
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: reader(z), trustedRoot: inst.root.publicKey, fetch: R.fetch });
    return { z, inst, R, c };
  }

  it("a correctly signed anchor verifies (with and without a prior attestation)", async () => {
    const { R, c } = await setup((R) => R.signAnchor());
    expect(await c.verifyAnchored(R.receipts[1]!)).toMatchObject({ anchorId: 0, index: 1, count: 3, root: R.root });
    await c.attest();
    expect(await c.verifyAnchored(R.receipts[2]!)).toMatchObject({ index: 2 });
  });

  // The strict Zcash reader already drops anchors whose 0x21 is not a valid instance signature (review fix: a
  // stale or misplaced signature can never be attached to a batch), so the client sees no anchor at all; the
  // client-side E_ANCHOR_SIG check itself is covered with a MemoryRegistry below.
  it("a bad signature: the anchor is never accepted (E_NOT_ANCHORED)", async () => {
    const { R, c, z } = await setup(() => "cd".repeat(64));
    await c.attest();
    expect(await code(c.verifyAnchored(R.receipts[0]!))).toBe("E_NOT_ANCHORED");
    expect(await reader(z).anchorCount()).toBe(0);
  });

  it("a signature by another key, or over another registry id: never accepted (E_NOT_ANCHORED)", async () => {
    const other = await setup((R) => R.signAnchor(CONTRACT, ed25519.utils.randomSecretKey()));
    expect(await code(other.c.verifyAnchored(other.R.receipts[0]!))).toBe("E_NOT_ANCHORED");
    const wrongId = await setup((R) => R.signAnchor("registry.test.near"));
    expect(await code(wrongId.c.verifyAnchored(wrongId.R.receipts[0]!))).toBe("E_NOT_ANCHORED");
  });

  it("a missing sig on a non-verifying registry → E_ANCHOR_SIG; a tier-A registry needs none", async () => {
    const inst = await instance();
    const R = routerFor(inst);
    const anchor: AnchorRecord = { id: 0, key_hash: inst.kh, root: R.root, first_seq: 0, count: 3, at_ms: 1 };
    const mk = (verifiesOnChain: boolean, a: AnchorRecord) => {
      const m = new MemoryRegistry({
        root: { kind: "MOCK", p256: toHex(inst.root.publicKey) },
        compose: [inst.composeHash],
        os: [inst.osHash],
        instances: { [inst.kh]: { compose_hash: inst.composeHash, os_measurement: inst.osHash, x25519: toHex(inst.xp), ed25519: toHex(inst.ep), operator: op.addr, org_id: "org-a", registered_at_ms: 1, expires_at_ms: Date.now() + 60_000, next_seq: 3 } },
        verifiesOnChain,
        contractId: CONTRACT,
      });
      m.addAnchor(a);
      return m;
    };
    const reply = await (await R.handle(new Request("http://r/v1/receipts/proof?seq=1"))).json();
    expect(await code(verifyReceiptAnchored({ receipt: R.receipts[1]!, reply, registry: mk(false, anchor) }))).toBe("E_ANCHOR_SIG");
    expect(await code(verifyReceiptAnchored({ receipt: R.receipts[1]!, reply, registry: mk(true, anchor) }))).toBe("NO_THROW");
    // signer resolved from the registry's instance record (no hint)
    expect(await code(verifyReceiptAnchored({ receipt: R.receipts[1]!, reply, registry: mk(false, { ...anchor, sig: R.signAnchor() }) }))).toBe("NO_THROW");
    // a registry that cannot say whether it verifies is treated as non-verifying (fail closed)
    const m = mk(true, anchor);
    const unknown = new Proxy(m, { get: (t, p) => (p === "verifiesOnChain" ? undefined : (Reflect.get(t, p) as unknown) instanceof Function ? (Reflect.get(t, p) as (...a: unknown[]) => unknown).bind(t) : Reflect.get(t, p)) });
    expect(await code(verifyReceiptAnchored({ receipt: R.receipts[1]!, reply, registry: unknown as RegistryReader }))).toBe("E_ANCHOR_SIG");
  });
});

// ---------------------------------------------------------------- CLI

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s) }, write: () => undefined };
}

describe("plr CLI with PLR_CHAIN=zcash", () => {
  const root = toHex(MockRoot.generate().publicKey);

  it("loads the Zcash registry from PLR_ZCASH_* or a zcash:… registry id", () => {
    const c = loadConfig({ PLR_CHAIN: "zcash", PLR_ZCASH_NETWORK: "regtest", PLR_ZCASH_OWNER: owner.addr, PLR_TRUSTED_ROOT: root, PLR_ZCASH_START_HEIGHT: "7" });
    expect(c).toMatchObject({ chain: "zcash", contractId: CONTRACT, rpcUrl: "http://127.0.0.1:18232", zcash: { network: "regtest", owner: owner.addr, startHeight: 7 } });
    const d = loadConfig({ PLR_CHAIN: "zcash", PLR_REGISTRY: CONTRACT, PLR_ZCASH_RPC: "http://127.0.0.1:9999", PLR_TRUSTED_ROOT: root });
    expect(d).toMatchObject({ chain: "zcash", contractId: CONTRACT, rpcUrl: "http://127.0.0.1:9999" });
    const v = loadVpnConfig({ PLR_CHAIN: "zcash", PLR_VPN_REGISTRY: `zcash:regtest:${op.addr}`, PLR_ZCASH_OWNER: owner.addr, PLR_TRUSTED_ROOT: root });
    expect(v).toMatchObject({ chain: "zcash", contractId: `zcash:regtest:${op.addr}` });
    expect(loadConfig({ PLR_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: root }).chain).toBe("near");
  });

  it("refuses incomplete or inconsistent Zcash settings and unsupported chains", () => {
    const base = { PLR_CHAIN: "zcash", PLR_TRUSTED_ROOT: root };
    const msg = (env: Record<string, string>) => {
      try {
        loadConfig(env);
        return "NO_THROW";
      } catch (e) {
        return (e as Error).message;
      }
    };
    expect(msg({ ...base, PLR_ZCASH_OWNER: owner.addr })).toMatch(/PLR_ZCASH_NETWORK/);
    expect(msg({ ...base, PLR_ZCASH_NETWORK: "regtest" })).toMatch(/PLR_ZCASH_OWNER/);
    expect(msg({ ...base, PLR_ZCASH_NETWORK: "mainnet", PLR_ZCASH_OWNER: owner.addr })).toMatch(/t-address/);
    expect(msg({ ...base, PLR_ZCASH_NETWORK: "testnet", PLR_REGISTRY: CONTRACT })).toMatch(/disagrees/);
    expect(msg({ ...base, PLR_ZCASH_OWNER: op.addr, PLR_REGISTRY: CONTRACT })).toMatch(/disagrees/);
    expect(msg({ ...base, PLR_REGISTRY: "registry.test.near" })).toMatch(/zcash:/);
    expect(msg({ ...base, PLR_REGISTRY: CONTRACT, PLR_ZCASH_RPC: "http://zebra.example.com" })).toMatch(/PLR_ZCASH_RPC/);
    expect(msg({ ...base, PLR_REGISTRY: CONTRACT, PLR_ZCASH_START_HEIGHT: "-1" })).toMatch(/START_HEIGHT/);
    expect(msg({ ...base, PLR_CHAIN: "evm", PLR_REGISTRY: "x" })).toMatch(/evm:<chainId>/); // tier B is supported: strict ids
    expect(msg({ ...base, PLR_CHAIN: "dogecoin", PLR_REGISTRY: "x" })).toMatch(/PLR_CHAIN/);
  });

  it("plr verify shows tier C and the registration-evidence check", async () => {
    const z = await zebra();
    const inst = await instance();
    publish(z, inst);
    const R = routerFor(inst);
    const url = await listen(R.handle);
    const env = { PLR_CHAIN: "zcash", PLR_ZCASH_RPC: z.url, PLR_REGISTRY: CONTRACT, PLR_ROUTER_URL: url, PLR_TRUSTED_ROOT: toHex(inst.root.publicKey) };
    const t = io();
    expect(await runCli(["verify"], env, t.io, t.write)).toBe(0);
    const text = t.out.join("\n");
    expect(text).toContain(`registry: ${CONTRACT} on zcash`);
    expect(text).toMatch(/tier: +C/);
    expect(text).toContain(`✔ ${REGISTRATION_EVIDENCE_CHECK}`);
    expect(text).toContain(`operator:      ${op.addr}`);
    expect(text).toContain("✔ VERIFIED");

    R.state.quote = "absent";
    const u = io();
    expect(await runCli(["verify"], env, u.io, u.write)).toBe(1);
    const bad = u.out.join("\n");
    expect(bad).toContain(`✘ ${REGISTRATION_EVIDENCE_CHECK}`);
    expect(bad).toContain("[E_REGISTRATION_EVIDENCE]");
    expect(bad).toContain(`✔ ${CHECKS.INSTANCE}`);
  });

  it("checkLines: the evidence step only for non-verifying registries; registry failures there are attributed to it", () => {
    expect(checkLines(undefined).length).toBe(Object.keys(CHECKS).length);
    expect(checkLines(undefined, undefined, { evidence: true }).length).toBe(Object.keys(CHECKS).length + 1);
    const lines = checkLines(new PlrError("E_REGISTRY_UNAVAILABLE"), "getRegistrationQuote", { evidence: true });
    expect(lines.at(-1)!.status).toBe("fail");
    expect(lines.slice(0, -1).every((l) => l.status === "pass")).toBe(true);
  });
});

// ---------------------------------------------------------------- review fixes (adversarial review regressions)

describe("review fixes: record authorship needs the author's own P2PKH coin", () => {
  it("records spending a non-P2PKH(author) coin or with a non-SIGHASH_ALL signature are ignored (no forgery without the key)", async () => {
    const z = await zebra();
    const anyone = { prevoutScript: new Uint8Array([0x6d, 0x51]) }; // OP_2DROP OP_1: accepts any <x> <pubkey> scriptSig
    z.mine([
      recordTx(owner, { type: "allow_compose", hash: h32(1) }, anyone),
      recordTx(owner, { type: "approve_operator", hash160: stranger.h160, org_id: "evil" }, anyone),
      recordTx(owner, { type: "transfer_owner", hash160: stranger.h160 }, anyone),
      recordTx(owner, { type: "allow_os", hash: h32(2) }, { hashType: 0x82 }),                                    // SIGHASH_NONE|ANYONECANPAY
      recordTx(owner, { type: "allow_os", hash: h32(3) }, { prevoutScript: p2pkhScript(fromHex(stranger.h160, 20)) }), // someone else's coin
    ]);
    const r = reader(z);
    expect(await r.isComposeAllowed(h32(1))).toBe(false);
    expect(await r.getOperator(stranger.addr)).toBeNull();
    expect(await r.isOsAllowed(h32(2))).toBe(false);
    expect(await r.isOsAllowed(h32(3))).toBe(false);
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(4) })]); // the real owner is still the owner
    expect(await r.isComposeAllowed(h32(4))).toBe(true);
    expect(z.calls.some((c) => c.method === "getrawtransaction")).toBe(true);
    expect(z.calls.some((c) => c.method === "getblock" && c.params[1] !== 0)).toBe(false);
  });

  it("a node that cannot or will not show a prevout fails the query (never a silently skipped record)", async () => {
    const z = await zebra();
    z.mine([recordTx(owner, { type: "allow_compose", hash: h32(1) })]);
    const other = coinbaseTx();
    z.override = (m) => (m === "getrawtransaction" ? { status: 200, body: { jsonrpc: "2.0", id: 0, result: toHex(other.raw) } } : undefined);
    expect(await code(reader(z).isComposeAllowed(h32(1)))).toBe("ERR:ZcashRegistryError");
    z.override = (m) => (m === "getrawtransaction" ? { status: 200, body: { jsonrpc: "2.0", id: 0, error: { code: -5, message: "no" } } } : undefined);
    expect(await code(reader(z).isComposeAllowed(h32(1)))).toBe("ERR:ZcashRegistryError");
    z.override = undefined;
    expect(await reader(z).isComposeAllowed(h32(1))).toBe(true);
  });
});

describe("review fixes: raw blocks (one large block must not stop every client)", () => {
  it("reads a ~1.9 MB block of many-output transactions via getblock <hash> 0", async () => {
    const z = await zebra();
    const p2sh = Uint8Array.from([0xa9, 0x14, ...new Uint8Array(20).fill(7), 0x87]);
    const big = Array.from({ length: 2 }, () => rawTx([{ prev: new Uint8Array(32).fill(9), index: 0, scriptSig: new Uint8Array([0x51]) }], Array.from({ length: 29_000 }, () => ({ value: 1000n, script: p2sh }))));
    const b = z.mine([...big, recordTx(owner, { type: "allow_compose", hash: h32(5) })]);
    expect(b.raw.length).toBeGreaterThan(1_800_000);
    expect(b.raw.length).toBeLessThan(2_000_000);
    const r = reader(z);
    expect(await r.isComposeAllowed(h32(5))).toBe(true);
    expect(z.calls.filter((c) => c.method === "getblock").every((c) => c.params[1] === 0)).toBe(true);
  });

  it("a block whose bytes do not hash to the requested block hash is refused", async () => {
    const z = await zebra();
    const b = z.mine([recordTx(owner, { type: "allow_compose", hash: h32(1) })]);
    const evil = z.mine([recordTx(owner, { type: "allow_compose", hash: h32(2) })]);
    z.override = (m, p) => (m === "getblock" && p[0] === b.hash ? { status: 200, body: { jsonrpc: "2.0", id: 0, result: toHex(evil.raw) } } : undefined);
    expect(await code(reader(z).isComposeAllowed(h32(1)))).toBe("ERR:ZcashRegistryError");
  });

  it("catch-up is bounded in time (not a fixed block budget) and keeps its progress", async () => {
    const z = await zebra();
    for (let i = 0; i < 60; i++) z.mine();
    z.mine([recordTx(owner, { type: "allow_os", hash: h32(1) })]);
    const r = reader(z, { syncTimeoutMs: 1, concurrency: 1 });
    let ok = false;
    for (let i = 0; i < 200 && !ok; i++) ok = await r.isOsAllowed(h32(1)).catch(() => false);
    expect(ok).toBe(true);
    const d = reader(z); // defaults: no 20 000-block budget any more
    expect(await d.isOsAllowed(h32(1))).toBe(true);
  });

  it("CLI: PLR_ZCASH_SYNC_TIMEOUT_MS is passed to the reader; bad values are refused", () => {
    const root = toHex(MockRoot.generate().publicKey);
    const base = { PLR_CHAIN: "zcash", PLR_ZCASH_NETWORK: "regtest", PLR_ZCASH_OWNER: owner.addr, PLR_TRUSTED_ROOT: root };
    expect(loadConfig({ ...base, PLR_ZCASH_SYNC_TIMEOUT_MS: "300000" }).zcash).toMatchObject({ syncTimeoutMs: 300_000 });
    expect(() => loadConfig({ ...base, PLR_ZCASH_SYNC_TIMEOUT_MS: "0" })).toThrow();
    expect(() => loadConfig({ ...base, PLR_ZCASH_SYNC_TIMEOUT_MS: "x" })).toThrow();
  });
});

describe("review: a rival approved operator copying an instance's public records (SPEC-CHAINS §5 selection)", () => {
  /** Policy + both operators approved; the rival (op2) copies the instance's public records FIRST. */
  async function race(rivalQuoteSha: (inst: Inst) => string) {
    const z = await zebra();
    const inst = await instance(op); // the genuine registration quote binds op
    z.mine([
      recordTx(owner, { type: "set_root", kind: "MOCK", p256: toHex(inst.root.publicKey) }),
      recordTx(owner, { type: "allow_compose", hash: inst.composeHash }),
      recordTx(owner, { type: "allow_os", hash: inst.osHash }),
      recordTx(owner, { type: "approve_operator", hash160: op.h160, org_id: "org-a" }),
      recordTx(owner, { type: "approve_operator", hash160: op2.h160, org_id: "org-rival" }),
    ]);
    const regs = (who: Party, q: string) => [
      recordTx(who, { type: "reg_keys", x25519: toHex(inst.xp), ed25519: toHex(inst.ep) }),
      recordTx(who, { type: "reg_measure", key_hash: inst.kh, compose_hash: inst.composeHash }),
      recordTx(who, { type: "reg_os", key_hash: inst.kh, os_measurement: inst.osHash }),
      recordTx(who, { type: "reg_quote", key_hash: inst.kh, quote_sha256: q }),
    ];
    z.mine(regs(op2, rivalQuoteSha(inst)));
    z.mine(regs(op, toHex(sha256(inst.regQuote))));
    return { z, inst };
  }

  for (const [name, q] of [["a garbage commitment", () => h32(0x77)], ["the genuine quote's commitment", (i: Inst) => toHex(sha256(i.regQuote))]] as const) {
    it(`rival registered first with ${name}: it is the §5 instance, and clients fail closed (no hijack)`, async () => {
      const { z, inst } = await race(q);
      const r = reader(z);
      expect((await r.getInstance(inst.kh))!).toMatchObject({ operator: op2.addr, org_id: "org-rival" });
      const R = routerFor(inst);
      const c = new PrivateClient({ routerUrl: "http://router.test", registry: r, trustedRoot: inst.root.publicKey, fetch: R.fetch });
      expect(await code(c.attest())).toBe("E_REGISTRATION_EVIDENCE"); // the quote binds op, not the recorded op2
      // the rival cannot anchor the key either (it cannot produce the instance's signature)
      z.mine([recordTx(op2, { type: "anchor", key_hash: inst.kh, root: R.root, first_seq: 0, count: 3 })]);
      z.mine([recordTx(op2, { type: "anchor_sig", key_prefix: inst.kh.slice(0, 16), sig: "cd".repeat(64) })]);
      expect(await r.anchorCount()).toBe(0);
    });
  }
});
