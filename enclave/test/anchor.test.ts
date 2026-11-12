import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  MockRoot, MockTdxAttester, anchorMessage, fromHex, keyHash, parseQuote, registrationNonce, registrationReportData,
  reportData, toHex, verifyEventLog, verifyMerkleProof, type VpnReceipt,
} from "@plr/shared";
import { Anchorer } from "../src/anchor.js";
import { Logger } from "../src/log.js";
import type { AnchorArgs, AnchorView, RegisterArgs, RegistryWriter } from "../src/near.js";
import { DEFAULT_ANCHOR_DEPOSIT } from "../src/config.js";
import { EXIT_ENV_ALLOWLIST } from "../src/mock-tdx/host.js";
import { loadExitConfig } from "../src/vpn/config.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { VpnReceiptLog } from "../src/vpn/receipts.js";
import { composeBytes as vpnComposeBytesOf, makeVpnCompose } from "../src/compose.js";
import { verifyVpnReceipt, vpnReceiptLeaf } from "@plr/shared";
import { eventually } from "./wait.js";

const CONTRACT = "registry.test.near";
const COMPOSE = vpnComposeBytesOf(makeVpnCompose({ bundleSha256: "22".repeat(32), nodeSha256: "33".repeat(32), allowLoopback: false }));

/**
 * Enforces the §7 rules the exit depends on (rev 1.3 operator-bound registration report_data, anchor sig, seq).
 * `operatorId` is the account that submits (the contract's `predecessor_account_id`).
 */
class FakeChain implements RegistryWriter {
  readonly contractId = CONTRACT;
  constructor(readonly operatorId = "operator.test.near") {}
  /** The account whose `register_instance` lands first keeps the record (SPEC §7: re-registration keeps operator). */
  instances = new Map<string, { ed: Uint8Array; next: number; operator: string }>();
  /** If set, a front-runner registers every new key under this account just before our own call lands. */
  frontRunner: string | null = null;
  anchors: AnchorView[] = [];
  failNext: string | null = null;
  dropResult = false;
  /** Every register_instance call that reached the report_data check. */
  submitted: RegisterArgs[] = [];
  calls = 0;

  async registerInstance(a: RegisterArgs): Promise<void> {
    this.calls++;
    if (this.failNext) { const c = this.failNext; this.failNext = null; throw new Error(`Smart contract panicked: ${c}`); }
    const q = parseQuote(fromHex(a.quote));
    verifyEventLog(a.event_log, q.report.rtmr[3]);
    const xp = fromHex(a.x25519, 32), ep = fromHex(a.ed25519, 32);
    const want = registrationReportData(xp, ep, CONTRACT, this.operatorId);
    this.submitted.push(a);
    if (toHex(q.report.reportData) !== toHex(want)) throw new Error("Smart contract panicked: E_REPORT_DATA");
    const kh = toHex(keyHash(xp, ep));
    const prev = this.instances.get(kh) ?? (this.frontRunner ? { ed: ep, next: 0, operator: this.frontRunner } : undefined);
    this.instances.set(kh, { ed: ep, next: prev?.next ?? 0, operator: prev?.operator ?? this.operatorId });
  }

  async anchorReceipts(a: AnchorArgs): Promise<unknown> {
    this.calls++;
    if (this.failNext) { const c = this.failNext; this.failNext = null; throw new Error(`Smart contract panicked: ${c}`); }
    const inst = this.instances.get(a.key_hash);
    if (!inst) throw new Error("panicked: E_INSTANCE_NOT_REGISTERED");
    if (a.first_seq !== inst.next || a.count < 1 || a.count > 10_000) throw new Error("panicked: E_SEQ");
    const msg = anchorMessage({ contractId: CONTRACT, keyHash: fromHex(a.key_hash, 32), root: fromHex(a.root, 32), firstSeq: BigInt(a.first_seq), count: BigInt(a.count) });
    if (!ed25519.verify(fromHex(a.sig, 64), msg, inst.ed)) throw new Error("panicked: E_ANCHOR_SIG");
    inst.next += a.count;
    const id = this.anchors.length;
    this.anchors.push({ id, key_hash: a.key_hash, root: a.root, first_seq: a.first_seq, count: a.count });
    if (this.dropResult) { this.dropResult = false; throw new Error("RPC timeout"); }
    return id;
  }

  async getInstanceNextSeq(kh: string) { return this.instances.get(kh)?.next ?? null; }
  async getInstanceOperator(kh: string) { return this.instances.get(kh)?.operator ?? null; }
  async anchorCount() { return this.anchors.length; }
  async getAnchor(id: number) { return this.anchors[id] ?? null; }
}

function setup() {
  const root = MockRoot.generate();
  const attester = new MockTdxAttester({ root, composeBytes: COMPOSE });
  const keys = VpnKeys.generate();
  const receipts = new VpnReceiptLog();
  const chain = new FakeChain();
  const lines: string[] = [];
  const anchorer = new Anchorer({ chain, attester, keys, receipts, composeBytes: COMPOSE, log: new Logger("plr-vpn", (l) => lines.push(l)) });
  const issue = (n: number) => {
    const out: VpnReceipt[] = [];
    for (let i = 0; i < n; i++) {
      out.push(receipts.issue({ th: randomBytes(32), composeHash: randomBytes(32), keyHash: keys.keyHash, tsOpenMs: Date.now(), tsCloseMs: Date.now(), sign: (r) => keys.signVpnReceipt(r) }).receipt);
    }
    return out;
  };
  return { root, attester, keys, receipts, chain, anchorer, lines, issue };
}

describe("registration (SPEC §5, §7)", () => {
  it("registers with a registration-nonce quote and the exact compose", async () => {
    const t = setup();
    expect(await t.anchorer.register()).toBe(true);
    expect(t.anchorer.state).toBe("registered");
    expect(t.chain.instances.has(toHex(t.keys.keyHash))).toBe(true);
    expect(t.lines.some((l) => l.startsWith("plr-vpn: registered key_hash="))).toBe(true);
  });

  it("rev 1.3: the registration quote is bound to this registry AND this operator, and is never a session quote", async () => {
    const t = setup();
    expect(await t.anchorer.register()).toBe(true);
    const sub = t.chain.submitted[0]!;
    const rd = parseQuote(fromHex(sub.quote)).report.reportData;
    expect(toHex(rd)).toBe(toHex(registrationReportData(t.keys.x25519, t.keys.ed25519, CONTRACT, "operator.test.near")));
    expect(toHex(rd)).toBe(toHex(t.keys.registrationReportData(CONTRACT, "operator.test.near")));
    // Somebody else submitting the very same quote (front-running / replay) is refused by the contract rule.
    const thief = new FakeChain("attacker.test.near");
    await expect(thief.registerInstance(sub)).rejects.toThrow(/E_REPORT_DATA/);
    expect(thief.instances.size).toBe(0);
    // A session quote — even one asked for with the registration nonce as client nonce — never matches it.
    const nonce = registrationNonce(CONTRACT, "operator.test.near");
    expect(toHex(t.keys.reportData(nonce))).not.toBe(toHex(rd));
    expect(toHex(t.keys.reportData(nonce))).toBe(toHex(reportData(t.keys.x25519, t.keys.ed25519, nonce)));
    const asSession = await t.attester.getQuote(t.keys.reportData(nonce));
    await expect(new FakeChain().registerInstance({ ...sub, quote: toHex(asSession.quote), event_log: asSession.eventLog })).rejects.toThrow(/E_REPORT_DATA/);
  });

  it("an operator id that cannot be bound (over 64 bytes) → registration fails closed, no quote submitted", async () => {
    const t = setup();
    const chain = new FakeChain("o".repeat(65));
    const a = new Anchorer({ chain, attester: t.attester, keys: t.keys, receipts: t.receipts, composeBytes: COMPOSE, log: new Logger("plr-vpn", (l) => t.lines.push(l)) });
    expect(await a.register()).toBe(false);
    expect(chain.calls).toBe(0);
    expect(a.lastError).toBe("E_BAD_INPUT");
  });

  it("failure → keeps state 'failed' and logs only the code", async () => {
    const t = setup();
    t.chain.failNext = "E_COMPOSE_NOT_ALLOWED";
    expect(await t.anchorer.register()).toBe(false);
    expect(t.anchorer.state).toBe("failed");
    expect(t.anchorer.lastError).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(t.lines).toEqual(["plr-vpn: registration_failed code=E_COMPOSE_NOT_ALLOWED"]);
  });

  it("non-coded failure → E_REGISTRY_UNAVAILABLE", async () => {
    const t = setup();
    t.chain.registerInstance = async () => { throw new Error("fetch failed: secret-ish detail"); };
    expect(await t.anchorer.register()).toBe(false);
    expect(t.lines.join("\n")).not.toContain("secret-ish");
    expect(t.anchorer.lastError).toBe("E_REGISTRY_UNAVAILABLE");
  });
});

describe("anchoring (SPEC §8)", () => {
  it("does nothing until registered or when empty", async () => {
    const t = setup();
    t.issue(2);
    await t.anchorer.anchorOnce();
    expect(t.chain.calls).toBe(0);
    await t.anchorer.register();
    const c = t.chain.calls;
    await t.anchorer.anchorOnce();
    await t.anchorer.anchorOnce();
    expect(t.chain.calls).toBe(c + 1);
  });

  it("anchors contiguous batches and serves proofs that verify against the on-chain root", async () => {
    const t = setup();
    await t.anchorer.register();
    const a = t.issue(5);
    await t.anchorer.anchorOnce();
    const b = t.issue(3);
    await t.anchorer.anchorOnce();
    expect(t.chain.anchors.map((x) => [x.first_seq, x.count])).toEqual([[0, 5], [5, 3]]);
    for (const r of [...a, ...b]) {
      const p = t.receipts.proof(r.seq)!;
      const anchor = t.chain.anchors[p.anchor_id]!;
      expect(p.root).toBe(anchor.root);
      expect(verifyMerkleProof(vpnReceiptLeaf(r), p.index, p.count, p.proof.map((h) => fromHex(h, 32)), fromHex(anchor.root, 32))).toBe(true);
    }
    expect(t.receipts.proof(8)).toBeNull();
  });

  it("a failed batch stays pending and is retried with the same first_seq (grown)", async () => {
    const t = setup();
    await t.anchorer.register();
    t.issue(2);
    t.chain.failNext = "E_COMPOSE_NOT_ALLOWED";
    await t.anchorer.anchorOnce();
    expect(t.receipts.anchoredCount).toBe(0);
    t.issue(1);
    await t.anchorer.anchorOnce();
    expect(t.chain.anchors.map((x) => [x.first_seq, x.count])).toEqual([[0, 3]]);
    expect(t.receipts.anchoredCount).toBe(3);
  });

  it("lost RPC response: E_SEQ on retry triggers a verified resync", async () => {
    const t = setup();
    await t.anchorer.register();
    t.issue(4);
    t.chain.dropResult = true;
    await t.anchorer.anchorOnce(); // anchored on chain, but the exit saw an error
    expect(t.receipts.anchoredCount).toBe(0);
    t.issue(1);
    await t.anchorer.anchorOnce(); // E_SEQ → resync adopts [0,4)
    expect(t.receipts.anchoredCount).toBe(4);
    await t.anchorer.anchorOnce();
    expect(t.receipts.anchoredCount).toBe(5);
    expect(t.anchorer.halted).toBe(false);
  });

  it("halts (fail closed) if the chain's anchor does not match the local log", async () => {
    const t = setup();
    await t.anchorer.register();
    t.issue(2);
    const kh = toHex(t.keys.keyHash);
    t.chain.anchors.push({ id: 0, key_hash: kh, root: "ee".repeat(32), first_seq: 0, count: 2 });
    t.chain.instances.get(kh)!.next = 2;
    await t.anchorer.anchorOnce();
    expect(t.anchorer.halted).toBe(true);
    expect(t.receipts.proof(0)).toBeNull();
    expect(t.lines.some((l) => l.includes("anchor_halted code=E_SEQ"))).toBe(true);
  });

  it("caps a batch at 10 000 receipts", () => {
    const t = setup();
    t.issue(10_005);
    expect(t.receipts.pendingBatch()!.count).toBe(10_000);
  }, 60_000);
});

describe("VpnReceiptLog", () => {
  it("rejects non-contiguous anchors", () => {
    const t = setup();
    t.issue(3);
    expect(() => t.receipts.markAnchored({ anchorId: 0, firstSeq: 1, count: 1, root: new Uint8Array(32) })).toThrow();
    expect(() => t.receipts.markAnchored({ anchorId: 0, firstSeq: 0, count: 4, root: new Uint8Array(32) })).toThrow();
  });
});

// Regression (review "anchor_receipts storage is paid by the contract"): every anchor carries a storage deposit
// (refunded in excess by the contract); if the chain still reports E_DEPOSIT, the exit re-registers, which
// tops up the instance's prepaid anchor credit, and the batch stays pending until it succeeds.
describe("anchor storage deposit", () => {
  const nearEnv = {
    PLR_TDX_SOCKET: "/tmp/q.sock",
    PLR_APP_COMPOSE_PATH: "/tmp/app-compose.json",
    PLR_NEAR_RPC: "http://127.0.0.1:3030",
    PLR_VPN_REGISTRY: "registry.test.near",
    PLR_OPERATOR_ID: "operator.test.near",
    PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64),
  };

  it("PLR_ANCHOR_DEPOSIT defaults to 0.01 NEAR and is strictly validated", () => {
    expect(loadExitConfig(nearEnv).near?.anchorDeposit).toBe(BigInt(DEFAULT_ANCHOR_DEPOSIT));
    expect(BigInt(DEFAULT_ANCHOR_DEPOSIT)).toBeGreaterThan(0n);
    expect(loadExitConfig({ ...nearEnv, PLR_ANCHOR_DEPOSIT: "5" }).near?.anchorDeposit).toBe(5n);
    // Malformed ⇒ registration (and anchoring) disabled, fail closed.
    for (const bad of ["-1", "1e3", "0x10", "1".repeat(41)]) {
      const c = loadExitConfig({ ...nearEnv, PLR_ANCHOR_DEPOSIT: bad });
      expect(c.near, bad).toBeNull();
      expect(c.nearConfigError, bad).toBe(true);
    }
    expect(EXIT_ENV_ALLOWLIST).toContain("PLR_ANCHOR_DEPOSIT");
  });

  it("E_DEPOSIT keeps the batch pending and triggers a top-up re-registration", async () => {
    const t = setup();
    await t.anchorer.register();
    const regCalls = () => t.chain.calls;
    t.issue(2);
    t.chain.failNext = "E_DEPOSIT";
    const before = regCalls();
    await t.anchorer.anchorOnce();
    expect(t.receipts.anchoredCount).toBe(0);
    // The top-up re-registration is scheduled immediately (timer 0): wait for its outcome event, not a fixed sleep.
    expect(await eventually(() => t.lines.some((l) => l.includes("registration_refreshed")))).toBe(true);
    t.anchorer.stop();
    expect(regCalls()).toBe(before + 2); // the failed anchor + the top-up registration
    expect(t.lines.some((l) => l.includes("anchor_failed") && l.includes("code=E_DEPOSIT"))).toBe(true);
    await t.anchorer.anchorOnce();
    expect(t.receipts.anchoredCount).toBe(2);
  });
});

describe("VPN exit registration + anchoring (SPEC-VPN §5: same Anchorer, VPN receipts)", () => {
  it("registers the exit and anchors VPN receipt leaves; proofs verify against the on-chain root", async () => {
    const compose = vpnComposeBytesOf(makeVpnCompose({ bundleSha256: "44".repeat(32), nodeSha256: "55".repeat(32), allowLoopback: false }));
    const root = MockRoot.generate();
    const attester = new MockTdxAttester({ root, composeBytes: compose });
    const keys = VpnKeys.generate();
    const receipts = new VpnReceiptLog();
    const chain = new FakeChain();
    const lines: string[] = [];
    const anchorer = new Anchorer({ chain, attester, keys, receipts, composeBytes: compose, log: new Logger("plr-vpn", (l) => lines.push(l)) });
    expect(await anchorer.register()).toBe(true);
    expect(lines).toContain(`plr-vpn: registered key_hash=${toHex(keys.keyHash)}`);
    const issued = [0, 1, 2].map((i) => receipts.issue({ th: randomBytes(32), composeHash: randomBytes(32), keyHash: keys.keyHash, tsOpenMs: 1000 + i, tsCloseMs: 900, sign: (r) => keys.signVpnReceipt(r) }));
    for (const [i, { receipt, sig }] of issued.entries()) {
      expect(receipt.seq).toBe(i);
      expect(receipt.ts_close_ms).toBe(receipt.ts_open_ms); // clock stepped back: clamped, never open > close
      expect(verifyVpnReceipt(receipt, sig, keys.ed25519)).toBe(true);
    }
    await anchorer.anchorOnce();
    expect(chain.anchors).toHaveLength(1);
    const p = receipts.proof(1)!;
    expect(verifyMerkleProof(vpnReceiptLeaf(issued[1]!.receipt), p.index, p.count, p.proof.map((h) => fromHex(h, 32)), fromHex(chain.anchors[0]!.root, 32))).toBe(true);
  });
});

// Review finding (high): whoever calls register_instance first for a key decides its on-chain operator, hence its
// org_id (SPEC §7 rev 1.2, SPEC-VPN §10). Rev 1.3 closes this on-chain (operator-bound registration quote); the exit
// still reads the operator back and stops for good on a mismatch (defense in depth: e.g. a faulty registry, simulated
// here by a chain that records someone else).
describe("operator read-back (defense in depth against registration hijack)", () => {
  function vpnSetup(chain: FakeChain) {
    const compose = vpnComposeBytesOf(makeVpnCompose({ bundleSha256: "44".repeat(32), nodeSha256: "55".repeat(32), allowLoopback: false }));
    const attester = new MockTdxAttester({ root: MockRoot.generate(), composeBytes: compose });
    const keys = VpnKeys.generate();
    const receipts = new VpnReceiptLog();
    const lines: string[] = [];
    let mismatches = 0;
    const anchorer = new Anchorer({
      chain, attester, keys, receipts, composeBytes: compose, log: new Logger("plr-vpn", (l) => lines.push(l)),
      onOperatorMismatch: () => { mismatches++; },
    });
    return { anchorer, keys, receipts, lines, mismatches: () => mismatches };
  }

  it("own operator on chain → registered as usual", async () => {
    const t = vpnSetup(new FakeChain());
    expect(await t.anchorer.register()).toBe(true);
    expect(t.anchorer.state).toBe("registered");
    expect(t.mismatches()).toBe(0);
  });

  it("someone else registered the key first → never 'registered', halts permanently, signals the service once", async () => {
    const chain = new FakeChain();
    chain.frontRunner = "attacker.test.near";
    const t = vpnSetup(chain);
    t.anchorer.start();
    expect(await eventually(() => t.mismatches() === 1)).toBe(true);
    expect(t.anchorer.state).toBe("failed");
    expect(t.anchorer.halted).toBe(true);
    expect(t.anchorer.lastError).toBe("E_OPERATOR_MISMATCH");
    expect(t.lines).toEqual(["plr-vpn: registration_failed code=E_OPERATOR_MISMATCH"]);
    // Permanent: no retries, no anchoring of anything issued afterwards.
    const calls = chain.calls;
    expect(await t.anchorer.register()).toBe(false);
    t.receipts.issue({ th: randomBytes(32), composeHash: randomBytes(32), keyHash: t.keys.keyHash, tsOpenMs: 1, tsCloseMs: 2, sign: (r) => t.keys.signVpnReceipt(r) });
    await t.anchorer.anchorOnce();
    expect(chain.calls).toBe(calls);
    expect(t.mismatches()).toBe(1);
    t.anchorer.stop();
  });

  it("read-back finds no record → retried like any failure (not 'registered')", async () => {
    const chain = new FakeChain();
    chain.getInstanceOperator = async () => null;
    const t = vpnSetup(chain);
    expect(await t.anchorer.register()).toBe(false);
    expect(t.anchorer.state).toBe("failed");
    expect(t.anchorer.lastError).toBe("E_INSTANCE_NOT_REGISTERED");
    expect(t.mismatches()).toBe(0);
  });

  it("without onOperatorMismatch the operator is not consulted", async () => {
    const chain = new FakeChain();
    chain.frontRunner = "attacker.test.near";
    chain.getInstanceOperator = async () => { throw new Error("must not be called"); };
    const t = setup();
    const a = new Anchorer({ chain, attester: t.attester, keys: t.keys, receipts: t.receipts, composeBytes: COMPOSE, log: new Logger("plr-vpn", () => undefined) });
    expect(await a.register()).toBe(true);
  });
});
