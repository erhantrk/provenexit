import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  MockRoot, MockTdxAttester, anchorMessage, fromHex, keyHash, parseQuote, receiptLeaf, registrationNonce,
  reportData, toHex, verifyEventLog, verifyMerkleProof, type Receipt,
} from "@plr/shared";
import { Anchorer } from "../src/anchor.js";
import { RouterKeys } from "../src/keys.js";
import { Logger } from "../src/log.js";
import type { AnchorArgs, AnchorView, RegisterArgs, RegistryWriter } from "../src/near.js";
import { ReceiptLog } from "../src/receipts.js";
import { composeBytes, makeCompose } from "../src/compose.js";
import { DEFAULT_ANCHOR_DEPOSIT, loadConfig } from "../src/config.js";
import { ROUTER_ENV_ALLOWLIST } from "../src/mock-tdx/host.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { VpnReceiptLog } from "../src/vpn/receipts.js";
import { composeBytes as vpnComposeBytesOf, makeVpnCompose } from "../src/compose.js";
import { verifyVpnReceipt, vpnReceiptLeaf } from "@plr/shared";

const CONTRACT = "registry.test.near";
const COMPOSE = composeBytes(makeCompose({ kind: "mock", modelSha256: "11".repeat(32), runtime: "node", bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", runtimeSha256: "33".repeat(32), nodeSha256: "33".repeat(32) }));

/** Enforces the §7 rules the router depends on (registration nonce/report_data, anchor sig, seq). */
class FakeChain implements RegistryWriter {
  readonly contractId = CONTRACT;
  instances = new Map<string, { ed: Uint8Array; next: number }>();
  anchors: AnchorView[] = [];
  failNext: string | null = null;
  dropResult = false;
  calls = 0;

  async registerInstance(a: RegisterArgs): Promise<void> {
    this.calls++;
    if (this.failNext) { const c = this.failNext; this.failNext = null; throw new Error(`Smart contract panicked: ${c}`); }
    const q = parseQuote(fromHex(a.quote));
    verifyEventLog(a.event_log, q.report.rtmr[3]);
    const xp = fromHex(a.x25519, 32), ep = fromHex(a.ed25519, 32);
    const want = reportData(xp, ep, registrationNonce(CONTRACT));
    if (toHex(q.report.reportData) !== toHex(want)) throw new Error("Smart contract panicked: E_REPORT_DATA");
    const kh = toHex(keyHash(xp, ep));
    const prev = this.instances.get(kh);
    this.instances.set(kh, { ed: ep, next: prev?.next ?? 0 });
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
  async anchorCount() { return this.anchors.length; }
  async getAnchor(id: number) { return this.anchors[id] ?? null; }
}

function setup() {
  const root = MockRoot.generate();
  const attester = new MockTdxAttester({ root, composeBytes: COMPOSE });
  const keys = RouterKeys.generate();
  const receipts = new ReceiptLog();
  const chain = new FakeChain();
  const lines: string[] = [];
  const anchorer = new Anchorer({ chain, attester, keys, receipts, composeBytes: COMPOSE, log: new Logger("plr-router", (l) => lines.push(l)) });
  const issue = (n: number) => {
    const out: Receipt[] = [];
    for (let i = 0; i < n; i++) {
      out.push(receipts.issue({ th: randomBytes(32), reqHash: randomBytes(32), respHash: randomBytes(32), composeHash: randomBytes(32), keyHash: keys.keyHash, sign: (r) => keys.signReceipt(r), nowMs: Date.now() }).receipt);
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
    expect(t.lines.some((l) => l.startsWith("plr-router: registered key_hash="))).toBe(true);
  });

  it("failure → keeps state 'failed' and logs only the code", async () => {
    const t = setup();
    t.chain.failNext = "E_COMPOSE_NOT_ALLOWED";
    expect(await t.anchorer.register()).toBe(false);
    expect(t.anchorer.state).toBe("failed");
    expect(t.anchorer.lastError).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(t.lines).toEqual(["plr-router: registration_failed code=E_COMPOSE_NOT_ALLOWED"]);
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
      expect(verifyMerkleProof(receiptLeaf(r), p.index, p.count, p.proof.map((h) => fromHex(h, 32)), fromHex(anchor.root, 32))).toBe(true);
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
    await t.anchorer.anchorOnce(); // anchored on chain, but the router saw an error
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

describe("ReceiptLog", () => {
  it("rejects non-contiguous anchors", () => {
    const t = setup();
    t.issue(3);
    expect(() => t.receipts.markAnchored({ anchorId: 0, firstSeq: 1, count: 1, root: new Uint8Array(32) })).toThrow();
    expect(() => t.receipts.markAnchored({ anchorId: 0, firstSeq: 0, count: 4, root: new Uint8Array(32) })).toThrow();
  });
});

// Regression (review "anchor_receipts storage is paid by the contract"): every anchor carries a storage deposit
// (refunded in excess by the contract); if the chain still reports E_DEPOSIT, the router re-registers, which
// tops up the instance's prepaid anchor credit, and the batch stays pending until it succeeds.
describe("anchor storage deposit", () => {
  const nearEnv = {
    PLR_TDX_SOCKET: "/tmp/q.sock",
    PLR_APP_COMPOSE_PATH: "/tmp/app-compose.json",
    PLR_NEAR_RPC: "http://127.0.0.1:3030",
    PLR_REGISTRY: "registry.test.near",
    PLR_OPERATOR_ID: "operator.test.near",
    PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64),
  };

  it("PLR_ANCHOR_DEPOSIT defaults to 0.01 NEAR and is strictly validated", () => {
    expect(loadConfig(nearEnv).near?.anchorDeposit).toBe(BigInt(DEFAULT_ANCHOR_DEPOSIT));
    expect(BigInt(DEFAULT_ANCHOR_DEPOSIT)).toBeGreaterThan(0n);
    expect(loadConfig({ ...nearEnv, PLR_ANCHOR_DEPOSIT: "5" }).near?.anchorDeposit).toBe(5n);
    // Malformed ⇒ registration (and anchoring) disabled, fail closed.
    for (const bad of ["-1", "1e3", "0x10", "1".repeat(41)]) {
      const c = loadConfig({ ...nearEnv, PLR_ANCHOR_DEPOSIT: bad });
      expect(c.near, bad).toBeNull();
      expect(c.nearConfigError, bad).toBe(true);
    }
    expect(ROUTER_ENV_ALLOWLIST).toContain("PLR_ANCHOR_DEPOSIT");
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
    await new Promise((r) => setTimeout(r, 50)); // the re-registration is scheduled immediately
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
