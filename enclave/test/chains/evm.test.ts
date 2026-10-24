// EVM tier-B writer (SPEC-CHAINS §4, §9) against an in-process fake node with the PlrRegistry rules.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  MockRoot, MockTdxAttester, PlrError, anchorMessage, fromHex, keyHash, registrationReportData, toHex, utf8,
} from "@plr/shared";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { EvmRegistryWriter, EvmRevertError, isEvmSecretKey, isNonceConflict, loadEvm, plrCodeOfRevert } from "../../src/chains/evm.js";
import { startFakeNode, type FakeNode } from "./evm-fake-node.js";

const CHAIN_ID = 31337;
const REGISTRY = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const COMPOSE = '{"plr":"evm-test"}';

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PlrError);
    return (e as PlrError).code;
  }
  return "NO_THROW";
}

describe("loadEvm (PLR_EVM_*)", () => {
  const key = generatePrivateKey().slice(2);
  it("none set ⇒ null; all set ⇒ config", () => {
    expect(loadEvm({})).toBeNull();
    const c = loadEvm({ PLR_EVM_RPC: "http://127.0.0.1:8545", PLR_EVM_REGISTRY: REGISTRY.toUpperCase().replace("0X", "0x"), PLR_EVM_KEY: key, PLR_EVM_CHAIN_ID: "10143" });
    expect(c).toEqual({ rpcUrl: "http://127.0.0.1:8545", registry: REGISTRY, key, chainId: 10143 });
    expect(loadEvm({ PLR_EVM_RPC: "https://rpc.example", PLR_EVM_VPN_REGISTRY: REGISTRY, PLR_EVM_KEY: `0x${key}` }, "PLR_EVM_VPN_REGISTRY")?.chainId).toBeNull();
  });
  it("partial or invalid ⇒ E_BAD_INPUT", () => {
    const ok = { PLR_EVM_RPC: "http://127.0.0.1:8545", PLR_EVM_REGISTRY: REGISTRY, PLR_EVM_KEY: key };
    for (const env of [
      { PLR_EVM_RPC: ok.PLR_EVM_RPC },
      { ...ok, PLR_EVM_KEY: "" },
      { ...ok, PLR_EVM_RPC: "ftp://x" },
      { ...ok, PLR_EVM_RPC: "not a url" },
      { ...ok, PLR_EVM_REGISTRY: "0x1234" },
      { ...ok, PLR_EVM_REGISTRY: `0x${"00".repeat(20)}` },
      { ...ok, PLR_EVM_KEY: "zz".repeat(32) },
      { ...ok, PLR_EVM_KEY: "00".repeat(32) }, // not a valid secp256k1 scalar
      { ...ok, PLR_EVM_CHAIN_ID: "0" },
      { ...ok, PLR_EVM_CHAIN_ID: "-1" },
    ]) {
      expect(() => loadEvm(env)).toThrow(PlrError);
    }
  });
  it("key validation", () => {
    expect(isEvmSecretKey(key)).toBe(true);
    expect(isEvmSecretKey(`0x${key}`)).toBe(true);
    expect(isEvmSecretKey("ff".repeat(32))).toBe(false); // ≥ curve order
    expect(isEvmSecretKey(123)).toBe(false);
  });
});

describe("revert mapping", () => {
  it("maps contract errors to PLR codes", () => {
    expect(plrCodeOfRevert("E_SEQ")).toBe("E_SEQ");
    expect(plrCodeOfRevert("E_OPERATOR_UNAPPROVED")).toBe("E_OPERATOR_UNAPPROVED");
    expect(plrCodeOfRevert("E_UNAUTHORIZED")).toBe("E_BAD_INPUT");
    expect(plrCodeOfRevert("E_ZERO_HASH")).toBe("E_BAD_INPUT");
    expect(isNonceConflict(new Error("nonce too low"))).toBe(true);
    expect(isNonceConflict(new Error("insufficient funds"))).toBe(false);
  });
});

describe("EvmRegistryWriter", () => {
  let node: FakeNode;
  let key: `0x${string}`;
  let operator: string;
  let owner: string;
  const root = MockRoot.generate();
  const xs = x25519.utils.randomSecretKey();
  const es = ed25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const ep = ed25519.getPublicKey(es);
  const kh = toHex(keyHash(xp, ep));
  const attester = new MockTdxAttester({ root, composeBytes: utf8(COMPOSE) });
  const contractId = `evm:${CHAIN_ID}:${REGISTRY}`;

  const writer = (o: Partial<ConstructorParameters<typeof EvmRegistryWriter>[0]> = {}) =>
    new EvmRegistryWriter({ rpcUrl: node.url, registry: REGISTRY, key, chainId: CHAIN_ID, pollMs: 10, timeoutMs: 2000, confirmTimeoutMs: 5000, random: () => 0, ...o });
  const regArgs = async (op = operator, cid = contractId) => ({
    quote: toHex((await attester.getQuote(registrationReportData(xp, ep, cid, op))).quote),
    event_log: [],
    app_compose: COMPOSE,
    x25519: toHex(xp),
    ed25519: toHex(ep),
  });
  const sigOf = (first: number, count: number, root32: Uint8Array) =>
    toHex(ed25519.sign(anchorMessage({ contractId, keyHash: fromHex(kh, 32), root: root32, firstSeq: BigInt(first), count: BigInt(count) }), es));

  beforeEach(async () => {
    key = generatePrivateKey();
    operator = privateKeyToAccount(key).address.toLowerCase();
    owner = privateKeyToAccount(generatePrivateKey()).address.toLowerCase();
    node = await startFakeNode({ chainId: CHAIN_ID, address: REGISTRY, owner, rootP256: `0x${toHex(root.publicKey)}` });
  });
  afterEach(async () => {
    await node.close();
  });

  it("identifiers per SPEC-CHAINS §3", () => {
    const w = writer({ registry: REGISTRY.replace("5fbdb", "5FBDB") });
    expect(w.contractId).toBe(contractId);
    expect(w.operatorId).toBe(operator);
    expect(w.operatorId).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it("rejects bad options", () => {
    expect(() => writer({ key: "00".repeat(32) })).toThrow(PlrError);
    expect(() => writer({ registry: "0x12" })).toThrow(PlrError);
    expect(() => writer({ chainId: 0 })).toThrow(PlrError);
    expect(() => writer({ rpcUrl: "file:///etc/passwd" })).toThrow(PlrError);
    expect(() => writer({ confirmTimeoutMs: 0 })).toThrow(PlrError);
  });

  it("registers (quote stored on-chain), reads the operator back, keeps next_seq on refresh", async () => {
    node.model.operators.set(operator, "org-a");
    const w = writer();
    const args = await regArgs();
    await w.registerInstance(args);
    expect(await w.getInstanceOperator(kh)).toBe(operator);
    expect(await w.getInstanceNextSeq(kh)).toBe(0);
    const inst = node.model.instances.get(`0x${kh}`)!;
    expect(inst.composeHash).toBe(`0x${toHex(sha256(utf8(COMPOSE)))}`);
    expect(inst.osMeasurement).toBe(`0x${toHex(attester.osMeasurement)}`);
    expect(node.model.quotes.get(`0x${kh}`)).toBe(`0x${args.quote}`);

    node.model.compose.add(inst.composeHash);
    node.model.os.add(inst.osMeasurement);
    const r = new Uint8Array(32).fill(7);
    expect(await w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 0, count: 2, sig: sigOf(0, 2, r) })).toBe(0);
    const args2 = await regArgs(); // fresh quote of the same boot
    await w.registerInstance(args2);
    expect(await w.getInstanceNextSeq(kh)).toBe(2);
    expect(node.model.quotes.get(`0x${kh}`)).toBe(`0x${args2.quote}`);
    expect(await w.getInstanceOperator("11".repeat(32))).toBeNull();
    expect(await w.getInstanceNextSeq("11".repeat(32))).toBeNull();
  });

  it("maps contract reverts to PLR codes (unapproved operator)", async () => {
    const w = writer();
    const p = w.registerInstance(await regArgs());
    await expect(p).rejects.toBeInstanceOf(EvmRevertError);
    expect(await codeOf(w.registerInstance(await regArgs()))).toBe("E_OPERATOR_UNAPPROVED");
    expect(node.calls.get("eth_sendRawTransaction") ?? 0).toBe(0); // simulated first, never sent
  });

  it("never submits a quote bound to another operator or registry", async () => {
    node.model.operators.set(operator, "org-a");
    const w = writer();
    expect(await codeOf(w.registerInstance(await regArgs(owner)))).toBe("E_REPORT_DATA");
    expect(await codeOf(w.registerInstance(await regArgs(operator, `evm:1:${REGISTRY}`)))).toBe("E_REPORT_DATA");
    expect(await codeOf(w.registerInstance({ ...(await regArgs()), x25519: "zz" }))).toBe("E_BAD_INPUT");
    expect(node.calls.get("eth_sendRawTransaction") ?? 0).toBe(0);
  });

  it("anchors contiguously; E_SEQ / E_COMPOSE_NOT_ALLOWED / E_INSTANCE_NOT_REGISTERED surface as codes", async () => {
    node.model.operators.set(operator, "org-a");
    const w = writer();
    const r = new Uint8Array(32).fill(1);
    expect(await codeOf(w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 0, count: 1, sig: sigOf(0, 1, r) }))).toBe("E_INSTANCE_NOT_REGISTERED");
    await w.registerInstance(await regArgs());
    const inst = node.model.instances.get(`0x${kh}`)!;
    expect(await codeOf(w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 0, count: 1, sig: sigOf(0, 1, r) }))).toBe("E_COMPOSE_NOT_ALLOWED");
    node.model.compose.add(inst.composeHash);
    node.model.os.add(inst.osMeasurement);
    expect(await w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 0, count: 3, sig: sigOf(0, 3, r) })).toBe(0);
    expect(await codeOf(w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 0, count: 1, sig: sigOf(0, 1, r) }))).toBe("E_SEQ");
    expect(await w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 3, count: 1, sig: sigOf(3, 1, r) })).toBe(1);
    expect(await w.anchorCount()).toBe(2);
    expect(await w.getAnchor(1)).toEqual({ id: 1, key_hash: kh, root: toHex(r), first_seq: 3, count: 1 });
    expect(await w.getAnchor(5)).toBeNull();
    expect(node.model.anchors[1]!.sig).toBe(`0x${sigOf(3, 1, r)}`);
    expect(await codeOf(w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 4, count: 0, sig: sigOf(4, 0, r) }))).toBe("E_BAD_INPUT");
    expect(await codeOf(w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 4, count: 1, sig: "ab" }))).toBe("E_BAD_INPUT");
  });

  it("retries a nonce conflict with a fresh nonce", async () => {
    node.model.operators.set(operator, "org-a");
    let failed = 0;
    node.override = (m) => {
      if (m === "eth_sendRawTransaction" && failed < 2) {
        failed++;
        return { jsonrpc: "2.0", id: 1, error: { code: -32000, message: "nonce too low" } };
      }
      return undefined;
    };
    await writer().registerInstance(await regArgs());
    expect(failed).toBe(2);
    expect(node.model.instances.has(`0x${kh}`)).toBe(true);
  });

  it("serializes concurrent sends of one writer (distinct nonces)", async () => {
    node.model.operators.set(operator, "org-a");
    const w = writer();
    await w.registerInstance(await regArgs());
    const inst = node.model.instances.get(`0x${kh}`)!;
    node.model.compose.add(inst.composeHash);
    node.model.os.add(inst.osMeasurement);
    const r = new Uint8Array(32).fill(3);
    const results = await Promise.all([
      w.registerInstance(await regArgs()),
      w.anchorReceipts({ key_hash: kh, root: toHex(r), first_seq: 0, count: 1, sig: sigOf(0, 1, r) }),
      w.registerInstance(await regArgs()),
    ]);
    expect(results[1]).toBe(0);
    expect(node.txs.map((t) => t.nonce)).toEqual([0, 1, 2, 3]);
  });

  it("refuses a node on another chain and a contract that is not this registry", async () => {
    node.model.operators.set(operator, "org-a");
    expect(await codeOf(writer({ chainId: 1 }).registerInstance(await regArgs(operator, `evm:1:${REGISTRY}`)))).toBe("E_BAD_INPUT");
    const other = "0x00000000000000000000000000000000000000aa";
    expect(await codeOf(writer({ registry: other }).registerInstance(await regArgs(operator, `evm:${CHAIN_ID}:${other}`)))).toBe("E_REGISTRY_UNAVAILABLE");
    expect(node.calls.get("eth_sendRawTransaction") ?? 0).toBe(0);
  });

  it("create() asks the node for the chain id", async () => {
    const w = await EvmRegistryWriter.create({ rpcUrl: node.url, registry: REGISTRY, key });
    expect(w.contractId).toBe(contractId);
  });

  it("bounded waits: a hanging RPC fails with E_REGISTRY_UNAVAILABLE; errors never carry the key", async () => {
    node.model.operators.set(operator, "org-a");
    node.override = (m) => (m === "eth_call" ? "hang" : undefined);
    const t0 = Date.now();
    let err: unknown;
    try {
      await writer({ timeoutMs: 300 }).registerInstance(await regArgs());
    } catch (e) {
      err = e;
    }
    expect((err as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(String((err as Error).message)).not.toContain(key.slice(2));
    expect(String((err as Error).stack)).not.toContain(key.slice(2));
  });

  it("a receipt that never comes is bounded by confirmTimeoutMs", async () => {
    node.model.operators.set(operator, "org-a");
    node.override = (m) => (m === "eth_getTransactionReceipt" ? { jsonrpc: "2.0", id: 1, result: null } : undefined);
    const t0 = Date.now();
    expect(await codeOf(writer({ confirmTimeoutMs: 400 }).registerInstance(await regArgs()))).toBe("E_REGISTRY_UNAVAILABLE");
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});
