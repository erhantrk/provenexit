// EvmRegistry (SPEC-CHAINS §2, §3, §9) against an in-process fake node with the PlrRegistry rules.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { encodeErrorResult } from "viem";
import { PlrError, keyHash, toHex } from "@plr/shared";
import { EvmRegistry, EvmRevertError, evmContractId, evmRevertName, parseEvmContractId, plrCodeOfRevert, PLR_REGISTRY_ABI } from "../../src/chains/evm.js";
import { startFakeNode, type FakeNode } from "./evm-fake-node.js";

const CHAIN_ID = 10143;
const REGISTRY = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const CID = `evm:${CHAIN_ID}:${REGISTRY}`;
const h = (b: number) => b.toString(16).padStart(2, "0").repeat(32);

describe("EVM identifiers", () => {
  it("contractId format", () => {
    expect(evmContractId(CHAIN_ID, REGISTRY.toUpperCase().replace("0X", "0x"))).toBe(CID);
    expect(parseEvmContractId(CID)).toEqual({ chainId: CHAIN_ID, address: REGISTRY });
    for (const bad of [
      `evm:0:${REGISTRY}`, `evm:01:${REGISTRY}`, `evm:${CHAIN_ID}:${REGISTRY.toUpperCase()}`, `evm:${CHAIN_ID}:0x1234`,
      `stellar:${REGISTRY}`, `evm:${CHAIN_ID}:${REGISTRY}x`, `evm:99999999999999999:${REGISTRY}`, 5, null,
    ]) {
      expect(parseEvmContractId(bad)).toBeNull();
    }
    expect(() => evmContractId(0, REGISTRY)).toThrow(PlrError);
    expect(() => evmContractId(1, "0x12")).toThrow(PlrError);
  });
  it("revert names map to PLR codes", () => {
    expect(plrCodeOfRevert("E_REPORT_DATA")).toBe("E_REPORT_DATA");
    expect(plrCodeOfRevert("E_UNAUTHORIZED")).toBe("E_BAD_INPUT");
    const e = new EvmRevertError("E_SEQ");
    expect(e).toBeInstanceOf(PlrError);
    expect(e.code).toBe("E_SEQ");
    expect(e.revert).toBe("E_SEQ");
    expect(evmRevertName(new Error("x"))).toBeNull();
    expect(encodeErrorResult({ abi: PLR_REGISTRY_ABI, errorName: "E_SEQ" })).toMatch(/^0x[0-9a-f]{8}$/);
  });
});

describe("EvmRegistry", () => {
  let node: FakeNode;
  const owner = privateKeyToAccount(generatePrivateKey()).address.toLowerCase();
  const op = privateKeyToAccount(generatePrivateKey()).address.toLowerCase();
  const x = new Uint8Array(32).fill(1);
  const ed = new Uint8Array(32).fill(2);
  const kh = toHex(keyHash(x, ed));
  const reader = (o: Partial<ConstructorParameters<typeof EvmRegistry>[0]> = {}) => new EvmRegistry({ rpcUrl: node.url, contractId: CID, timeoutMs: 2000, ...o });

  beforeEach(async () => {
    node = await startFakeNode({ chainId: CHAIN_ID, address: REGISTRY, owner, rootP256: `0x${"ab".repeat(64)}` });
    node.model.instances.set(`0x${kh}`, {
      composeHash: `0x${h(0x11)}`, osMeasurement: `0x${h(0x22)}`, x25519: `0x${toHex(x)}`, ed25519: `0x${toHex(ed)}`, operator: op,
      registeredAtMs: BigInt(Date.now() - 1000), expiresAtMs: BigInt(Date.now() + 3_600_000), nextSeq: 4n,
    });
    node.model.quotes.set(`0x${kh}`, `0x${"04000200810000".padEnd(1656, "0")}`);
    node.model.operators.set(op, "org-a");
    node.model.compose.add(`0x${h(0x11)}`);
  });
  afterEach(async () => {
    await node.close();
  });

  it("is tier B with the SPEC-CHAINS §3 contract id", () => {
    const r = reader();
    expect(r.chain).toBe("evm");
    expect(r.verifiesOnChain).toBe(false);
    expect(r.contractId).toBe(CID);
    expect(new EvmRegistry({ rpcUrl: node.url, chainId: CHAIN_ID, address: REGISTRY.replace("5fbdb", "5FBDB") }).contractId).toBe(CID);
  });

  it("RPC URL and option checks", () => {
    expect(() => new EvmRegistry({ rpcUrl: "http://10.0.0.1:8545", contractId: CID })).toThrow(PlrError); // plain http to a remote host
    expect(() => new EvmRegistry({ rpcUrl: "https://u:p@rpc.example", contractId: CID })).toThrow(PlrError);
    expect(() => new EvmRegistry({ rpcUrl: "ws://127.0.0.1:1", contractId: CID })).toThrow(PlrError);
    expect(new EvmRegistry({ rpcUrl: "https://testnet-rpc.monad.xyz", contractId: CID }).rpcUrl).toBe("https://testnet-rpc.monad.xyz/");
    expect(() => reader({ contractId: "evm:1:0x12" })).toThrow(PlrError);
    expect(() => reader({ chainId: 1 })).toThrow(PlrError); // disagrees with contractId
    expect(() => new EvmRegistry({ rpcUrl: node.url, chainId: 1, address: `0x${"00".repeat(20)}` })).toThrow(PlrError);
    expect(() => reader({ timeoutMs: 0 })).toThrow(PlrError);
  });

  it("reads policy, root and the live instance (org looked up live)", async () => {
    const r = reader();
    expect(await r.getRoot()).toEqual({ kind: "MOCK", p256: "ab".repeat(64) });
    expect(await r.isComposeAllowed(h(0x11))).toBe(true);
    expect(await r.isOsAllowed(h(0x22))).toBe(false);
    expect(await r.isComposeAllowed("00".repeat(32))).toBe(false);
    expect(await r.isComposeAllowed("XYZ")).toBe(false);
    const inst = await r.getInstance(kh);
    expect(inst).toMatchObject({ compose_hash: h(0x11), os_measurement: h(0x22), x25519: toHex(x), ed25519: toHex(ed), operator: op, org_id: "org-a", next_seq: 4 });
    node.model.operators.set(op, "org-b");
    expect((await r.getInstance(kh))?.org_id).toBe("org-b");
    // SPEC-CHAINS §1: a revoked operator's instances are not accepted (the owner cuts a rogue operator off at once)
    node.model.operators.delete(op);
    expect(await r.getInstance(kh)).toBeNull();
    expect(await r.getOperator(op)).toBeNull();
    expect(await r.getInstance(h(0x33))).toBeNull();
    expect(await r.getInstance("nothex")).toBeNull();
    expect(await r.getOwner()).toBe(owner);
  });

  it("expired instances read as null", async () => {
    let now = Date.now();
    const r = reader({ now: () => now });
    expect(await r.getInstance(kh)).not.toBeNull();
    now += 3_600_001;
    expect(await r.getInstance(kh)).toBeNull();
  });

  it("returns the on-chain registration quote, ignoring the offered one", async () => {
    const r = reader();
    const q = await r.getRegistrationQuote(kh, new Uint8Array([1, 2, 3]));
    expect(q).not.toBeNull();
    expect(q!.length).toBe(828);
    expect(q![0]).toBe(4);
    expect(await r.getRegistrationQuote(h(0x44), new Uint8Array(828))).toBeNull();
    expect(await r.getRegistrationQuote("bad")).toBeNull();
  });

  it("anchors carry the stored signature; unknown ids are null", async () => {
    node.model.anchors.push({ keyHash: `0x${kh}`, root: `0x${h(0x55)}`, firstSeq: 0n, count: 4n, atMs: 1234n, sig: `0x${"cd".repeat(64)}` });
    const r = reader();
    expect(await r.anchorCount()).toBe(1);
    expect(await r.getAnchor(0)).toEqual({ id: 0, key_hash: kh, root: h(0x55), first_seq: 0, count: 4, at_ms: 1234, sig: "cd".repeat(64) });
    expect(await r.getAnchor(1)).toBeNull();
    expect(await r.getAnchor(-1)).toBeNull();
    node.model.anchors[0]!.sig = "0xcdcd";
    await expect(r.getAnchor(0)).rejects.toThrow(/malformed sig/);
  });

  it("fails closed when the node is on another chain or the address is not this registry", async () => {
    await node.close();
    node = await startFakeNode({ chainId: CHAIN_ID, address: REGISTRY, owner, rootP256: `0x${"ab".repeat(64)}`, reportedChainId: 1 });
    await expect(reader().getRoot()).rejects.toThrow(/another chain/);
    const other = "0x00000000000000000000000000000000000000aa";
    await node.close();
    node = await startFakeNode({ chainId: CHAIN_ID, address: other, owner, rootP256: `0x${"ab".repeat(64)}` });
    await expect(reader().getRoot()).rejects.toThrow();
    await expect(reader().isComposeAllowed(h(0x11))).rejects.toThrow();
  });

  it("identity is retried after a failure, then cached", async () => {
    let fail = true;
    node.override = (m) => (m === "eth_chainId" && fail ? { jsonrpc: "2.0", id: 1, error: { code: -32000, message: "down" } } : undefined);
    const r = reader();
    await expect(r.getRoot()).rejects.toThrow();
    fail = false;
    expect((await r.getRoot()).kind).toBe("MOCK");
    const n = node.calls.get("eth_chainId");
    await r.getRoot();
    expect(node.calls.get("eth_chainId")).toBe(n);
  });

  it("malformed or failing replies reject (never answer from garbage)", async () => {
    const r = reader();
    await r.getRoot(); // identity ok
    node.override = (m) => (m === "eth_call" ? { jsonrpc: "2.0", id: 1, result: "0x1234" } : undefined);
    await expect(r.getInstance(kh)).rejects.toThrow();
    await expect(r.isComposeAllowed(h(0x11))).rejects.toThrow();
    node.override = (m) => (m === "eth_call" ? { jsonrpc: "2.0", id: 1, error: { code: 3, message: "execution reverted", data: encodeErrorResult({ abi: PLR_REGISTRY_ABI, errorName: "E_SEQ" }) } } : undefined);
    await expect(r.getAnchor(0)).rejects.toThrow(/reverted E_SEQ/);
    node.override = (m) => (m === "eth_call" ? "hang" : undefined);
    const t0 = Date.now();
    await expect(reader({ timeoutMs: 200 }).getRoot()).rejects.toThrow();
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("a too-large reply is refused", async () => {
    const r = reader();
    await r.getRoot();
    node.override = (m) => (m === "eth_call" ? { jsonrpc: "2.0", id: 1, result: `0x${"00".repeat(300_000)}` } : undefined);
    await expect(r.getRegistrationQuote(kh)).rejects.toThrow();
  });
});
