import { describe, it, expect, afterEach } from "vitest";
import { createServer } from "node:net";
import { PlrError, verifyAttestation, MockVerifier, fromHex } from "@plr/shared";
import { NearRegistry, PrivateClient } from "../src/index.js";
import { makeFakeRouter } from "./fake-router.js";
import { registryHandler, startFakeRpc, type FakeRpc } from "./fake-rpc.js";

let rpcs: FakeRpc[] = [];
afterEach(async () => {
  for (const r of rpcs) await r.close();
  rpcs = [];
});

async function setup() {
  const router = makeFakeRouter();
  const rpc = await startFakeRpc(registryHandler(router.registry));
  rpcs.push(rpc);
  const reg = new NearRegistry({ rpcUrl: rpc.url, contractId: "registry.test.near", timeoutMs: 1_000 });
  return { router, rpc, reg };
}

async function freePort(): Promise<number> {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => ok(port));
    });
  });
}

describe("NearRegistry", () => {
  it("reads root, allowlists, instance and anchor via view calls", async () => {
    const { router, rpc, reg } = await setup();
    expect(reg.chain).toBe("near");
    expect(reg.contractId).toBe("registry.test.near");
    expect(await reg.getRoot()).toEqual(await router.registry.getRoot());
    expect(await reg.isComposeAllowed(router.composeHash)).toBe(true);
    expect(await reg.isOsAllowed(router.osHash)).toBe(true);
    expect(await reg.isComposeAllowed("ab".repeat(32))).toBe(false);
    expect(await reg.getInstance(router.keyHash)).toEqual(router.record);
    expect(await reg.getInstance("cd".repeat(32))).toBeNull();
    expect(await reg.getAnchor(0)).toBeNull();
    expect(rpc.calls.map((c) => c.method)).toEqual([
      "get_root", "is_compose_allowed", "is_os_allowed", "is_compose_allowed", "get_instance", "get_instance", "get_anchor",
    ]);
    expect(rpc.calls[1]!.args).toEqual({ hash: router.composeHash });
    expect(rpc.calls[4]!.args).toEqual({ key_hash: router.keyHash });
    expect(rpc.calls[6]!.args).toEqual({ id: 0 });
    expect(rpc.calls.every((c) => c.finality === "optimistic")).toBe(true);
  });

  it("never queries the chain for malformed or zero hashes", async () => {
    const { rpc, reg } = await setup();
    expect(await reg.isComposeAllowed("00".repeat(32))).toBe(false);
    expect(await reg.isOsAllowed("AB".repeat(32))).toBe(false);
    expect(await reg.getInstance("0x" + "ab".repeat(31))).toBeNull();
    expect(await reg.getAnchor(-1)).toBeNull();
    expect(rpc.calls).toHaveLength(0);
  });

  it("accepts u64 fields encoded as decimal strings (near-sdk U64)", async () => {
    const router = makeFakeRouter();
    const rpc = await startFakeRpc(async (m) => {
      if (m === "get_instance") return { ...router.record, registered_at_ms: "1", expires_at_ms: String(router.record.expires_at_ms), next_seq: "7" };
      if (m === "get_anchor") return { id: "0", key_hash: router.keyHash, root: "ee".repeat(32), first_seq: "0", count: "3", at_ms: 5 };
      throw new Error("x");
    });
    rpcs.push(rpc);
    const reg = new NearRegistry({ rpcUrl: rpc.url, contractId: "registry.test.near" });
    expect((await reg.getInstance(router.keyHash))!.next_seq).toBe(7);
    expect(await reg.getAnchor(0)).toEqual({ id: 0, key_hash: router.keyHash, root: "ee".repeat(32), first_seq: 0, count: 3, at_ms: 5 });
  });

  it("rejects malformed replies", async () => {
    const replies: [string, unknown][] = [
      ["get_root", { kind: "OTHER", p256: "ab".repeat(64) }],
      ["get_root", { kind: "MOCK", p256: "AB".repeat(64) }],
      ["is_compose_allowed", "true"],
      ["is_compose_allowed", 1],
      ["get_instance", { compose_hash: "zz" }],
      ["get_instance", []],
    ];
    for (const [method, value] of replies) {
      const rpc = await startFakeRpc(async () => value);
      rpcs.push(rpc);
      const reg = new NearRegistry({ rpcUrl: rpc.url, contractId: "registry.test.near" });
      const call =
        method === "get_root" ? reg.getRoot() : method === "is_compose_allowed" ? reg.isComposeAllowed("ab".repeat(32)) : reg.getInstance("ab".repeat(32));
      await expect(call, `${method} ${JSON.stringify(value)}`).rejects.toThrow();
    }
  });

  it("surfaces contract panics, JSON-RPC errors, HTTP errors, garbage results and timeouts", async () => {
    const { rpc, reg } = await setup();
    rpc.raw = () => ({ status: 200, body: { jsonrpc: "2.0", id: "1", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_ACCOUNT" }, message: "x", code: -32000 } } });
    await expect(reg.getRoot()).rejects.toThrow();
    rpc.raw = () => ({ status: 200, body: { jsonrpc: "2.0", id: "1", result: { result: [300], logs: [] } } });
    await expect(reg.getRoot()).rejects.toThrow();
    rpc.raw = () => ({ status: 200, body: { jsonrpc: "2.0", id: "1", result: { result: [...Buffer.from("not json")], logs: [] } } });
    await expect(reg.getRoot()).rejects.toThrow();
    rpc.raw = () => ({ status: 503, body: {} });
    await expect(reg.getRoot()).rejects.toThrow();
    rpc.raw = () => "hang";
    const t0 = Date.now();
    await expect(reg.getRoot()).rejects.toThrow(/timeout/);
    expect(Date.now() - t0).toBeLessThan(5_000);
    rpc.raw = undefined;
    const missing = await startFakeRpc(async () => { throw new Error("MethodResolveError"); });
    rpcs.push(missing);
    await expect(new NearRegistry({ rpcUrl: missing.url, contractId: "a.near" }).getRoot()).rejects.toThrow();
  });

  it("validates its configuration", () => {
    expect(() => new NearRegistry({ rpcUrl: "nope", contractId: "a.near" })).toThrow(PlrError);
    expect(() => new NearRegistry({ rpcUrl: "file:///x", contractId: "a.near" })).toThrow(PlrError);
    expect(() => new NearRegistry({ rpcUrl: "http://x", contractId: "Bad..Id" })).toThrow(PlrError);
    expect(() => new NearRegistry({ rpcUrl: "http://x", contractId: "a" })).toThrow(PlrError);
  });

  it("drives verifyAttestation end to end; an unreachable RPC maps to E_REGISTRY_UNAVAILABLE", async () => {
    const { router, reg } = await setup();
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: reg, trustedRoot: router.root.publicKey, fetch: router.fetch });
    const res = await c.chat({ messages: [{ role: "user", content: "hi" }] });
    expect(res.content.length).toBeGreaterThan(0);

    const dead = new NearRegistry({ rpcUrl: `http://127.0.0.1:${await freePort()}`, contractId: "registry.test.near", timeoutMs: 2_000 });
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const bundleRes = await router.fetch(`http://router.test/v1/attestation?nonce=${Buffer.from(nonce).toString("hex")}`);
    const err = await verifyAttestation({
      bundle: (await bundleRes.json()) as never, nonce, verifier: new MockVerifier(router.root.publicKey),
      registry: dead, trustedRoot: fromHex(Buffer.from(router.root.publicKey).toString("hex"), 64),
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PlrError);
    expect((err as PlrError).code).toBe("E_REGISTRY_UNAVAILABLE");
  });
});
