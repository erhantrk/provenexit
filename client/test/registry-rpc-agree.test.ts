// Several RPC endpoints: every registry query goes to all of them and is used only if all give the same answer.
import { describe, it, expect, afterEach } from "vitest";
import { CHECKS, ERROR_CODES, PlrError, toHex } from "@plr/shared";
import {
  ConfigError,
  NearRegistry,
  NearRegistryError,
  REGISTRY_CODE_LINE,
  RegistryRpcDisagreeError,
  checkLines,
  isRegistryRefusal,
  isRegistryRpcDisagreeError,
  loadVpnConfig,
  parseRpcUrls,
  runCli,
} from "../src/index.js";
import { startFakeExit } from "./fake-exit.js";
import { FAKE_CODE_HASH, registryHandler, startFakeRpc, type ViewHandler } from "./fake-rpc.js";

const OTHER_HASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const REGISTRY = "vpnregistry.test.near";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

/**
 * One fake exit and `n` fake RPC endpoints that all serve its registry. `lie[i]` replaces the answer of endpoint
 * `i` for the methods it names (the endpoint that "disagrees").
 */
async function stack(n: number, lie: Record<number, Record<string, unknown>> = {}) {
  const X = await startFakeExit();
  const honest = registryHandler(X.registry);
  const rpcs = [];
  for (let i = 0; i < n; i++) {
    const answers = lie[i];
    const handler: ViewHandler = answers === undefined ? honest : async (m, a) => (Object.hasOwn(answers, m) ? answers[m] : honest(m, a));
    rpcs.push(await startFakeRpc(handler));
  }
  closers.push(X.close, ...rpcs.map((r) => r.close));
  const rpcUrl = rpcs.map((r) => r.url).join(",");
  const env: Record<string, string> = { PLR_VPN_URL: X.url, PLR_NEAR_RPC: rpcUrl, PLR_VPN_REGISTRY: REGISTRY, PLR_TRUSTED_ROOT: toHex(X.root.publicKey) };
  return { X, rpcs, rpcUrl, env };
}

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s) } };
}

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined, (x: unknown) => x);

describe("parseRpcUrls (the RPC setting: one URL or a comma-separated list)", () => {
  it("accepts one URL and a list; spaces around commas are ignored", () => {
    expect(parseRpcUrls("https://a.example").map((u) => u.href)).toEqual(["https://a.example/"]);
    expect(parseRpcUrls("https://a.example, https://b.example ,http://127.0.0.1:3030").map((u) => u.href)).toEqual(["https://a.example/", "https://b.example/", "http://127.0.0.1:3030/"]);
  });

  it("refuses an empty entry, a repeated endpoint, a non-https remote host and more than five", () => {
    for (const bad of ["", "https://a.example,", ",https://a.example", "https://a.example,https://a.example/", "https://a.example,http://b.example", "https://a.example,https://u:p@b.example", [1, 2, 3, 4, 5, 6].map((i) => `https://r${i}.example`).join(",")]) {
      expect(() => parseRpcUrls(bad), bad).toThrow(PlrError);
      expect(() => new NearRegistry({ rpcUrl: bad, contractId: REGISTRY }), bad).toThrow(PlrError);
    }
  });
});

describe("NearRegistry with several RPC endpoints", () => {
  it("all agree: views answer and every endpoint was asked, in parallel, for every query", async () => {
    const { X, rpcs, rpcUrl } = await stack(3);
    // endpoints answer at different blocks: only the answer itself is compared, not the block next to it
    const bytes = [...Buffer.from(JSON.stringify(await X.registry.getRoot()), "utf8")];
    rpcs[1]!.raw = (m) => (m === "get_root" ? { status: 200, body: { jsonrpc: "2.0", id: "x", result: { result: bytes, logs: [], block_height: 987, block_hash: "2".repeat(44) } } } : undefined);
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY, codeHash: FAKE_CODE_HASH });
    expect(r.rpcUrls).toHaveLength(3);
    expect(r.rpcUrl).toBe(r.rpcUrls.join(","));
    expect((await r.getRoot()).p256).toBe(toHex(X.root.publicKey));
    expect(await r.isComposeAllowed(X.composeHash)).toBe(true);
    expect(await r.getInstance(X.keyHash)).toEqual(X.record);
    expect(r.codeHashVerified).toBe(true);
    for (const rpc of rpcs) {
      expect(rpc.accountViews).toBe(1);
      expect(rpc.calls.map((c) => c.method)).toEqual(["get_root", "is_compose_allowed", "get_instance"]);
    }
  });

  it("one endpoint gives another answer: E_REGISTRY_RPC_DISAGREE, after asking everyone a second time", async () => {
    const { X, rpcs, rpcUrl } = await stack(3, { 2: { is_compose_allowed: false } });
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY });
    await expect(r.getRoot()).resolves.toBeDefined(); // the queries they agree on still answer
    const e = await caught(r.isComposeAllowed(X.composeHash));
    expect(e).toBeInstanceOf(RegistryRpcDisagreeError);
    expect(e).toBeInstanceOf(PlrError);
    expect(isRegistryRpcDisagreeError(e)).toBe(true);
    expect(isRegistryRefusal(e)).toBe(true);
    expect((e as PlrError).code).toBe("E_REGISTRY_RPC_DISAGREE");
    expect((e as PlrError).message).toContain("E_REGISTRY_RPC_DISAGREE");
    // a client-only code: the shared list (bundled into the measured exit image) is unchanged
    expect(ERROR_CODES as readonly string[]).not.toContain("E_REGISTRY_RPC_DISAGREE");
    for (const rpc of rpcs) expect(rpc.calls.filter((c) => c.method === "is_compose_allowed")).toHaveLength(2);
  });

  it("the lying endpoint is the majority or the minority: refused either way (no vote)", async () => {
    const { X, rpcUrl } = await stack(3, { 0: { is_compose_allowed: false }, 1: { is_compose_allowed: false } });
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY });
    expect(isRegistryRpcDisagreeError(await caught(r.isComposeAllowed(X.composeHash)))).toBe(true);
  });

  it("a difference that is gone when asked again (an owner call just landed) passes", async () => {
    const { X, rpcs, rpcUrl } = await stack(2);
    let lagging = true;
    const stale = [...Buffer.from("false", "utf8")];
    rpcs[1]!.raw = (m) => {
      if (m !== "is_compose_allowed" || !lagging) return undefined;
      lagging = false;
      return { status: 200, body: { jsonrpc: "2.0", id: "x", result: { result: stale, logs: [], block_height: 1, block_hash: "1".repeat(32) } } };
    };
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY });
    expect(await r.isComposeAllowed(X.composeHash)).toBe(true);
    expect(rpcs[0]!.calls).toHaveLength(2);
  });

  it("endpoints report different code hashes: E_REGISTRY_RPC_DISAGREE (even if one is the pin), no view is sent", async () => {
    const { rpcs, rpcUrl } = await stack(2);
    rpcs[1]!.codeHash = OTHER_HASH;
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY, codeHash: FAKE_CODE_HASH });
    expect(isRegistryRpcDisagreeError(await caught(r.getRoot()))).toBe(true);
    expect(r.codeHashVerified).toBe(false);
    for (const rpc of rpcs) expect(rpc.calls).toHaveLength(0);
    // both report the same, wrong, code: that is the code-hash refusal
    rpcs[0]!.codeHash = OTHER_HASH;
    expect((await caught(r.getRoot()) as PlrError).code).toBe("E_REGISTRY_CODE_HASH");
  });

  it("one endpoint is down, hangs or answers garbage: rejects like an unreachable registry (fail closed)", async () => {
    const { rpcs, rpcUrl } = await stack(3);
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY, timeoutMs: 1500 });
    for (const broken of ["hang", { status: 200, body: { jsonrpc: "2.0", id: "x", result: { result: "nope" } } }] as const) {
      rpcs[1]!.raw = () => broken;
      const e = await caught(r.getRoot());
      expect(e).toBeInstanceOf(NearRegistryError);
      expect(e).not.toBeInstanceOf(PlrError);
    }
    await rpcs[1]!.close();
    const e = await caught(r.getRoot());
    expect(e).toBeInstanceOf(NearRegistryError);
    expect(isRegistryRefusal(e)).toBe(false);
    // the two that answered were asked; their agreement is not enough
    expect(rpcs[0]!.calls.length).toBeGreaterThan(0);
    expect(rpcs[2]!.calls.length).toBeGreaterThan(0);
  });

  it("one endpoint down and the other two differ: the disagreement is reported", async () => {
    const { rpcs, rpcUrl } = await stack(3, { 2: { get_root: { kind: "MOCK", p256: "ab".repeat(64) } } });
    await rpcs[0]!.close();
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY, timeoutMs: 3000 });
    expect(isRegistryRpcDisagreeError(await caught(r.getRoot()))).toBe(true);
  });

  it("one endpoint configured: asked once, nothing compared, errors as before", async () => {
    const { X, rpcs, rpcUrl } = await stack(1);
    const r = new NearRegistry({ rpcUrl, contractId: REGISTRY, codeHash: FAKE_CODE_HASH });
    expect(r.rpcUrls).toEqual([`${rpcUrl}/`]);
    expect(r.rpcUrl).toBe(`${rpcUrl}/`);
    expect((await r.getRoot()).p256).toBe(toHex(X.root.publicKey));
    expect(rpcs[0]!.accountViews).toBe(1);
    expect(rpcs[0]!.calls).toHaveLength(1);
    rpcs[0]!.raw = () => ({ status: 200, body: { jsonrpc: "2.0", id: "x", result: { result: "nope" } } });
    const e = await caught(r.getRoot());
    expect(e).toBeInstanceOf(NearRegistryError);
    expect(e).not.toBeInstanceOf(PlrError);
    expect(rpcs[0]!.calls).toHaveLength(2); // no second round with a single endpoint
  });
});

describe("check lines", () => {
  it("E_REGISTRY_RPC_DISAGREE fails the line whose registry query it was", () => {
    const failed = (call: Parameters<typeof checkLines>[1], state: "verified" | "unverified" | undefined) =>
      checkLines(new RegistryRpcDisagreeError(), call, { codeHash: state }).find((l) => l.status === "fail");
    expect(failed("getRoot", "verified")).toMatchObject({ name: CHECKS.ROOT, code: "E_REGISTRY_RPC_DISAGREE" });
    expect(failed("isComposeAllowed", "verified")).toMatchObject({ name: CHECKS.COMPOSE_ALLOWED, code: "E_REGISTRY_RPC_DISAGREE" });
    expect(failed("isOsAllowed", undefined)).toMatchObject({ name: CHECKS.OS_ALLOWED, code: "E_REGISTRY_RPC_DISAGREE" });
    expect(failed("getInstance", "verified")).toMatchObject({ name: CHECKS.INSTANCE, code: "E_REGISTRY_RPC_DISAGREE" });
    // the endpoints report different code hashes: the code-hash line
    expect(failed(undefined, "unverified")).toMatchObject({ name: REGISTRY_CODE_LINE, code: "E_REGISTRY_RPC_DISAGREE" });
  });
});

describe("plr vpn verify with several RPC endpoints", () => {
  it("all agree: VERIFIED; the header lists the endpoints", async () => {
    const { env, rpcs } = await stack(2);
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text).toContain(`(2 RPC endpoints that must give the same answers: ${rpcs[0]!.url}/, ${rpcs[1]!.url}/)`);
    expect(text).toContain(`  ✔ ${REGISTRY_CODE_LINE}`);
    expect(text).toContain("✔ VERIFIED");
    expect(text).not.toContain("✘");
    expect(rpcs[1]!.calls.map((c) => c.method)).toEqual(rpcs[0]!.calls.map((c) => c.method));
    expect(rpcs[1]!.calls.length).toBeGreaterThan(3);
    expect(rpcs[1]!.accountViews).toBe(rpcs[0]!.accountViews);
  });

  it("one endpoint says the compose is not allowed: REFUSED with E_REGISTRY_RPC_DISAGREE on that line", async () => {
    const { env } = await stack(2, { 1: { is_compose_allowed: false } });
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toContain(`  ✔ ${REGISTRY_CODE_LINE}`);
    expect(text).toContain(`  ✔ ${CHECKS.ROOT}`);
    expect(text).toContain(`  ✘ ${CHECKS.COMPOSE_ALLOWED}  [E_REGISTRY_RPC_DISAGREE]`);
    expect(text).toContain(`  · ${CHECKS.OS_ALLOWED}  (not checked)`);
    expect(text).toContain(`  · ${CHECKS.INSTANCE}  (not checked)`);
    expect(text).toContain("✘ REFUSED — E_REGISTRY_RPC_DISAGREE.");
    expect(text).not.toContain("✔ VERIFIED");
    expect(text.match(/✘/g)).toHaveLength(2);
  });

  it("one endpoint serves another root: REFUSED on the root line", async () => {
    const { env } = await stack(2, { 0: { get_root: { kind: "MOCK", p256: "ab".repeat(64) } } });
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(1);
    expect(t.out.join("\n")).toContain(`  ✘ ${CHECKS.ROOT}  [E_REGISTRY_RPC_DISAGREE]`);
  });

  it("endpoints report different code hashes: REFUSED on the code-hash line, the exit is not contacted", async () => {
    const { X, env, rpcs } = await stack(2);
    const before = X.stats.attestations;
    rpcs[1]!.codeHash = OTHER_HASH;
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toContain(`  ✘ ${REGISTRY_CODE_LINE}  [E_REGISTRY_RPC_DISAGREE]`);
    expect(text).toContain(`  · ${CHECKS.RESPONSE}  (not checked)`);
    expect(text).toContain("✘ REFUSED — E_REGISTRY_RPC_DISAGREE.");
    expect(text).not.toContain("✔ ");
    expect(X.stats.attestations).toBe(before);
    for (const rpc of rpcs) expect(rpc.calls).toHaveLength(0);
  });

  it("one endpoint is down: REFUSED with E_REGISTRY_UNAVAILABLE (the other one alone is not enough)", async () => {
    const { env, rpcs } = await stack(2);
    await rpcs[1]!.close();
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toContain(`  ✘ ${CHECKS.ROOT}  [E_REGISTRY_UNAVAILABLE]`);
    expect(text).toContain("✘ REFUSED — E_REGISTRY_UNAVAILABLE.");
    expect(text).not.toContain("✔ VERIFIED");
    // with a pin, the account is the first thing that cannot be read from every endpoint
    const p = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, p.io)).toBe(1);
    expect(p.out.join("\n")).toContain(`  ✘ ${REGISTRY_CODE_LINE}  [E_REGISTRY_UNAVAILABLE]`);
  });

  it("disagreement: `plr vpn` does not start the proxy", async () => {
    const { env } = await stack(2, { 1: { is_os_allowed: false } });
    const t = io();
    expect(await runCli(["vpn"], { ...env, PLR_VPN_SOCKS_PORT: "0" }, t.io, async () => {})).toBe(1);
    expect(t.err.join("\n")).toContain("E_REGISTRY_RPC_DISAGREE");
  });

  it("one endpoint configured: the output is what it was (one URL in the header, no second endpoint asked)", async () => {
    const { env, rpcs } = await stack(1);
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text).toContain(`  registry: ${REGISTRY} on near (${rpcs[0]!.url})`);
    expect(text).not.toContain("RPC endpoints");
    expect(text).toContain("✔ VERIFIED");
  });

  it("a bad list in PLR_NEAR_RPC: config error before anything is contacted", async () => {
    const { env, rpcs } = await stack(1);
    for (const bad of [`${rpcs[0]!.url},${rpcs[0]!.url}`, `${rpcs[0]!.url},`, `${rpcs[0]!.url},http://rpc.example`]) {
      const t = io();
      expect(await runCli(["vpn", "verify"], { ...env, PLR_NEAR_RPC: bad }, t.io)).toBe(2);
      expect(t.err.join("\n")).toContain("PLR_NEAR_RPC");
      expect(() => loadVpnConfig({ ...env, PLR_NEAR_RPC: bad })).toThrow(ConfigError);
    }
    expect(loadVpnConfig({ ...env, PLR_NEAR_RPC: `${rpcs[0]!.url} , https://rpc.example` }).rpcUrl).toBe(`${rpcs[0]!.url}/,https://rpc.example/`);
    expect(loadVpnConfig(env).rpcUrl).toBe(rpcs[0]!.url);
    expect(rpcs[0]!.calls).toHaveLength(0);
  });
});
