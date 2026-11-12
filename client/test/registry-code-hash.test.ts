// The registry account's on-chain code hash is pinned next to its id: match, mismatch, missing pin.
import { describe, it, expect, afterEach } from "vitest";
import { CHECKS, ERROR_CODES, INTEL_ROOT_P256, PlrError, toHex } from "@plr/shared";
import {
  ConfigError,
  NearRegistry,
  NearRegistryError,
  KNOWN_REGISTRY_CODE_HASHES,
  REGISTRY_CODE_LINE,
  RegistryCodeHashError,
  VpnClient,
  checkLines,
  isRegistryCodeHashError,
  loadVpnConfig,
  resolveRegistryCodeHash,
  runCli,
} from "../src/index.js";
import { startFakeExit } from "./fake-exit.js";
import { FAKE_CODE_HASH, registryHandler, startFakeRpc } from "./fake-rpc.js";

const OTHER_HASH = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const LIVE = "vpnreg.pe-owner-erhan.testnet";
const LIVE_HASH = "C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM";
const REGISTRY = "vpnregistry.test.near";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function stack() {
  const X = await startFakeExit();
  const rpc = await startFakeRpc(registryHandler(X.registry));
  closers.push(X.close, rpc.close);
  const env: Record<string, string> = { PLR_VPN_URL: X.url, PLR_NEAR_RPC: rpc.url, PLR_VPN_REGISTRY: REGISTRY, PLR_TRUSTED_ROOT: toHex(X.root.publicKey) };
  return { X, rpc, env };
}

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s) } };
}

describe("resolveRegistryCodeHash (where the pin comes from)", () => {
  it("ships the pin of the live registry; an explicit pin wins", () => {
    expect(KNOWN_REGISTRY_CODE_HASHES[LIVE]).toBe(LIVE_HASH);
    expect(resolveRegistryCodeHash(LIVE, undefined, true)).toBe(LIVE_HASH);
    expect(resolveRegistryCodeHash(LIVE, "", true)).toBe(LIVE_HASH);
    expect(resolveRegistryCodeHash(LIVE, OTHER_HASH, true)).toBe(OTHER_HASH);
    expect(resolveRegistryCodeHash("other.testnet", OTHER_HASH, true)).toBe(OTHER_HASH);
  });

  it("missing pin: INTEL refuses, MOCK runs with the account id only", () => {
    expect(() => resolveRegistryCodeHash("other.testnet", undefined, true)).toThrow(/PLR_VPN_REGISTRY_CODE_HASH is required/);
    expect(resolveRegistryCodeHash("other.testnet", undefined, false)).toBeUndefined();
    // not an own property of the shipped map
    expect(() => resolveRegistryCodeHash("constructor", undefined, true)).toThrow();
  });

  it("refuses a malformed pin and the 'no contract' hash", () => {
    for (const bad of ["abc", "0".repeat(44), "1".repeat(32), LIVE_HASH + "!", "l".repeat(44)]) {
      expect(() => resolveRegistryCodeHash(LIVE, bad, false)).toThrow(/code hash/);
    }
  });

  it("loadVpnConfig: baked pin for the live registry, ConfigError for an unpinned registry with the Intel root", () => {
    const intel = toHex(INTEL_ROOT_P256);
    expect(loadVpnConfig({ PLR_VPN_REGISTRY: LIVE, PLR_TRUSTED_ROOT: intel, PLR_NEAR_RPC: "https://rpc.example" }).registryCodeHash).toBe(LIVE_HASH);
    expect(() => loadVpnConfig({ PLR_VPN_REGISTRY: "other.testnet", PLR_TRUSTED_ROOT: intel, PLR_NEAR_RPC: "https://rpc.example" })).toThrow(ConfigError);
    expect(loadVpnConfig({ PLR_VPN_REGISTRY: "other.testnet", PLR_TRUSTED_ROOT: intel, PLR_NEAR_RPC: "https://rpc.example", PLR_VPN_REGISTRY_CODE_HASH: OTHER_HASH }).registryCodeHash).toBe(OTHER_HASH);
    expect(() => loadVpnConfig({ PLR_VPN_REGISTRY: LIVE, PLR_TRUSTED_ROOT: intel, PLR_NEAR_RPC: "https://rpc.example", PLR_VPN_REGISTRY_CODE_HASH: "nope" })).toThrow(ConfigError);
  });
});

describe("NearRegistry code-hash pin", () => {
  it("match: views answer; one view_account is reused for the following views", async () => {
    const { X, rpc } = await stack();
    const r = new NearRegistry({ rpcUrl: rpc.url, contractId: REGISTRY, codeHash: FAKE_CODE_HASH });
    expect(r.codeHashVerified).toBe(false);
    expect((await r.getRoot()).p256).toBe(toHex(X.root.publicKey));
    expect(r.codeHashVerified).toBe(true);
    await Promise.all([r.getRoot(), r.isComposeAllowed("ab".repeat(32)), r.getInstance("cd".repeat(32))]);
    expect(rpc.accountViews).toBe(1);
  });

  it("mismatch: every view rejects with E_REGISTRY_CODE_HASH and no contract view is sent", async () => {
    const { rpc } = await stack();
    rpc.codeHash = OTHER_HASH;
    const r = new NearRegistry({ rpcUrl: rpc.url, contractId: REGISTRY, codeHash: FAKE_CODE_HASH });
    for (const call of [() => r.getRoot(), () => r.isComposeAllowed("ab".repeat(32)), () => r.isOsAllowed("ab".repeat(32)), () => r.getInstance("cd".repeat(32)), () => r.getAnchor(0), () => r.view("get_owner", {})]) {
      const e = await call().then(() => undefined, (x: unknown) => x);
      expect(isRegistryCodeHashError(e)).toBe(true);
      expect(e).toBeInstanceOf(PlrError);
      expect((e as PlrError).code).toBe("E_REGISTRY_CODE_HASH");
      expect((e as PlrError).message).toContain("E_REGISTRY_CODE_HASH");
    }
    // a client-only code: the shared list (bundled into the measured exit image) is unchanged
    expect(ERROR_CODES as readonly string[]).not.toContain("E_REGISTRY_CODE_HASH");
    expect(rpc.calls).toHaveLength(0);
    expect(rpc.accountViews).toBe(6); // a failed check is never reused
    expect(r.codeHashVerified).toBe(false);
    // the account gets the pinned code back: the next view passes
    rpc.codeHash = FAKE_CODE_HASH;
    await expect(r.getRoot()).resolves.toBeDefined();
  });

  it("view_account unanswered or malformed: rejects (registry unavailable), never passes", async () => {
    const { rpc } = await stack();
    const r = new NearRegistry({ rpcUrl: rpc.url, contractId: REGISTRY, codeHash: FAKE_CODE_HASH, timeoutMs: 3000 });
    for (const answer of ["fail", "not base58 !"]) {
      rpc.codeHash = answer;
      const e = await r.getRoot().then(() => undefined, (x: unknown) => x);
      expect(e).toBeInstanceOf(NearRegistryError);
      expect(e).not.toBeInstanceOf(PlrError);
    }
    expect(rpc.calls).toHaveLength(0);
    expect(r.codeHashVerified).toBe(false);
  });

  it("no pin: view_account is not asked (MOCK demo); a malformed pin is refused", async () => {
    const { rpc } = await stack();
    const r = new NearRegistry({ rpcUrl: rpc.url, contractId: REGISTRY });
    await r.getRoot();
    expect(rpc.accountViews).toBe(0);
    expect(r.codeHashVerified).toBeUndefined();
    expect(() => new NearRegistry({ rpcUrl: rpc.url, contractId: REGISTRY, codeHash: "1".repeat(32) })).toThrow(PlrError);
  });
});

describe("check lines", () => {
  it("lists the code-hash line first, only for a pinned registry", () => {
    const names = (o: Parameters<typeof checkLines>[2]) => checkLines(undefined, undefined, o).map((l) => l.name);
    expect(names({ intel: true })).not.toContain(REGISTRY_CODE_LINE);
    const pinned = names({ intel: true, codeHash: "verified" });
    expect(pinned).toHaveLength(names({ intel: true }).length + 1);
    expect(pinned[0]).toBe(REGISTRY_CODE_LINE);
    expect(pinned.filter((n) => n !== REGISTRY_CODE_LINE)).toEqual(names({ intel: true }));
  });

  it("E_REGISTRY_CODE_HASH fails that line; so does an unreadable account", () => {
    const failed = (e: unknown, state: "verified" | "unverified") => checkLines(e, "getRoot", { codeHash: state }).find((l) => l.status === "fail");
    expect(failed(new RegistryCodeHashError(), "unverified")).toMatchObject({ name: REGISTRY_CODE_LINE, code: "E_REGISTRY_CODE_HASH" });
    expect(failed(new PlrError("E_REGISTRY_UNAVAILABLE"), "unverified")).toMatchObject({ name: REGISTRY_CODE_LINE, code: "E_REGISTRY_UNAVAILABLE" });
    expect(failed(new PlrError("E_REGISTRY_UNAVAILABLE"), "verified")).toMatchObject({ name: CHECKS.ROOT });
  });
});

describe("plr vpn verify with a registry code-hash pin", () => {
  it("match: VERIFIED, the code-hash line is the first ✔", async () => {
    const { env, rpc } = await stack();
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text).toContain(`  pinned registry code hash: ${FAKE_CODE_HASH}`);
    expect(text).toContain(`  ✔ ${REGISTRY_CODE_LINE}`);
    expect(t.out.indexOf(`  ✔ ${REGISTRY_CODE_LINE}`)).toBe(t.out.indexOf(`  ✔ ${CHECKS.RESPONSE}`) - 1);
    expect(text).toContain("✔ VERIFIED");
    expect(text).not.toContain("✘");
    expect(rpc.accountViews).toBeGreaterThanOrEqual(1);
  });

  it("mismatch: REFUSED with E_REGISTRY_CODE_HASH, no other check runs, the exit is not contacted", async () => {
    const { X, env, rpc } = await stack();
    const before = X.stats.attestations;
    rpc.codeHash = OTHER_HASH;
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toContain(`  ✘ ${REGISTRY_CODE_LINE}  [E_REGISTRY_CODE_HASH]`);
    expect(text).toContain(`  · ${CHECKS.RESPONSE}  (not checked)`);
    expect(text).toContain(`  · ${CHECKS.ROOT}  (not checked)`);
    expect(text).toContain(`  · ${CHECKS.INSTANCE}  (not checked)`);
    expect(text).not.toContain("✔ ");
    expect(X.stats.attestations).toBe(before);
    expect(text).toContain("✘ REFUSED — E_REGISTRY_CODE_HASH.");
    expect(text).not.toContain("✔ VERIFIED");
    expect(text.match(/✘/g)).toHaveLength(2);
    expect(rpc.calls).toHaveLength(0);
  });

  it("account unreadable: REFUSED with E_REGISTRY_UNAVAILABLE on the code-hash line", async () => {
    const { env, rpc } = await stack();
    rpc.codeHash = "fail";
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH }, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toContain(`  ✘ ${REGISTRY_CODE_LINE}  [E_REGISTRY_UNAVAILABLE]`);
    expect(text).toContain("✘ REFUSED — E_REGISTRY_UNAVAILABLE.");
    expect(rpc.calls).toHaveLength(0);
  });

  it("the code changes after a verification: the next connection is refused (per-connection re-check)", async () => {
    const { X, env, rpc } = await stack();
    let now = 0;
    const realNow = performance.now.bind(performance);
    const registry = new NearRegistry({ rpcUrl: rpc.url, contractId: REGISTRY, codeHash: FAKE_CODE_HASH });
    const client = new VpnClient({ exitUrl: env.PLR_VPN_URL!, registry, trustedRoot: X.root.publicKey });
    const session = await client.attestSession();
    expect(session.verified.checks.length).toBeGreaterThan(0);
    rpc.codeHash = OTHER_HASH;
    // within the reuse window the passed check still counts; after it, the account is read again
    performance.now = () => realNow() + now;
    try {
      now = 31_000;
      const e = await client.connect("127.0.0.1", 9).then(() => undefined, (x: unknown) => x);
      expect(isRegistryCodeHashError(e)).toBe(true);
    } finally {
      performance.now = realNow;
    }
  });

  it("mismatch: `plr vpn` does not start the proxy", async () => {
    const { env, rpc } = await stack();
    rpc.codeHash = OTHER_HASH;
    const t = io();
    expect(await runCli(["vpn"], { ...env, PLR_VPN_REGISTRY_CODE_HASH: FAKE_CODE_HASH, PLR_VPN_SOCKS_PORT: "0" }, t.io, async () => {})).toBe(1);
    expect(t.err.join("\n")).toContain("E_REGISTRY_CODE_HASH");
  });

  it("missing pin with a MOCK root: verifies with a warning and no code-hash line", async () => {
    const { env, rpc } = await stack();
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text).toContain("registry code hash NOT pinned");
    expect(text).not.toContain(REGISTRY_CODE_LINE);
    expect(text).toContain("✔ VERIFIED");
    expect(rpc.accountViews).toBe(0);
  });

  it("missing pin with the Intel root: config error before anything is contacted", async () => {
    const { env, rpc } = await stack();
    const t = io();
    expect(await runCli(["vpn", "verify"], { ...env, PLR_TRUSTED_ROOT: toHex(INTEL_ROOT_P256) }, t.io)).toBe(2);
    expect(t.err.join("\n")).toContain("PLR_VPN_REGISTRY_CODE_HASH is required");
    expect(rpc.calls).toHaveLength(0);
    expect(rpc.accountViews).toBe(0);
  });
});
