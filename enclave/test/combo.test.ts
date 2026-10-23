// SPEC-COMBO: the LLM router and the VPN exit in one TD — compose schema, build, host measurement, per-process
// environments, and (where Unix sockets are allowed) a live three-process launch.
import { afterAll, describe, expect, it } from "vitest";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import net from "node:net";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { FRAME, MockRoot, MockVerifier, PlrError, isDebug, parseConnectErr, toHex, verifyEventLog } from "@plr/shared";
import {
  VPN_DOH_PRODUCTION, VPN_DOH_TEST, VPN_ENTRY, canonicalJson, composeBytes, composeService, makeComboCompose, makeCompose, makeVpnCompose,
  parseComboCompose, parseCompose, parseVpnCompose, routerLlmKindOf, vpnPolicyOf, type ComboCompose,
} from "../src/compose.js";
import { loadConfig } from "../src/config.js";
import {
  COMBO_EXIT_ENV_ALLOWLIST, COMBO_ROUTER_ENV_ALLOWLIST, HostError, comboProcessEnvs, composeServiceOf, launchCombo, measureBoot, measureComboBoot,
  measureVpnBoot,
} from "../src/mock-tdx/host.js";
import { loadExitConfig } from "../src/vpn/config.js";
import { attest, chat } from "./helpers.js";
import { TestTunnel, attestExit, mentionsNumber, startEchoUpstream } from "./vpn-helpers.js";

const DIST = resolve(import.meta.dirname, "..", "dist");
const INFO = JSON.parse(readFileSync(join(DIST, "build-info.json"), "utf8"));
const comboCompose = (v: "combo" | "combo-test", k: "mock" | "llama" = "mock") => join(DIST, INFO.combo[v].compose[k].file);
mkdirSync(resolve(import.meta.dirname, "..", ".run"), { recursive: true });
const tmp = mkdtempSync(join(resolve(import.meta.dirname, "..", ".run"), "c-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const enc = (s: string) => new TextEncoder().encode(s);
const code = (f: () => unknown) => {
  try { f(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
};
const hostErr = async (p: Promise<unknown>) => {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(HostError); return (e as HostError).code; }
  return "NO_THROW";
};

const N = "33".repeat(32);
const parts = (o: { kind?: "mock" | "llama.cpp"; allowLoopback?: boolean; routerNode?: string; vpnNode?: string; entry?: string } = {}) => ({
  router: {
    kind: o.kind ?? "mock", modelSha256: "11".repeat(32), runtime: "node-mock-llm",
    runtimeSha256: o.kind === "llama.cpp" ? "66".repeat(32) : (o.routerNode ?? N),
    bundleSha256: "22".repeat(32), entry: o.entry ?? "router.bundle.mjs", nodeSha256: o.routerNode ?? N,
  },
  vpn: { bundleSha256: "44".repeat(32), nodeSha256: o.vpnNode ?? N, allowLoopback: o.allowLoopback ?? false },
});
type Mut = { [k: string]: any };
/** Canonical bytes of a (possibly invalid) mutation of a valid combo compose. */
const mutated = (f: (c: Mut) => void): Uint8Array => {
  const c = JSON.parse(JSON.stringify(makeComboCompose(parts()))) as Mut;
  f(c);
  return enc(canonicalJson(c));
};

// ------------------------------------------------------------------------------------------- compose (SPEC-COMBO §1)

describe("plr-combo compose (SPEC-COMBO §1)", () => {
  it("exact schema, canonical bytes, round trip; both halves carry their own service's fields", () => {
    const c = makeComboCompose(parts());
    expect(Object.keys(c).sort()).toEqual(["manifest_version", "name", "router", "vpn"]);
    expect(Object.keys(c.router).sort()).toEqual(["bundle_sha256", "entry", "llm", "node_sha256", "policy"]);
    expect(Object.keys(c.vpn).sort()).toEqual(["bundle_sha256", "entry", "node_sha256", "policy"]);
    expect(c.router.policy).toEqual({ disk: "none", egress: [], logs: "none" });
    expect(c.vpn.policy).toEqual({ disk: "none", dns: { doh: [...VPN_DOH_PRODUCTION] }, egress: { allow_loopback: false, deny_private: true }, logs: "none" });
    expect(c.vpn.entry).toBe(VPN_ENTRY);
    const b = composeBytes(c);
    expect(new TextDecoder().decode(b)).toBe(canonicalJson(c as never));
    expect(parseComboCompose(b)).toEqual(c);
    expect(composeService(b)).toBe("combo");
    const t = makeComboCompose(parts({ allowLoopback: true }));
    expect(t.vpn.policy.dns.doh).toEqual([...VPN_DOH_TEST]);
    expect(toHex(sha256(composeBytes(t)))).not.toBe(toHex(sha256(b))); // a test build never passes as production
  });

  it("refuses extra / missing keys at every level", () => {
    const bad = [
      mutated((c) => { c.extra = 1; }),
      mutated((c) => { delete c.vpn; }),
      mutated((c) => { c.router.x = 1; }),
      mutated((c) => { delete c.router.policy; }),
      mutated((c) => { c.router.llm.x = 1; }),
      mutated((c) => { c.vpn.x = 1; }),
      mutated((c) => { delete c.vpn.policy; }),
      mutated((c) => { c.vpn.policy.x = 1; }),
      mutated((c) => { c.vpn.policy.egress.x = true; }),
      mutated((c) => { c.vpn.llm = c.router.llm; }),
      mutated((c) => { c.llm = c.router.llm; }),
    ];
    for (const b of bad) expect(code(() => parseComboCompose(b))).toBe("E_BAD_INPUT");
  });

  it("validates the router half with the router rules and the vpn half with the VPN rules", () => {
    const bad = [
      mutated((c) => { c.manifest_version = 2; }),
      mutated((c) => { c.name = "plr-router"; }),
      mutated((c) => { c.router.llm.kind = "gpt"; }),
      mutated((c) => { c.router.llm.model_sha256 = "zz"; }),
      mutated((c) => { c.router.llm.runtime_sha256 = "77".repeat(32); }), // mock LLM runs on node: must equal node_sha256
      mutated((c) => { c.router.policy.egress = ["1.2.3.4"]; }),
      mutated((c) => { c.router.policy.disk = "rw"; }),
      mutated((c) => { c.router.entry = "../router.bundle.mjs"; }),
      mutated((c) => { c.router.bundle_sha256 = "AA".repeat(32); }),
      mutated((c) => { c.vpn.entry = "other.mjs"; }),
      mutated((c) => { c.vpn.policy.egress.deny_private = false; }),
      mutated((c) => { c.vpn.policy.logs = "all"; }),
      mutated((c) => { c.vpn.policy.dns.doh = ["http://127.0.0.1:18253/dns-query"]; }), // plain http needs allow_loopback
      mutated((c) => { c.vpn.policy.dns.doh = ["https://dns.example/dns-query"]; }), // not an IP literal
      mutated((c) => { c.vpn.policy.dns.doh = []; }),
      mutated((c) => { c.vpn.bundle_sha256 = "4".repeat(63); }),
    ];
    for (const b of bad) expect(code(() => parseComboCompose(b))).toBe("E_BAD_INPUT");
    expect(() => makeComboCompose(parts({ entry: "a/b.mjs" }))).toThrow(PlrError);
  });

  it("one runtime: router.node_sha256 must equal vpn.node_sha256; the two entries must differ", () => {
    expect(() => makeComboCompose(parts({ routerNode: "33".repeat(32), vpnNode: "55".repeat(32) }))).toThrow(/node_sha256/);
    expect(code(() => parseComboCompose(mutated((c) => { c.vpn.node_sha256 = "55".repeat(32); })))).toBe("E_BAD_INPUT");
    expect(() => makeComboCompose(parts({ entry: VPN_ENTRY }))).toThrow(/router.entry/);
    // llama.cpp: the LLM runtime is llama-server (its own pin); node pins still agree.
    expect(parseComboCompose(composeBytes(makeComboCompose(parts({ kind: "llama.cpp" })))).router.llm.runtime_sha256).toBe("66".repeat(32));
  });

  it("must already be canonical; bounded; UTF-8", () => {
    const c = makeComboCompose(parts());
    expect(code(() => parseComboCompose(enc(JSON.stringify(c))))).toBe("E_BAD_INPUT");
    expect(code(() => parseComboCompose(enc(canonicalJson(c as never).replace("\n", "\r\n"))))).toBe("E_BAD_INPUT");
    expect(code(() => parseComboCompose(new Uint8Array(9000).fill(0x20)))).toBe("E_BAD_INPUT");
    expect(code(() => parseComboCompose(new Uint8Array([0xff, 0xfe])))).toBe("E_BAD_INPUT");
  });

  it("the documents stay disjoint; services read their own half of a combo", () => {
    const combo = composeBytes(makeComboCompose(parts({ allowLoopback: true })));
    const router = composeBytes(makeCompose(parts().router));
    const vpn = composeBytes(makeVpnCompose(parts().vpn));
    expect(code(() => parseCompose(combo))).toBe("E_BAD_INPUT");
    expect(code(() => parseVpnCompose(combo))).toBe("E_BAD_INPUT");
    expect(code(() => parseComboCompose(router))).toBe("E_BAD_INPUT");
    expect(code(() => parseComboCompose(vpn))).toBe("E_BAD_INPUT");
    expect(routerLlmKindOf(combo)).toBe("mock");
    expect(routerLlmKindOf(router)).toBe("mock");
    expect(code(() => routerLlmKindOf(vpn))).toBe("E_BAD_INPUT");
    expect(vpnPolicyOf(combo).egress.allow_loopback).toBe(true);
    expect(vpnPolicyOf(vpn).egress.allow_loopback).toBe(false);
    expect(code(() => vpnPolicyOf(router))).toBe("E_BAD_INPUT");
    // A non-canonical combo is refused by the service accessors too (they parse strictly).
    expect(code(() => vpnPolicyOf(enc(JSON.stringify(JSON.parse(new TextDecoder().decode(combo))))))).toBe("E_BAD_INPUT");
  });
});

// ------------------------------------------------------------------------------------------- build

describe("combo builds (build-info 'combo' key)", () => {
  it("combo + combo-test for llm kinds mock and llama: the honest bundles, the VPN policies of SPEC-COMBO §1", () => {
    expect(Object.keys(INFO).sort()).toEqual(["combo", "llm", "runtime", "variants", "vpn"]);
    expect(Object.keys(INFO.combo).sort()).toEqual(["combo", "combo-test"]);
    const hashes = new Set<string>();
    for (const v of ["combo", "combo-test"] as const) {
      const e = INFO.combo[v];
      expect(e.allow_loopback).toBe(v === "combo-test");
      expect(e.doh).toEqual(v === "combo" ? [...VPN_DOH_PRODUCTION] : [...VPN_DOH_TEST]);
      expect(e.router_bundle_sha256).toBe(INFO.variants.honest.bundle_sha256);
      expect(e.vpn_bundle_sha256).toBe(INFO.vpn["vpn-honest"].bundle_sha256);
      expect(Object.keys(e.compose).sort()).toEqual(["llama", "mock"]);
      for (const k of ["mock", "llama"] as const) {
        const { dir, file, compose_hash } = e.compose[k];
        expect(file).toBe(`${dir}/app-compose.json`);
        const bytes = readFileSync(join(DIST, file));
        expect(toHex(sha256(bytes))).toBe(compose_hash);
        hashes.add(compose_hash);
        const c: ComboCompose = parseComboCompose(new Uint8Array(bytes)); // strict + canonical
        expect(c.router.llm.kind).toBe(k === "mock" ? "mock" : "llama.cpp");
        expect(c.router.llm.model_sha256).toBe(INFO.llm[c.router.llm.kind]);
        expect(c.router.node_sha256).toBe(INFO.runtime.node_sha256);
        expect(c.vpn.node_sha256).toBe(INFO.runtime.node_sha256);
        expect(c.router.llm.runtime_sha256).toBe(k === "mock" ? INFO.runtime.node_sha256 : INFO.runtime.llama_server_sha256);
        expect(c.vpn.policy.egress).toEqual({ allow_loopback: v === "combo-test", deny_private: true });
        expect(c.vpn.policy.dns.doh).toEqual(e.doh);
        expect(toHex(sha256(readFileSync(join(DIST, dir, c.router.entry))))).toBe(c.router.bundle_sha256);
        expect(toHex(sha256(readFileSync(join(DIST, dir, VPN_ENTRY))))).toBe(c.vpn.bundle_sha256);
      }
    }
    expect(hashes.size).toBe(4);
    // Existing keys untouched.
    expect(Object.keys(INFO.variants).sort()).toEqual(["evil-logger", "honest"]);
    expect(Object.keys(INFO.vpn).sort()).toEqual(["vpn-evil-logger", "vpn-honest", "vpn-honest-test"]);
  });
});

// ------------------------------------------------------------------------------------------- host measurement

describe("measurement of a plr-combo compose (SPEC-COMBO §2)", () => {
  const root = MockRoot.generate();

  it("measures everything once: one boot event log binding the combo compose; DEBUG only on request", async () => {
    for (const v of ["combo", "combo-test"] as const) {
      const b = await measureComboBoot({ composePath: comboCompose(v), root });
      expect(b.service).toBe("combo");
      expect(b.composeHash).toBe(INFO.combo[v].compose.mock.compose_hash);
      const q = await b.attester.getQuote(new Uint8Array(64));
      const parsed = new MockVerifier(root.publicKey).verify(q.quote);
      expect(toHex(verifyEventLog(q.eventLog, parsed.report.rtmr[3]).composeHash)).toBe(b.composeHash);
      expect(isDebug(parsed.report)).toBe(false);
      expect(b.eventLog.map((e) => e.event)).toEqual(["system-preparing", "app-id", "compose-hash", "instance-id", "boot-mr-done"]);
      expect(toHex(sha256(b.routerBundleBytes))).toBe(INFO.variants.honest.bundle_sha256);
      expect(toHex(sha256(b.vpnBundleBytes))).toBe(INFO.vpn["vpn-honest"].bundle_sha256);
      expect(b.llmBytes).not.toBeNull();
    }
    const d = await measureComboBoot({ composePath: comboCompose("combo-test"), root, debug: true });
    expect(isDebug(new MockVerifier(root.publicKey).verify((await d.attester.getQuote(new Uint8Array(64))).quote).report)).toBe(true);
    expect(composeServiceOf(comboCompose("combo"))).toBe("combo");
  });

  /** A private copy of the combo-test (mock) build directory with one file replaced. */
  const copyWith = (file: string | null, bytes?: Buffer | string): string => {
    const src = join(DIST, INFO.combo["combo-test"].compose.mock.dir);
    const d = mkdtempSync(join(tmp, "m-"));
    for (const f of ["app-compose.json", "router.bundle.mjs", VPN_ENTRY]) copyFileSync(join(src, f), join(d, f));
    if (file !== null) writeFileSync(join(d, file), bytes!);
    return join(d, "app-compose.json");
  };

  it("refuses on any mismatch: router bundle, exit bundle, mock LLM, node pin → E_MEASUREMENT_MISMATCH", async () => {
    expect(await hostErr(measureComboBoot({ composePath: copyWith(null), root }))).toBe("NO_THROW");
    const evilRouter = readFileSync(join(DIST, "evil-logger.bundle.mjs"));
    const evilVpn = readFileSync(join(DIST, INFO.vpn["vpn-evil-logger"].bundle));
    expect(await hostErr(measureComboBoot({ composePath: copyWith("router.bundle.mjs", evilRouter), root }))).toBe("E_MEASUREMENT_MISMATCH");
    expect(await hostErr(measureComboBoot({ composePath: copyWith(VPN_ENTRY, evilVpn), root }))).toBe("E_MEASUREMENT_MISMATCH");
    expect(await hostErr(measureComboBoot({ composePath: copyWith(VPN_ENTRY, Buffer.concat([readFileSync(join(DIST, INFO.vpn["vpn-honest"].bundle)), Buffer.from("\n")])), root }))).toBe("E_MEASUREMENT_MISMATCH");
    const llm = join(tmp, "llm-tampered.mjs");
    writeFileSync(llm, readFileSync(resolve(import.meta.dirname, "..", "mock-llm", "server.mjs"), "utf8") + "//x\n");
    expect(await hostErr(measureComboBoot({ composePath: copyWith(null), root, llmFile: llm }))).toBe("E_MEASUREMENT_MISMATCH");
    const otherNode = readFileSync(comboCompose("combo-test"), "utf8").replaceAll(INFO.runtime.node_sha256, "00".repeat(32));
    expect(await hostErr(measureComboBoot({ composePath: copyWith("app-compose.json", otherNode), root }))).toBe("E_MEASUREMENT_MISMATCH");
    // Bundles from elsewhere must carry the compose's entry names.
    expect(await hostErr(measureComboBoot({ composePath: comboCompose("combo-test"), root, vpnBundlePath: join(DIST, "router.bundle.mjs") }))).toBe("E_BUNDLE_ENTRY");
    expect(await hostErr(measureComboBoot({ composePath: comboCompose("combo-test"), root, routerBundlePath: join(DIST, "evil-logger.bundle.mjs") }))).toBe("E_BUNDLE_ENTRY");
  });

  it("each measurement path refuses the other documents (E_COMPOSE); non-canonical combo → E_COMPOSE", async () => {
    expect(await hostErr(measureBoot({ composePath: comboCompose("combo-test"), root }))).toBe("E_COMPOSE");
    expect(await hostErr(measureVpnBoot({ composePath: comboCompose("combo-test"), root }))).toBe("E_COMPOSE");
    expect(await hostErr(measureComboBoot({ composePath: join(DIST, "app-compose.mock.json"), root }))).toBe("E_COMPOSE");
    expect(await hostErr(measureComboBoot({ composePath: join(DIST, INFO.vpn["vpn-honest"].compose.file), root }))).toBe("E_COMPOSE");
    const loose = JSON.stringify(JSON.parse(readFileSync(comboCompose("combo-test"), "utf8")));
    expect(await hostErr(measureComboBoot({ composePath: copyWith("app-compose.json", loose), root }))).toBe("E_COMPOSE");
  });

  it("launchCombo refuses a mismatching build before starting anything", async () => {
    let out = "";
    const p = copyWith("router.bundle.mjs", readFileSync(join(DIST, "evil-logger.bundle.mjs")));
    expect(await hostErr(launchCombo({ composePath: p, root, runDir: tmp, output: (s) => { out += s; } }))).toBe("E_MEASUREMENT_MISMATCH");
    expect(out).toBe("plr-host: launch_refused code=E_MEASUREMENT_MISMATCH\n");
  });
});

// ------------------------------------------------------------------------------------------- per-process environments

describe("combo process environments (SPEC-COMBO §2)", () => {
  const hostEnv = {
    PLR_NEAR_RPC: "http://127.0.0.1:3030", PLR_REGISTRY: "registry.test.near", PLR_VPN_REGISTRY: "vpnregistry.test.near",
    PLR_OPERATOR_ID: "operator.test.near", PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64), PLR_ANCHOR_INTERVAL_MS: "1000",
    PLR_ROUTER_HOST: "127.0.0.1", PLR_VPN_HOST: "127.0.0.1",
    // never forwarded
    NODE_OPTIONS: "--require /evil.js", PLR_MOCK_ROOT_SECRET_FILE: "/root.hex", PLR_LLM_PORT: "1", PLR_LLM_API_KEY: "ff".repeat(32), HOME: "/home/x",
    PLR_TDX_SOCKET: "/forged.sock", PLR_APP_COMPOSE_PATH: "/forged.json", DYLD_INSERT_LIBRARIES: "/evil.dylib",
  };
  const base = {
    hostEnv, nodeEnv: { DYLD_LIBRARY_PATH: "/p/node-x/lib" }, socketPath: "/p/q.sock", routerComposePath: "/p/router/app-compose.json",
    vpnComposePath: "/p/vpn/app-compose.json", routerPort: 18100, llmPort: 41234, llmApiKey: "ab".repeat(32), runDir: "/run",
  };

  it("the router gets the LLM port + key and the LLM registry; the exit gets the VPN registry and NO LLM port or key", () => {
    const { router, exit } = comboProcessEnvs({ ...base, exitPort: 0 });
    expect(router).toEqual({
      PLR_NEAR_RPC: "http://127.0.0.1:3030", PLR_REGISTRY: "registry.test.near", PLR_OPERATOR_ID: "operator.test.near",
      PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64), PLR_ANCHOR_INTERVAL_MS: "1000", PLR_ROUTER_HOST: "127.0.0.1",
      DYLD_LIBRARY_PATH: "/p/node-x/lib", PLR_TDX_SOCKET: "/p/q.sock", PLR_APP_COMPOSE_PATH: "/p/router/app-compose.json",
      PLR_ROUTER_PORT: "18100", PLR_LLM_PORT: "41234", PLR_LLM_API_KEY: "ab".repeat(32), PLR_RUN_DIR: "/run",
    });
    expect(exit).toEqual({
      PLR_NEAR_RPC: "http://127.0.0.1:3030", PLR_VPN_REGISTRY: "vpnregistry.test.near", PLR_OPERATOR_ID: "operator.test.near",
      PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64), PLR_ANCHOR_INTERVAL_MS: "1000", PLR_VPN_HOST: "127.0.0.1",
      DYLD_LIBRARY_PATH: "/p/node-x/lib", PLR_TDX_SOCKET: "/p/q.sock", PLR_APP_COMPOSE_PATH: "/p/vpn/app-compose.json", PLR_VPN_PORT: "0",
    });
    for (const k of Object.keys(exit)) expect(k).not.toMatch(/LLM|ROUTER|^PLR_REGISTRY$|RUN_DIR/);
    expect(Object.values(exit)).not.toContain("ab".repeat(32));
    expect(Object.values(exit)).not.toContain("41234");
    for (const k of Object.keys(router)) expect(k).not.toMatch(/VPN/);
    for (const k of [...COMBO_ROUTER_ENV_ALLOWLIST, ...COMBO_EXIT_ENV_ALLOWLIST]) expect(k).toMatch(/^PLR_/);
    expect(COMBO_EXIT_ENV_ALLOWLIST).not.toContain("PLR_REGISTRY" as never);
    expect(COMBO_EXIT_ENV_ALLOWLIST).not.toContain("PLR_LLM_PORT" as never);
    expect(COMBO_ROUTER_ENV_ALLOWLIST).not.toContain("PLR_VPN_REGISTRY" as never);
  });

  it("each service loads its own registry from its environment; the exit never falls back to the LLM registry", () => {
    const { router, exit } = comboProcessEnvs(base);
    expect(loadConfig(router).near?.contractId).toBe("registry.test.near");
    expect(loadConfig(router).llmApiKey).toBe("ab".repeat(32));
    const x = loadExitConfig(exit);
    expect([x.near?.contractId, x.port]).toEqual(["vpnregistry.test.near", 18200]);
    // Without PLR_VPN_REGISTRY the exit is unregistered (clients refuse it), never registered on PLR_REGISTRY.
    const { PLR_VPN_REGISTRY: _drop, ...noVpn } = hostEnv;
    const lone = loadExitConfig(comboProcessEnvs({ ...base, hostEnv: noVpn }).exit);
    expect([lone.near, lone.nearConfigError]).toEqual([null, true]);
    // PLR_VPN_PORT from the host env applies when no explicit exit port is given; host-set keys always win.
    expect(loadExitConfig(comboProcessEnvs({ ...base, hostEnv: { ...hostEnv, PLR_VPN_PORT: "18299" } }).exit).port).toBe(18299);
    expect(comboProcessEnvs({ ...base, hostEnv: { ...hostEnv, PLR_VPN_PORT: "18299" }, exitPort: 18201 }).exit.PLR_VPN_PORT).toBe("18201");
  });
});

// ------------------------------------------------------------------------------------------- live launch (needs Unix sockets)

async function unixSocketsAllowed(): Promise<boolean> {
  const p = join(tmp, "probe.sock");
  return new Promise((ok) => {
    const s = net.createServer();
    s.once("error", () => ok(false));
    s.listen(p, () => s.close(() => ok(true)));
  });
}
const canSock = await unixSocketsAllowed();
if (!canSock) console.warn("combo.test: Unix sockets are not permitted in this sandbox; live combo launch tests skipped");

const waitFor = async (re: RegExp, get: () => string, ms = 30_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const m = re.exec(get());
    if (m) return m;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("timeout waiting for " + re + "\n" + get());
};
const ROUTER_RE = /plr-router: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/;
const VPN_RE = /plr-vpn: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/;
const gone = (p: { exitCode: number | null; signalCode: NodeJS.Signals | null }) => p.exitCode !== null || p.signalCode !== null;

describe.skipIf(!canSock)("launchCombo via the mock TDX host (three processes, one TD)", () => {
  it("router + exit from one measurement, distinct keys, both work, nothing leaks, clean shutdown of all three", async () => {
    const root = MockRoot.generate();
    const up = await startEchoUpstream();
    const SECRET = "combo-live-" + toHex(randomBytes(8));
    let out = "";
    const h = await launchCombo({
      composePath: comboCompose("combo-test"), root, runDir: tmp, routerPort: 0, exitPort: 0,
      // A registry id alone: incomplete NEAR config ⇒ registration disabled (no chain in unit tests).
      env: { PLR_REGISTRY: "registry.test.near", PLR_VPN_REGISTRY: "vpnregistry.test.near" },
      output: (s) => { out += s; },
    });
    try {
      const r = await waitFor(ROUTER_RE, () => out);
      const x = await waitFor(VPN_RE, () => out);
      expect(r[3]).toBe(INFO.combo["combo-test"].compose.mock.compose_hash);
      expect(x[3]).toBe(r[3]);
      expect(x[2]).not.toBe(r[2]); // each service generated its own keys
      expect(new Set([h.llm.pid, h.router.pid, h.exit.pid]).size).toBe(3);
      expect((out.match(/plr-host: measured /g) ?? []).length).toBe(1); // measured + RTMR3 extended once
      await waitFor(/plr-router: registration_disabled/, () => out);
      await waitFor(/plr-vpn: registration_disabled/, () => out);
      expect(statSync(h.socketPath).mode & 0o777).toBe(0o600);

      // Router role.
      const rv = await attest(r[1]!, root.publicKey);
      expect(toHex(rv.composeHash)).toBe(h.boot.composeHash);
      expect(toHex(rv.keyHash)).toBe(r[2]);
      const c = await chat(r[1]!, rv, { messages: [{ role: "user", content: SECRET }] });
      expect(c.status).toBe(200);
      expect(c.content).toMatch(/^mock-answer-/);

      // Exit role (same compose, same OS measurement, other keys).
      const xv = await attestExit(x[1]!, root.publicKey);
      expect(toHex(xv.composeHash)).toBe(h.boot.composeHash);
      expect(toHex(xv.osMeasurement)).toBe(toHex(rv.osMeasurement));
      expect(toHex(xv.keyHash)).toBe(x[2]);
      const t = await TestTunnel.open(Number(new URL(x[1]!).port), xv, xv.nonce);
      t.connect("127.0.0.1", up.port);
      await t.until(() => t.frames.length >= 1);
      t.send(FRAME.DATA, new TextEncoder().encode(SECRET));
      t.send(FRAME.FIN);
      expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
      expect(t.data().toString()).toBe(SECRET);

      // Even through the (loopback-allowed) test exit, the LLM refuses anyone without the router's per-boot key.
      const l = await TestTunnel.open(Number(new URL(x[1]!).port), xv, xv.nonce);
      l.connect("127.0.0.1", h.llmPort);
      await l.until(() => l.frames.length >= 1);
      expect(l.frames[0]!.type).toBe(FRAME.CONNECT_OK);
      l.send(FRAME.DATA, new TextEncoder().encode("GET /v1/models HTTP/1.1\r\nHost: llm\r\nConnection: close\r\n\r\n"));
      await l.until(() => l.data().length > 12);
      expect(l.data().toString("latin1")).toMatch(/^HTTP\/1\.1 401 /);
      l.sock.destroy();

      await new Promise((res) => setTimeout(res, 100));
      expect(out).not.toContain(SECRET);
      expect(out).not.toContain(c.content);
      expect(mentionsNumber(out, up.port)).toBe(false);
    } finally {
      const dir = resolve(h.socketPath, "..");
      expect(await h.stop()).toBe(0);
      expect(existsSync(dir)).toBe(false);
      for (const p of [h.llm, h.router, h.exit]) expect(gone(p)).toBe(true);
      await up.close();
    }
  }, 90_000);

  it("production combo: the exit refuses the router's and the LLM's loopback ports (E_EGRESS_DENIED)", async () => {
    const root = MockRoot.generate();
    let out = "";
    const h = await launchCombo({ composePath: comboCompose("combo"), root, runDir: tmp, routerPort: 0, exitPort: 0, output: (s) => { out += s; } });
    try {
      const r = await waitFor(ROUTER_RE, () => out);
      const x = await waitFor(VPN_RE, () => out);
      expect(r[3]).toBe(INFO.combo.combo.compose.mock.compose_hash);
      const xv = await attestExit(x[1]!, root.publicKey);
      const port = Number(new URL(x[1]!).port);
      for (const target of [Number(new URL(r[1]!).port), h.llmPort]) {
        const t = await TestTunnel.open(port, xv, xv.nonce);
        t.connect("127.0.0.1", target);
        await t.until(() => t.frames.length >= 1);
        expect(t.frames[0]!.type).toBe(FRAME.CONNECT_ERR);
        expect(parseConnectErr(t.frames[0]!.payload)).toBe("E_EGRESS_DENIED");
        t.sock.destroy();
      }
    } finally {
      expect(await h.stop()).toBe(0);
    }
  }, 90_000);

  it("if one service dies the host stops the whole TD (fail closed)", async () => {
    const root = MockRoot.generate();
    let out = "";
    const h = await launchCombo({ composePath: comboCompose("combo-test"), root, runDir: tmp, routerPort: 0, exitPort: 0, output: (s) => { out += s; } });
    await waitFor(ROUTER_RE, () => out);
    await waitFor(VPN_RE, () => out);
    h.exit.kill("SIGKILL");
    expect(await h.done).toBe(1);
    for (const p of [h.llm, h.router, h.exit]) expect(gone(p)).toBe(true);
    expect(existsSync(resolve(h.socketPath, ".."))).toBe(false);
  }, 90_000);
});
