import { afterAll, describe, expect, it } from "vitest";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import net from "node:net";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { FRAME, MockRoot, MockVerifier, isDebug, registrationNonce, registrationReportData, toHex, verifyEventLog } from "@plr/shared";
import { EXIT_ENV_ALLOWLIST, HostError, exitNodeFlags, launchVpn, measureVpnBoot } from "../src/mock-tdx/host.js";
import { composeBytes, makeVpnCompose, parseVpnCompose } from "../src/compose.js";
import { startFakeDoh } from "./doh-server.js";
import { TestTunnel, attestExit, mentionsNumber, startEchoUpstream } from "./vpn-helpers.js";

const DIST = resolve(import.meta.dirname, "..", "dist");
const INFO = JSON.parse(readFileSync(join(DIST, "build-info.json"), "utf8"));
const vpnCompose = (v: string) => join(DIST, INFO.vpn[v].compose.file);
mkdirSync(resolve(import.meta.dirname, "..", ".run"), { recursive: true });
const tmp = mkdtempSync(join(resolve(import.meta.dirname, "..", ".run"), "v-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const hostErr = async (p: Promise<unknown>) => {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(HostError); return (e as HostError).code; }
  return "NO_THROW";
};

describe("VPN builds (SPEC-VPN §2)", () => {
  it("build-info records the three VPN variants under 'vpn'", () => {
    expect(Object.keys(INFO.vpn).sort()).toEqual(["vpn-evil-logger", "vpn-honest", "vpn-honest-test"]);
    for (const [name, v] of Object.entries<any>(INFO.vpn)) {
      const bytes = readFileSync(join(DIST, v.compose.file));
      expect(toHex(sha256(bytes)), name).toBe(v.compose.compose_hash);
      const c = parseVpnCompose(new Uint8Array(bytes));
      expect(c.vpn.bundle_sha256).toBe(v.bundle_sha256);
      expect(toHex(sha256(readFileSync(join(DIST, v.bundle))))).toBe(v.bundle_sha256);
      expect(c.policy.egress.allow_loopback).toBe(name !== "vpn-honest");
      expect(c.vpn.node_sha256).toBe(INFO.runtime.node_sha256);
    }
    expect(INFO.vpn["vpn-honest"].bundle_sha256).toBe(INFO.vpn["vpn-honest-test"].bundle_sha256);
    expect(INFO.vpn["vpn-honest"].compose.compose_hash).not.toBe(INFO.vpn["vpn-honest-test"].compose.compose_hash);
    expect(INFO.vpn["vpn-evil-logger"].bundle_sha256).not.toBe(INFO.vpn["vpn-honest"].bundle_sha256);
  });

  it("the honest exit bundle contains no evil code", () => {
    const honest = readFileSync(join(DIST, INFO.vpn["vpn-honest"].bundle), "utf8");
    const evil = readFileSync(join(DIST, INFO.vpn["vpn-evil-logger"].bundle), "utf8");
    expect(evil).toContain("EVIL-VPN-LOGGER");
    expect(honest).not.toMatch(/EVIL|stolen/i);
    expect(honest).not.toMatch(/sourceMappingURL/);
    expect(honest).not.toContain(resolve(import.meta.dirname, ".."));
  });
});

describe("measurement of a plr-vpn compose", () => {
  const root = MockRoot.generate();

  it("measures the built VPN composes (no LLM); the event log binds the compose hash", async () => {
    for (const v of ["vpn-honest", "vpn-honest-test", "vpn-evil-logger"]) {
      const b = await measureVpnBoot({ composePath: vpnCompose(v), root });
      expect(b.composeHash).toBe(INFO.vpn[v].compose.compose_hash);
      const q = await b.attester.getQuote(new Uint8Array(64));
      const parsed = new MockVerifier(root.publicKey).verify(q.quote);
      expect(toHex(verifyEventLog(q.eventLog, parsed.report.rtmr[3]).composeHash)).toBe(b.composeHash);
      expect(isDebug(parsed.report)).toBe(false);
    }
  });

  it("tampered / evil bundle under the honest compose → E_MEASUREMENT_MISMATCH; foreign entry → E_BUNDLE_ENTRY; not a plr-vpn compose → E_COMPOSE", async () => {
    const d = mkdtempSync(join(tmp, "m-"));
    copyFileSync(vpnCompose("vpn-honest"), join(d, "app-compose.json"));
    copyFileSync(join(DIST, INFO.vpn["vpn-evil-logger"].bundle), join(d, "vpn.bundle.mjs"));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "app-compose.json"), root }))).toBe("E_MEASUREMENT_MISMATCH");
    writeFileSync(join(d, "vpn.bundle.mjs"), Buffer.concat([readFileSync(join(DIST, INFO.vpn["vpn-honest"].bundle)), Buffer.from("\n")]));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "app-compose.json"), root }))).toBe("E_MEASUREMENT_MISMATCH");
    copyFileSync(join(DIST, INFO.vpn["vpn-honest"].bundle), join(d, "other.bundle.mjs"));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "app-compose.json"), root, bundlePath: join(d, "other.bundle.mjs") }))).toBe("E_BUNDLE_ENTRY");
    writeFileSync(join(d, "other.json"), JSON.stringify({ manifest_version: 1, name: "plr-router" }, null, 2) + "\n");
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "other.json"), root }))).toBe("E_COMPOSE");
  });

  it("a compose pinning another node → E_MEASUREMENT_MISMATCH", async () => {
    const d = mkdtempSync(join(tmp, "n-"));
    const text = readFileSync(vpnCompose("vpn-honest"), "utf8").replace(INFO.runtime.node_sha256, "00".repeat(32));
    writeFileSync(join(d, "app-compose.json"), text);
    copyFileSync(join(DIST, INFO.vpn["vpn-honest"].bundle), join(d, "vpn.bundle.mjs"));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "app-compose.json"), root }))).toBe("E_MEASUREMENT_MISMATCH");
  });

  it("isolation flags (read-only fs, no child processes / addons / eval); env allowlist has no code-injection keys", () => {
    const vc = parseVpnCompose(new Uint8Array(readFileSync(vpnCompose("vpn-honest"))));
    expect(exitNodeFlags(vc, "/p")).toEqual(["--permission", "--allow-fs-read=/p", "--disallow-code-generation-from-strings", "--no-addons"]);
    for (const k of EXIT_ENV_ALLOWLIST) expect(k).toMatch(/^PLR_/);
    expect(EXIT_ENV_ALLOWLIST).toContain("PLR_VPN_PORT");
    expect(EXIT_ENV_ALLOWLIST).toContain("PLR_VPN_HOST");
    expect(EXIT_ENV_ALLOWLIST).not.toContain("PLR_MOCK_ROOT_SECRET_FILE" as never);
  });
});

// ------------------------------------------------------------------ live launch (needs Unix sockets)

async function unixSocketsAllowed(): Promise<boolean> {
  const p = join(tmp, "probe.sock");
  return new Promise((ok) => {
    const s = net.createServer();
    s.once("error", () => ok(false));
    s.listen(p, () => s.close(() => ok(true)));
  });
}
const canSock = await unixSocketsAllowed();
if (!canSock) console.warn("vpn-host.test: Unix sockets are not permitted in this sandbox; live VPN launch tests skipped");

const waitFor = async (re: RegExp, get: () => string, ms = 30_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const m = re.exec(get());
    if (m) return m;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("timeout waiting for " + re + "\n" + get());
};

describe.skipIf(!canSock)("launchVpn via the mock TDX host", () => {
  it("launches the test build (no LLM), tunnels to a local upstream, prints nothing about it, stops cleanly", async () => {
    const root = MockRoot.generate();
    const up = await startEchoUpstream();
    const runDir = join(tmp, "run");
    mkdirSync(runDir, { recursive: true });
    let out = "";
    const MARK = "vpn-live-" + Date.now();
    // A registry id alone: incomplete NEAR config ⇒ registration disabled.
    const h = await launchVpn({ composePath: vpnCompose("vpn-honest-test"), root, runDir, exitPort: 0, exitEnv: { PLR_VPN_REGISTRY: "vpnregistry.test.near" }, output: (s) => { out += s; } });
    try {
      const m = await waitFor(/plr-vpn: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/, () => out);
      expect(m[3]).toBe(INFO.vpn["vpn-honest-test"].compose.compose_hash);
      // A separate log line written after "listening": it may arrive in a later stdout chunk, so wait for it.
      await waitFor(/plr-vpn: registration_disabled/, () => out);
      expect(out).not.toContain("llm_ready");
      const url = m[1]!;
      const v = await attestExit(url, root.publicKey);
      // SPEC §5 rev 1.3: even asked with a registration nonce, the public endpoint hands out a SESSION quote only.
      const reg = await fetch(`${url}/v1/attestation?nonce=${toHex(registrationNonce("vpnregistry.test.near", "attacker.test.near"))}`);
      expect(reg.status).toBe(200);
      const regRd = new MockVerifier(root.publicKey).verify(Buffer.from(((await reg.json()) as { quote: string }).quote, "hex")).report.reportData;
      expect(toHex(regRd)).not.toBe(toHex(registrationReportData(v.x25519, v.ed25519, "vpnregistry.test.near", "attacker.test.near")));
      expect(toHex(v.keyHash)).toBe(m[2]);
      const t = await TestTunnel.open(Number(new URL(url).port), v, v.nonce);
      t.connect("127.0.0.1", up.port);
      await t.until(() => t.frames.length >= 1);
      t.send(FRAME.DATA, new TextEncoder().encode(MARK));
      t.send(FRAME.FIN);
      expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
      expect(t.data().toString()).toBe(MARK);
      await new Promise((r) => setTimeout(r, 100));
      expect(out).not.toContain(MARK);
      expect(mentionsNumber(out, up.port)).toBe(false);
      expect(statSync(h.socketPath).mode & 0o777).toBe(0o600);
    } finally {
      const dir = resolve(h.socketPath, "..");
      expect(await h.stop()).toBe(0);
      expect(existsSync(dir)).toBe(false);
      await up.close();
    }
  }, 60_000);

  it("the launched bundle (host isolation flags) resolves names only via the compose's DoH resolver; prints none of it", async () => {
    const root = MockRoot.generate();
    const up = await startEchoUpstream();
    const doh = await startFakeDoh(); // ephemeral port: a custom (self-consistent, unregistered) test compose points at it
    const NAME = `live-${Date.now()}.plr.test`;
    doh.set(NAME, ["127.0.0.1"]);
    const d = mkdtempSync(join(tmp, "doh-"));
    const cb = composeBytes(makeVpnCompose({ bundleSha256: INFO.vpn["vpn-honest-test"].bundle_sha256, nodeSha256: INFO.runtime.node_sha256, allowLoopback: true, doh: [doh.url] }));
    writeFileSync(join(d, "app-compose.json"), cb);
    copyFileSync(join(DIST, INFO.vpn["vpn-honest-test"].bundle), join(d, "vpn.bundle.mjs"));
    let out = "";
    const h = await launchVpn({ composePath: join(d, "app-compose.json"), root, runDir: tmp, exitPort: 0, output: (s) => { out += s; } });
    try {
      const url = (await waitFor(/plr-vpn: listening url=(\S+)/, () => out))[1]!;
      const v = await attestExit(url, root.publicKey);
      const port = Number(new URL(url).port);
      const ok = await TestTunnel.open(port, v, v.nonce);
      ok.connect(NAME, up.port);
      expect(await ok.until(() => ok.frames.length >= 1)).toBe(true);
      expect(ok.types()).toEqual([FRAME.CONNECT_OK]);
      expect(doh.hits()).toBe(2);
      ok.sock.destroy();
      doh.mode = "down"; // no fallback to the host resolver, even for a name it could resolve
      const nx = await TestTunnel.open(port, v, v.nonce);
      nx.connect("example.com", 443);
      expect(await nx.until(() => nx.frames.length >= 1)).toBe(true);
      expect(nx.types()).toEqual([FRAME.CONNECT_ERR]);
      nx.sock.destroy();
      expect(out).not.toContain(NAME);
      expect(out).not.toContain("example.com");
    } finally {
      await h.stop();
      await up.close();
      await doh.close();
    }
  }, 60_000);

  it("the evil logger build prints destinations and payload bytes (why clients must refuse it)", async () => {
    const root = MockRoot.generate();
    const up = await startEchoUpstream();
    let out = "";
    const MARK = "vpn-evil-" + Date.now();
    const h = await launchVpn({ composePath: vpnCompose("vpn-evil-logger"), root, runDir: tmp, exitPort: 0, output: (s) => { out += s; } });
    try {
      const url = (await waitFor(/plr-vpn: listening url=(\S+)/, () => out))[1]!;
      const v = await attestExit(url, root.publicKey);
      const t = await TestTunnel.open(Number(new URL(url).port), v, v.nonce);
      t.connect("127.0.0.1", up.port);
      await t.until(() => t.frames.length >= 1);
      t.send(FRAME.DATA, new TextEncoder().encode(MARK));
      await waitFor(new RegExp(`EVIL-VPN-LOGGER c2s: .*${MARK}`), () => out);
      expect(out).toContain(`127.0.0.1:${up.port}`);
      expect(out).toContain(MARK);
      t.sock.destroy();
    } finally {
      await h.stop();
      await up.close();
    }
  }, 60_000);
});
