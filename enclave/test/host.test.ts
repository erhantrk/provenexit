import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import net from "node:net";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { MockRoot, MockVerifier, isDebug, toHex, verifyEventLog } from "@plr/shared";
import { HostError, generateRootSecret, launchVpn, loadRootSecret, measureVpnBoot, type VpnHostHandle } from "../src/mock-tdx/host.js";
import { SocketAttester, parseQuoteResponse } from "../src/mock-tdx/attester.js";
import { attest } from "./helpers.js";
import { shortTmp } from "./short-tmp.js";

const DIST = resolve(import.meta.dirname, "..", "dist");
const COMPOSE = join(DIST, "vpn-exit", "vpn-honest-test", "app-compose.json");
const EVIL_BUNDLE = join(DIST, "vpn-exit", "vpn-evil-logger", "vpn.bundle.mjs");
// Short base path: Unix socket paths are limited to 104 bytes on macOS (os.tmpdir() can be long).
mkdirSync(resolve(import.meta.dirname, "..", ".run"), { recursive: true });
const tmp = shortTmp("t-");
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const hostErr = async (p: Promise<unknown>) => {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(HostError); return (e as HostError).code; }
  return "NO_THROW";
};

describe("MOCK ROOT secret file", () => {
  it("round-trips and requires mode 0600", async () => {
    const f = join(tmp, "root.hex");
    const root = await generateRootSecret(f);
    expect(statSync(f).mode & 0o777).toBe(0o600);
    expect(toHex(loadRootSecret(f).publicKey)).toBe(toHex(root.publicKey));
    await expect(generateRootSecret(f)).rejects.toThrow(); // never overwrites
    chmodSync(f, 0o644);
    expect(() => loadRootSecret(f)).toThrow(/E_ROOT_SECRET_MODE/);
  });
  it("rejects malformed content", () => {
    const f = join(tmp, "bad.hex");
    writeFileSync(f, "AB".repeat(32), { mode: 0o600 });
    expect(() => loadRootSecret(f)).toThrow(/E_ROOT_SECRET/);
    expect(() => loadRootSecret(join(tmp, "missing"))).toThrow(/E_ROOT_SECRET/);
  });
});

describe("measurement (SPEC §4): refuses to launch on any mismatch", () => {
  const root = MockRoot.generate();

  it("measures the built honest compose; boot event log binds the compose hash", async () => {
    const b = await measureVpnBoot({ composePath: COMPOSE, root });
    const bytes = readFileSync(COMPOSE);
    expect(b.composeHash).toBe(toHex(sha256(bytes)));
    const q = await b.attester.getQuote(new Uint8Array(64));
    const parsed = new MockVerifier(root.publicKey).verify(q.quote);
    expect(toHex(verifyEventLog(q.eventLog, parsed.report.rtmr[3]).composeHash)).toBe(b.composeHash);
    expect(isDebug(parsed.report)).toBe(false);
    const b2 = await measureVpnBoot({ composePath: COMPOSE, root });
    expect(b2.eventLog[3]!.event).toBe("instance-id");
    expect(b2.eventLog[3]!.event_payload).not.toBe(b.eventLog[3]!.event_payload); // fresh instance-id per boot
  });

  it("--debug sets the TD DEBUG attribute", async () => {
    const b = await measureVpnBoot({ composePath: COMPOSE, root, debug: true });
    const q = await b.attester.getQuote(new Uint8Array(64));
    expect(isDebug(new MockVerifier(root.publicKey).verify(q.quote).report)).toBe(true);
  });

  it("tampered bundle → E_MEASUREMENT_MISMATCH", async () => {
    const d = mkdtempSync(join(tmp, "m-"));
    copyFileSync(COMPOSE, join(d, "app-compose.json"));
    writeFileSync(join(d, "vpn.bundle.mjs"), Buffer.concat([readFileSync(join(DIST, "vpn-exit", "vpn-honest-test", "vpn.bundle.mjs")), Buffer.from("\n")]));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "app-compose.json"), root }))).toBe("E_MEASUREMENT_MISMATCH");
  });

  it("evil bundle under the honest compose → E_MEASUREMENT_MISMATCH", async () => {
    const d = mkdtempSync(join(tmp, "m-"));
    copyFileSync(COMPOSE, join(d, "app-compose.json"));
    copyFileSync(EVIL_BUNDLE, join(d, "vpn.bundle.mjs"));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "app-compose.json"), root }))).toBe("E_MEASUREMENT_MISMATCH");
  });

  it("non-canonical or malformed compose → E_COMPOSE; foreign entry → E_BUNDLE_ENTRY", async () => {
    const d = mkdtempSync(join(tmp, "m-"));
    const c = JSON.parse(readFileSync(COMPOSE, "utf8"));
    writeFileSync(join(d, "a.json"), JSON.stringify(c));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "a.json"), root }))).toBe("E_COMPOSE");
    writeFileSync(join(d, "b.json"), readFileSync(COMPOSE, "utf8").replace('"none"', '"all"'));
    expect(await hostErr(measureVpnBoot({ composePath: join(d, "b.json"), root }))).toBe("E_COMPOSE");
    copyFileSync(EVIL_BUNDLE, join(d, "evil.bundle.mjs"));
    expect(await hostErr(measureVpnBoot({ composePath: COMPOSE, root, bundlePath: join(d, "evil.bundle.mjs") }))).toBe("E_BUNDLE_ENTRY");
  });
});

describe("quote-service response parsing", () => {
  it("is strict", () => {
    expect(() => parseQuoteResponse("{}")).toThrow();
    expect(() => parseQuoteResponse(JSON.stringify({ quote: "AB", event_log: [] }))).toThrow();
    expect(() => parseQuoteResponse(JSON.stringify({ quote: "00".repeat(828), event_log: [{ imr: 3 }] }))).toThrow();
    expect(() => parseQuoteResponse(JSON.stringify({ quote: "00".repeat(828), event_log: [], x: 1 }))).toThrow();
    expect(parseQuoteResponse(JSON.stringify({ quote: "00".repeat(828), event_log: [] })).quote.length).toBe(828);
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
if (!canSock) console.warn("host.test: Unix sockets are not permitted in this sandbox; live launch tests skipped");

describe.skipIf(!canSock)("launch via the mock TDX host (SPEC §6.1)", () => {
  let root: MockRoot;
  let out = "";
  let h: VpnHostHandle;
  let url = "";
  const runDir = join(tmp, "run");

  const waitFor = async (re: RegExp, get: () => string, ms = 30_000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const m = re.exec(get());
      if (m) return m;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error("timeout waiting for " + re);
  };

  beforeAll(async () => {
    root = MockRoot.generate();
    mkdirSync(runDir, { recursive: true });
    h = await launchVpn({ composePath: COMPOSE, root, runDir, exitPort: 0, output: (s) => { out += s; } });
    url = (await waitFor(/plr-vpn: listening url=(\S+)/, () => out))[1]!;
  });
  afterAll(async () => { await h?.stop(); });

  it("serves quotes on a 0600 socket in a 0700 private directory", async () => {
    expect(statSync(h.socketPath).mode & 0o777).toBe(0o600);
    expect(statSync(resolve(h.socketPath, "..")).mode & 0o777).toBe(0o700);
    const q = await new SocketAttester(h.socketPath).getQuote(new Uint8Array(64).fill(7));
    const parsed = new MockVerifier(root.publicKey).verify(q.quote);
    expect(toHex(parsed.report.reportData)).toBe("07".repeat(64));
  });

  it("the launched exit attests with the measured compose", async () => {
    const v = await attest(url, root.publicKey);
    expect(toHex(v.composeHash)).toBe(h.boot.composeHash);
  });

  it("stop() terminates the exit and removes the private directory", async () => {
    const dir = resolve(h.socketPath, "..");
    expect(await h.stop()).toBe(0);
    expect(existsSync(dir)).toBe(false);
    expect(h.exit.exitCode !== null || h.exit.signalCode !== null).toBe(true);
  });

  it("refuses to launch a mismatching build (nothing started)", async () => {
    const d = mkdtempSync(join(tmp, "bad-"));
    copyFileSync(COMPOSE, join(d, "app-compose.json"));
    copyFileSync(EVIL_BUNDLE, join(d, "vpn.bundle.mjs"));
    let o = "";
    expect(await hostErr(launchVpn({ composePath: join(d, "app-compose.json"), root, runDir, output: (s) => { o += s; } }))).toBe("E_MEASUREMENT_MISMATCH");
    expect(o).toContain("plr-host: launch_refused code=E_MEASUREMENT_MISMATCH");
  });
});
