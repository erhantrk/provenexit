import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { parseVpnCompose } from "../src/compose.js";

const ENCLAVE = resolve(import.meta.dirname, "..");
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

/** Every file under `dir` (relative paths, sorted). */
function walk(dir: string, rel = ""): string[] {
  return readdirSync(join(dir, rel)).sort().flatMap((f) => {
    const r = rel ? `${rel}/${f}` : f;
    return statSync(join(dir, r)).isDirectory() ? walk(dir, r) : [r];
  });
}

function build(out: string, extra: string[] = []): Record<string, string> {
  execFileSync(process.execPath, [join(ENCLAVE, "build.mjs"), "--out", out, ...extra], { cwd: ENCLAVE, stdio: "pipe" });
  return Object.fromEntries(walk(out).map((f) => [f, sha(readFileSync(join(out, f)))]));
}

describe("reproducible build (SPEC §4, SPEC-VPN §2)", () => {
  it("two builds give byte-identical bundles and compose files; composes carry the real hashes", () => {
    const a = mkdtempSync(join(tmpdir(), "plr-build-a-"));
    const b = mkdtempSync(join(tmpdir(), "plr-build-b-"));
    try {
      const ha = build(a), hb = build(b);
      expect(Object.keys(ha)).toEqual([
        "build-info.json",
        "vpn-exit/vpn-evil-logger/app-compose.json", "vpn-exit/vpn-evil-logger/vpn.bundle.mjs",
        "vpn-exit/vpn-honest/app-compose.json", "vpn-exit/vpn-honest/vpn.bundle.mjs",
        "vpn-exit/vpn-honest-test/app-compose.json", "vpn-exit/vpn-honest-test/vpn.bundle.mjs",
      ]);
      expect(hb).toEqual(ha);

      const info = JSON.parse(readFileSync(join(a, "build-info.json"), "utf8"));
      expect(Object.keys(info).sort()).toEqual(["runtime", "vpn"]);
      const TEST_DOH = ["http://127.0.0.1:18253/dns-query"], PROD_DOH = ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"];
      for (const [v, loopback] of [["vpn-honest", false], ["vpn-honest-test", true], ["vpn-evil-logger", true]] as const) {
        const dir = `vpn-exit/${v}`;
        const c = parseVpnCompose(new Uint8Array(readFileSync(join(a, dir, "app-compose.json")))); // strict + canonical
        expect(c.vpn.bundle_sha256).toBe(ha[`${dir}/vpn.bundle.mjs`]);
        expect(c.vpn.node_sha256).toBe(info.runtime.node_sha256);
        expect(c.policy.egress).toEqual({ allow_loopback: loopback, deny_private: true });
        expect(c.policy.dns.doh).toEqual(loopback ? TEST_DOH : PROD_DOH); // SPEC-VPN §2
        expect(info.vpn[v]).toEqual({
          dir, bundle: `${dir}/vpn.bundle.mjs`, bundle_sha256: ha[`${dir}/vpn.bundle.mjs`], allow_loopback: loopback, doh: loopback ? TEST_DOH : PROD_DOH,
          compose: { file: `${dir}/app-compose.json`, compose_hash: ha[`${dir}/app-compose.json`] },
        });
      }
      expect(ha["vpn-exit/vpn-honest/vpn.bundle.mjs"]).toBe(ha["vpn-exit/vpn-honest-test/vpn.bundle.mjs"]);
      expect(ha["vpn-exit/vpn-honest/app-compose.json"]).not.toBe(ha["vpn-exit/vpn-honest-test/app-compose.json"]);
      expect(ha["vpn-exit/vpn-honest/vpn.bundle.mjs"]).not.toBe(ha["vpn-exit/vpn-evil-logger/vpn.bundle.mjs"]);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  }, 120_000);

  it("--node-exe-only (the exit image build): same bundles, node_sha256 = manifest digest of the node executable alone", () => {
    const a = mkdtempSync(join(tmpdir(), "plr-build-exe-"));
    try {
      const ha = build(a, ["--node-exe-only"]);
      const exe = realpathSync(process.execPath);
      const want = sha(new TextEncoder().encode(`${sha(readFileSync(exe))} exe ${basename(exe)}\n`));
      const info = JSON.parse(readFileSync(join(a, "build-info.json"), "utf8"));
      expect(info.runtime.node_sha256).toBe(want);
      const c = parseVpnCompose(new Uint8Array(readFileSync(join(a, "vpn-exit/vpn-honest/app-compose.json"))));
      expect(c.vpn.node_sha256).toBe(want);
      expect(c.vpn.bundle_sha256).toBe(ha["vpn-exit/vpn-honest/vpn.bundle.mjs"]);
      expect(c.policy.egress).toEqual({ allow_loopback: false, deny_private: true });
      // the flag changes only the runtime pin, never the code
      expect(ha["vpn-exit/vpn-honest/vpn.bundle.mjs"]).toBe(sha(readFileSync(join(ENCLAVE, "dist", "vpn-exit", "vpn-honest", "vpn.bundle.mjs"))));
    } finally {
      rmSync(a, { recursive: true, force: true });
    }
  }, 120_000);

  it("the honest bundle contains no evil code, no absolute paths, no source maps", () => {
    const honest = readFileSync(join(ENCLAVE, "dist", "vpn-exit", "vpn-honest", "vpn.bundle.mjs"), "utf8");
    const evil = readFileSync(join(ENCLAVE, "dist", "vpn-exit", "vpn-evil-logger", "vpn.bundle.mjs"), "utf8");
    expect(evil).toContain("EVIL-VPN-LOGGER");
    expect(honest).not.toMatch(/EVIL/);
    expect(honest).not.toContain(ENCLAVE);
    expect(honest).not.toMatch(/sourceMappingURL/);
  });
});
