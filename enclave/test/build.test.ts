import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { parseComboCompose, parseCompose, parseVpnCompose } from "../src/compose.js";

const ENCLAVE = resolve(import.meta.dirname, "..");
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

/** Every file under `dir` (relative paths, sorted). */
function walk(dir: string, rel = ""): string[] {
  return readdirSync(join(dir, rel)).sort().flatMap((f) => {
    const r = rel ? `${rel}/${f}` : f;
    return statSync(join(dir, r)).isDirectory() ? walk(dir, r) : [r];
  });
}

function build(out: string): Record<string, string> {
  execFileSync(process.execPath, [join(ENCLAVE, "build.mjs"), "--out", out], { cwd: ENCLAVE, stdio: "pipe" });
  return Object.fromEntries(walk(out).map((f) => [f, sha(readFileSync(join(out, f)))]));
}

describe("reproducible build (SPEC §4)", () => {
  it("two builds give byte-identical bundles and compose files; composes carry the real hashes", () => {
    const a = mkdtempSync(join(tmpdir(), "plr-build-a-"));
    const b = mkdtempSync(join(tmpdir(), "plr-build-b-"));
    try {
      const ha = build(a), hb = build(b);
      expect(Object.keys(ha)).toEqual([
        "app-compose.evil-logger.llama.json", "app-compose.evil-logger.mock.json", "app-compose.json",
        "app-compose.llama.json", "app-compose.mock.json", "build-info.json",
        ...["combo", "combo-test"].flatMap((v) => ["llama", "mock"].flatMap((k) => ["app-compose.json", "router.bundle.mjs", "vpn.bundle.mjs"].map((f) => `combo/${v}/${k}/${f}`))),
        "evil-logger.bundle.mjs", "router.bundle.mjs",
        "vpn-exit/vpn-evil-logger/app-compose.json", "vpn-exit/vpn-evil-logger/vpn.bundle.mjs",
        "vpn-exit/vpn-honest/app-compose.json", "vpn-exit/vpn-honest/vpn.bundle.mjs",
        "vpn-exit/vpn-honest-test/app-compose.json", "vpn-exit/vpn-honest-test/vpn.bundle.mjs",
      ]);
      expect(hb).toEqual(ha);

      const mockLlmSha = sha(readFileSync(join(ENCLAVE, "mock-llm", "server.mjs")));
      for (const [file, bundle, kind] of [
        ["app-compose.mock.json", "router.bundle.mjs", "mock"],
        ["app-compose.llama.json", "router.bundle.mjs", "llama.cpp"],
        ["app-compose.evil-logger.mock.json", "evil-logger.bundle.mjs", "mock"],
      ] as const) {
        const c = parseCompose(new Uint8Array(readFileSync(join(a, file)))); // strict + canonical
        expect(c.router.bundle_sha256).toBe(ha[bundle]);
        expect(c.router.entry).toBe(bundle);
        expect(c.llm.kind).toBe(kind);
        expect(c.llm.model_sha256).toBe(kind === "mock" ? mockLlmSha : "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db");
      }
      expect(ha["router.bundle.mjs"]).not.toBe(ha["evil-logger.bundle.mjs"]);
      expect(ha["app-compose.mock.json"]).not.toBe(ha["app-compose.evil-logger.mock.json"]);
      const info = JSON.parse(readFileSync(join(a, "build-info.json"), "utf8"));
      expect(info.variants.honest.compose.mock.compose_hash).toBe(ha["app-compose.mock.json"]);

      // VPN exit builds (SPEC-VPN §2), recorded under "vpn" without touching the router keys.
      expect(Object.keys(info).sort()).toEqual(["combo", "llm", "runtime", "variants", "vpn"]);
      const TEST_DOH = ["http://127.0.0.1:18253/dns-query"], PROD_DOH = ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"];
      for (const [v, loopback] of [["vpn-honest", false], ["vpn-honest-test", true], ["vpn-evil-logger", true]] as const) {
        const dir = `vpn-exit/${v}`;
        const c = parseVpnCompose(new Uint8Array(readFileSync(join(a, dir, "app-compose.json")))); // strict + canonical
        expect(c.vpn.bundle_sha256).toBe(ha[`${dir}/vpn.bundle.mjs`]);
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

      // Combo builds (SPEC-COMBO §1) under "combo": the honest bundles side by side with a plr-combo compose.
      const comboHashes = new Set<string>();
      for (const [v, loopback] of [["combo", false], ["combo-test", true]] as const) {
        expect(info.combo[v]).toMatchObject({ allow_loopback: loopback, doh: loopback ? TEST_DOH : PROD_DOH, router_bundle_sha256: ha["router.bundle.mjs"], vpn_bundle_sha256: ha["vpn-exit/vpn-honest/vpn.bundle.mjs"] });
        for (const [k, kind] of [["mock", "mock"], ["llama", "llama.cpp"]] as const) {
          const dir = `combo/${v}/${k}`;
          expect(info.combo[v].compose[k]).toEqual({ dir, file: `${dir}/app-compose.json`, compose_hash: ha[`${dir}/app-compose.json`] });
          const c = parseComboCompose(new Uint8Array(readFileSync(join(a, dir, "app-compose.json")))); // strict + canonical
          expect(c.router.llm.kind).toBe(kind);
          expect([c.router.bundle_sha256, c.vpn.bundle_sha256]).toEqual([ha[`${dir}/router.bundle.mjs`], ha[`${dir}/vpn.bundle.mjs`]]);
          expect(ha[`${dir}/router.bundle.mjs`]).toBe(ha["router.bundle.mjs"]);
          expect(ha[`${dir}/vpn.bundle.mjs`]).toBe(ha["vpn-exit/vpn-honest/vpn.bundle.mjs"]);
          expect(c.vpn.policy.egress).toEqual({ allow_loopback: loopback, deny_private: true });
          comboHashes.add(ha[`${dir}/app-compose.json`]!);
        }
      }
      expect(comboHashes.size).toBe(4);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  }, 120_000);

  it("the honest bundle contains no evil code, no absolute paths, no source maps", () => {
    const honest = readFileSync(join(ENCLAVE, "dist", "router.bundle.mjs"), "utf8");
    const evil = readFileSync(join(ENCLAVE, "dist", "evil-logger.bundle.mjs"), "utf8");
    expect(evil).toContain("EVIL-LOGGER");
    expect(honest).not.toMatch(/EVIL|stolen/i);
    expect(honest).not.toContain(ENCLAVE);
    expect(honest).not.toMatch(/sourceMappingURL/);
  });
});
