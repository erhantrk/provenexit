// Regression tests for review finding "the node binary is not measured": the host pins the runtime closure of node
// in the compose, refuses to launch on a mismatch and runs a verified private copy.
import { afterAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { MockRoot, toHex } from "@plr/shared";
import { VPN_ENTRY, composeBytes, makeVpnCompose, parseVpnCompose } from "../src/compose.js";
import { HostError, measureVpnBoot } from "../src/mock-tdx/host.js";
import { installRuntime, measureRuntime, readMacho, runtimeDigest } from "../src/mock-tdx/runtime.js";

const DIST = resolve(import.meta.dirname, "..", "dist");
mkdirSync(resolve(import.meta.dirname, "..", ".run"), { recursive: true });
const tmp = mkdtempSync(join(resolve(import.meta.dirname, "..", ".run"), "rt-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const hostErr = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(HostError);
    return (e as HostError).code;
  }
  return "NO_THROW";
};

describe("runtime closure measurement", () => {
  it("covers the dylibs that hold the code, not just the executable stub", async () => {
    const c = await measureRuntime(process.execPath);
    expect(c.exe.role).toBe("exe");
    expect(c.exe.path).toBe(realpathSync(process.execPath));
    expect(c.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(c.digest).toBe(runtimeDigest(c.files));
    if (process.platform === "darwin") {
      // Homebrew node: an 85 KB stub; V8 and Node live in libnode.*.dylib.
      const libs = c.files.filter((f) => f.role === "lib").map((f) => f.name);
      if (statSync(c.exe.path).size < 1024 * 1024) expect(libs.some((n) => /^libnode\./.test(n))).toBe(true);
      expect(c.files.every((f) => !f.path.startsWith("/usr/lib/") && !f.path.startsWith("/System/"))).toBe(true);
    }
    expect((await measureRuntime(process.execPath)).digest).toBe(c.digest); // deterministic
  });

  it("the manifest digest changes with any file hash, name or role", () => {
    const f = [
      { role: "exe" as const, name: "node", sha256: "11".repeat(32) },
      { role: "lib" as const, name: "libnode.127.dylib", sha256: "22".repeat(32) },
    ];
    const d = runtimeDigest(f);
    expect(runtimeDigest([...f].reverse())).toBe(d); // order independent
    expect(runtimeDigest([f[0]!, { ...f[1]!, sha256: "23".repeat(32) }])).not.toBe(d);
    expect(runtimeDigest([f[0]!, { ...f[1]!, name: "libnode.128.dylib" }])).not.toBe(d);
    expect(runtimeDigest([f[0]!, { ...f[1]!, role: "exe" }])).not.toBe(d);
  });

  it("non-Mach-O executables (wrapper scripts) are refused", async () => {
    const script = join(tmp, "steal.sh");
    writeFileSync(script, "#!/bin/sh\nexec /usr/bin/env node \"$@\"\n", { mode: 0o755 });
    expect(await readMacho(script)).toBeNull();
    expect(await hostErr(measureRuntime(script))).toBe("E_RUNTIME_FORMAT");
    expect(await hostErr(measureRuntime(join(tmp, "missing")))).toBe("E_RUNTIME");
  });

  it.runIf(process.platform === "darwin")("installRuntime runs verified private copies and refuses a different digest", async () => {
    const c = await measureRuntime(process.execPath);
    const dir = mkdtempSync(join(tmp, "inst-"));
    const rt = await installRuntime(c, dir, c.digest);
    expect(statSync(rt.exe).mode & 0o777).toBe(0o500);
    const out = execFileSync(rt.exe, ["-e", "process.stdout.write(process.version)"], {
      env: { ...process.env, ...rt.env, DYLD_PRINT_LIBRARIES: "1" },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    expect(out).toBe(process.version);
    // Wrong pin ⇒ refused even though the copy itself is fine.
    expect(await hostErr(installRuntime(c, mkdtempSync(join(tmp, "inst-")), "00".repeat(32)))).toBe("E_MEASUREMENT_MISMATCH");
    // A library swapped after measurement: the copy is re-hashed, so it no longer reproduces the pin.
    const lib = c.files.find((f) => f.role === "lib");
    if (lib) {
      const fake = join(tmp, "swapped.dylib");
      copyFileSync(c.exe.path, fake);
      const swapped = { ...c, files: c.files.map((f) => (f === lib ? { ...f, path: fake } : f)) };
      expect(await hostErr(installRuntime(swapped, mkdtempSync(join(tmp, "inst-")), c.digest))).toBe("E_MEASUREMENT_MISMATCH");
    }
  }, 60_000); // copies + re-hashes the node closure (~120 MB) three times
});

describe("compose pins the runtime", () => {
  it("the built VPN composes pin this machine's node", async () => {
    const node = await measureRuntime(process.execPath);
    const info = JSON.parse(readFileSync(join(DIST, "build-info.json"), "utf8"));
    expect(info.runtime.node_sha256).toBe(node.digest);
    for (const v of ["vpn-honest", "vpn-honest-test", "vpn-evil-logger"]) {
      const c = parseVpnCompose(new Uint8Array(readFileSync(join(DIST, info.vpn[v].compose.file))));
      expect(c.vpn.node_sha256, v).toBe(node.digest);
    }
  });
});

describe("the host refuses unmeasured runtimes", () => {
  const root = MockRoot.generate();

  /** A VPN compose in its own dir (the honest bundle copied next to it) pinning `nodeSha256`. */
  function composeWith(nodeSha256: string) {
    const dir = mkdtempSync(join(tmp, "c-"));
    const info = JSON.parse(readFileSync(join(DIST, "build-info.json"), "utf8"));
    const bundle = readFileSync(join(DIST, info.vpn["vpn-honest-test"].bundle));
    writeFileSync(join(dir, VPN_ENTRY), bundle);
    const c = makeVpnCompose({ bundleSha256: toHex(sha256(bundle)), nodeSha256, allowLoopback: true });
    const composePath = join(dir, "app-compose.json");
    writeFileSync(composePath, composeBytes(c));
    return { composePath };
  }

  it("a compose pinning another node → E_MEASUREMENT_MISMATCH", async () => {
    const { composePath } = composeWith("ab".repeat(32));
    expect(await hostErr(measureVpnBoot({ composePath, root }))).toBe("E_MEASUREMENT_MISMATCH");
  });

  it("a node binary other than the pinned one → E_MEASUREMENT_MISMATCH", async () => {
    const node = (await measureRuntime(process.execPath)).digest;
    const { composePath } = composeWith(node);
    expect((await measureVpnBoot({ composePath, root })).nodeRuntime.digest).toBe(node);
    const fakeNode = join(tmp, "node");
    copyFileSync("/bin/ls", fakeNode);
    chmodSync(fakeNode, 0o755);
    expect(await hostErr(measureVpnBoot({ composePath, root, nodePath: fakeNode }))).toBe("E_MEASUREMENT_MISMATCH");
  });
});
