// Regression tests for review findings "llama-server / node binaries are not measured" and "llama-server prompt
// cache reuse": the host pins the runtime closures of node and llama-server in the compose, refuses to launch
// on a mismatch, runs verified private copies, and launches llama-server with prompt caching disabled.
import { afterAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { MockRoot, toHex } from "@plr/shared";
import { composeBytes, makeCompose, parseCompose } from "../src/compose.js";
import { HostError, DEFAULT_LLAMA_SERVER, llamaServerArgs, measureBoot } from "../src/mock-tdx/host.js";
import { installRuntime, measureRuntime, readMacho, runtimeDigest } from "../src/mock-tdx/runtime.js";
import { HttpLlmClient, upstreamBody } from "../src/llm.js";

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
const hasLlama = (() => {
  try {
    return statSync(DEFAULT_LLAMA_SERVER).isFile();
  } catch {
    return false;
  }
})();

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

  it.runIf(hasLlama)("includes llama-server's libraries and ggml's dlopen'd backends", async () => {
    const c = await measureRuntime(DEFAULT_LLAMA_SERVER);
    const names = c.files.map((f) => f.name);
    expect(names).toContain("llama-server");
    expect(names.some((n) => /^libllama/.test(n))).toBe(true);
    expect(names.some((n) => /^libggml-cpu.*\.so$/.test(n) || /^libggml-metal\.so$/.test(n))).toBe(true);
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
    writeFileSync(script, "#!/bin/sh\nexec /opt/homebrew/bin/llama-server \"$@\"\n", { mode: 0o755 });
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

describe("compose pins the runtimes", () => {
  it("requires router.node_sha256 and llm.runtime_sha256; a mock LLM must pin the same node", () => {
    const ok = makeCompose({ kind: "mock", modelSha256: "11".repeat(32), runtime: "node-mock-llm", runtimeSha256: "33".repeat(32), bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", nodeSha256: "33".repeat(32) });
    expect(parseCompose(composeBytes(ok)).router.node_sha256).toBe("33".repeat(32));
    expect(() => makeCompose({ kind: "mock", modelSha256: "11".repeat(32), runtime: "node-mock-llm", runtimeSha256: "44".repeat(32), bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", nodeSha256: "33".repeat(32) })).toThrow(/runtime_sha256/);
    const legacy = new TextEncoder().encode(
      JSON.stringify({ llm: { kind: "mock", model_sha256: "11".repeat(32), runtime: "x" }, manifest_version: 1, name: "plr-router", policy: { disk: "none", egress: [], logs: "none" }, router: { bundle_sha256: "22".repeat(32), entry: "router.bundle.mjs" } }, null, 2) + "\n",
    );
    expect(() => parseCompose(legacy)).toThrow(/llm keys/);
  });

  it("the built composes pin this machine's node (and llama-server)", async () => {
    const node = await measureRuntime(process.execPath);
    const mock = parseCompose(new Uint8Array(readFileSync(join(DIST, "app-compose.mock.json"))));
    expect(mock.router.node_sha256).toBe(node.digest);
    expect(mock.llm.runtime_sha256).toBe(node.digest);
    const llama = parseCompose(new Uint8Array(readFileSync(join(DIST, "app-compose.llama.json"))));
    expect(llama.router.node_sha256).toBe(node.digest);
    if (hasLlama && !process.env.PLR_LLAMA_SERVER) expect(llama.llm.runtime_sha256).toBe((await measureRuntime(DEFAULT_LLAMA_SERVER)).digest);
  });
});

describe("the host refuses unmeasured runtimes", () => {
  const root = MockRoot.generate();

  /** A compose in its own dir (bundle copied next to it) with chosen runtime pins and a tiny "model" file. */
  function composeWith(o: { kind: "mock" | "llama.cpp"; nodeSha256: string; runtimeSha256: string }) {
    const dir = mkdtempSync(join(tmp, "c-"));
    const bundle = readFileSync(join(DIST, "router.bundle.mjs"));
    writeFileSync(join(dir, "router.bundle.mjs"), bundle);
    const model = join(dir, "model.gguf");
    writeFileSync(model, "not really a model");
    const llmFile = o.kind === "mock" ? join(DIST, "..", "mock-llm", "server.mjs") : model;
    const c = makeCompose({
      kind: o.kind,
      modelSha256: toHex(sha256(readFileSync(llmFile))),
      runtime: o.kind === "mock" ? "node-mock-llm" : "llama.cpp/llama-server",
      runtimeSha256: o.runtimeSha256,
      bundleSha256: toHex(sha256(bundle)),
      entry: "router.bundle.mjs",
      nodeSha256: o.nodeSha256,
    });
    const composePath = join(dir, "app-compose.json");
    writeFileSync(composePath, composeBytes(c));
    return { composePath, llmFile };
  }

  it("a compose pinning another node → E_MEASUREMENT_MISMATCH", async () => {
    const other = "ab".repeat(32);
    const { composePath, llmFile } = composeWith({ kind: "mock", nodeSha256: other, runtimeSha256: other });
    expect(await hostErr(measureBoot({ composePath, llmFile, root }))).toBe("E_MEASUREMENT_MISMATCH");
  });

  it("a node binary other than the pinned one → E_MEASUREMENT_MISMATCH", async () => {
    const node = (await measureRuntime(process.execPath)).digest;
    const { composePath, llmFile } = composeWith({ kind: "mock", nodeSha256: node, runtimeSha256: node });
    expect((await measureBoot({ composePath, llmFile, root })).nodeRuntime.digest).toBe(node);
    const fakeNode = join(tmp, "node");
    copyFileSync("/bin/ls", fakeNode);
    chmodSync(fakeNode, 0o755);
    expect(await hostErr(measureBoot({ composePath, llmFile, root, nodePath: fakeNode }))).toBe("E_MEASUREMENT_MISMATCH");
  });

  it.runIf(hasLlama)("--llama-server pointing at a wrapper or another binary is refused", async () => {
    const node = (await measureRuntime(process.execPath)).digest;
    const llama = (await measureRuntime(DEFAULT_LLAMA_SERVER)).digest;
    const { composePath, llmFile } = composeWith({ kind: "llama.cpp", nodeSha256: node, runtimeSha256: llama });
    expect((await measureBoot({ composePath, llmFile, root })).llmRuntime.digest).toBe(llama);
    const steal = join(tmp, "steal.sh");
    writeFileSync(steal, "#!/bin/sh\nexec /opt/homebrew/bin/llama-server \"$@\"\n", { mode: 0o755 });
    expect(await hostErr(measureBoot({ composePath, llmFile, root, llamaServer: steal }))).toBe("E_RUNTIME_FORMAT");
    expect(await hostErr(measureBoot({ composePath, llmFile, root, llamaServer: process.execPath }))).toBe("E_MEASUREMENT_MISMATCH");
  });
});

describe("llama-server prompt-cache side channel", () => {
  it("the LLM is locked to the router by a per-boot API key (mock LLM honours it like llama-server)", async () => {
    // @ts-expect-error plain JS module without types
    const mod: unknown = await import("../mock-llm/server.mjs");
    const { createMockLlm } = mod as { createMockLlm(o?: { apiKey?: string }): import("node:http").Server };
    const key = "cd".repeat(32);
    const srv = createMockLlm({ apiKey: key });
    await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const body = JSON.stringify({ messages: [{ role: "user", content: "x" }], stream: true });
    try {
      expect((await fetch(`${base}/health`)).status).toBe(200);
      expect((await fetch(`${base}/v1/chat/completions`, { method: "POST", body })).status).toBe(401);
      expect((await fetch(`${base}/v1/chat/completions`, { method: "POST", body, headers: { authorization: "Bearer " + "cd".repeat(31) + "ce" } })).status).toBe(401);
      const ok = await fetch(`${base}/v1/chat/completions`, { method: "POST", body, headers: { authorization: `Bearer ${key}` } });
      expect(ok.status).toBe(200);
      await ok.text();
      const llm = new HttpLlmClient((srv.address() as AddressInfo).port, { apiKey: key });
      let text = "";
      for await (const d of await llm.chat({ messages: [{ role: "user", content: "hi" }] }, new AbortController().signal)) text += d;
      expect(text).toMatch(/^mock-answer-[0-9a-f]{16}$/);
      const wrong = new HttpLlmClient((srv.address() as AddressInfo).port, { apiKey: "00".repeat(32) });
      await expect(wrong.chat({ messages: [{ role: "user", content: "hi" }] }, new AbortController().signal)).rejects.toThrow(/E_UPSTREAM/);
    } finally {
      await new Promise<void>((ok) => srv.close(() => ok()));
    }
  });

  it("PLR_LLM_API_KEY is strictly validated by the router config", async () => {
    const { loadConfig } = await import("../src/config.js");
    const env = { PLR_TDX_SOCKET: "/tmp/q.sock", PLR_APP_COMPOSE_PATH: "/tmp/c.json" };
    expect(loadConfig(env).llmApiKey).toBeNull();
    expect(loadConfig({ ...env, PLR_LLM_API_KEY: "ef".repeat(32) }).llmApiKey).toBe("ef".repeat(32));
    expect(() => loadConfig({ ...env, PLR_LLM_API_KEY: "EF".repeat(32) })).toThrow(/PLR_LLM_API_KEY/);
    expect(() => loadConfig({ ...env, PLR_LLM_API_KEY: "ef" })).toThrow(/PLR_LLM_API_KEY/);
  });

  it("is launched with every prompt/KV cache reuse disabled and a single slot", () => {
    const a = llamaServerArgs("/m.gguf", 18080);
    const after = (flag: string) => a[a.indexOf(flag) + 1];
    expect(a).toContain("--no-cache-prompt");
    expect(after("--cache-reuse")).toBe("0");
    expect(after("-cram")).toBe("0");
    expect(a).toContain("--no-cache-idle-slots");
    expect(after("-np")).toBe("1");
    expect(after("--host")).toBe("127.0.0.1");
    expect(a).toContain("--no-slots");
  });

  it("the router asks for cache_prompt:false on every upstream request", async () => {
    expect(upstreamBody({ messages: [{ role: "user", content: "x" }] })).toEqual({ messages: [{ role: "user", content: "x" }], stream: true, cache_prompt: false });
    let seen: unknown;
    let auth: unknown;
    const srv = createServer((req, res) => {
      auth = req.headers.authorization;
      const parts: Buffer[] = [];
      req.on("data", (c: Buffer) => parts.push(c));
      req.on("end", () => {
        seen = JSON.parse(Buffer.concat(parts).toString("utf8"));
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.end('data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n');
      });
    });
    await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
    try {
      const key = "ab".repeat(32);
      expect(() => new HttpLlmClient(1, { apiKey: "AB".repeat(32) })).toThrow(/api key/);
      const llm = new HttpLlmClient((srv.address() as AddressInfo).port, { apiKey: key });
      const out: string[] = [];
      for await (const d of await llm.chat({ messages: [{ role: "user", content: "hi" }], stream: false } as never, new AbortController().signal)) out.push(d);
      expect(out.join("")).toBe("ok");
      expect(seen).toMatchObject({ stream: true, cache_prompt: false });
      expect(auth).toBe(`Bearer ${key}`);
    } finally {
      await new Promise<void>((ok) => srv.close(() => ok()));
    }
  });
});
