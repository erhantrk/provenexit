import { describe, it, expect, afterEach } from "vitest";
import { toHex } from "@plr/shared";
import { runCli, loadConfig, ConfigError } from "../src/index.js";
import { makeFakeRouter } from "./fake-router.js";
import { registryHandler, startFakeRpc } from "./fake-rpc.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function stack() {
  const r = makeFakeRouter();
  const srv = await r.listen();
  const rpc = await startFakeRpc(registryHandler(r.registry));
  closers.push(srv.close, rpc.close);
  const env = { PLR_ROUTER_URL: srv.url, PLR_NEAR_RPC: rpc.url, PLR_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: toHex(r.root.publicKey) };
  return { r, env };
}

function io() {
  const out: string[] = [];
  const err: string[] = [];
  const deltas: string[] = [];
  return { out, err, deltas, io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s) }, write: (s: string) => deltas.push(s) };
}

describe("plr CLI", () => {
  it("verify prints every check with ✔, MOCK ROOT, compose hash and the on-chain instance", async () => {
    const { r, env } = await stack();
    const t = io();
    expect(await runCli(["verify"], env, t.io, t.write)).toBe(0);
    const text = t.out.join("\n");
    expect(text.match(/✔/g)!.length).toBeGreaterThanOrEqual(14);
    expect(text).not.toContain("✘");
    expect(text).toContain("MOCK ROOT");
    expect(text).toContain(r.composeHash);
    expect(text).toContain("operator.test.near");
    expect(text).toContain("next seq");
  });

  it("verify marks the failing check with ✘ and its code, and exits 1", async () => {
    const { r, env } = await stack();
    r.registry.revokeCompose(r.composeHash);
    const t = io();
    expect(await runCli(["verify"], env, t.io, t.write)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toMatch(/✘ compose hash allowed by registry\s+\[E_COMPOSE_NOT_ALLOWED\]/);
    expect(text).toMatch(/✔ app-compose matches measured compose-hash/);
    expect(text).toMatch(/· OS measurement allowed by registry/);
    expect(text).toContain("REFUSED");
  });

  it("verify names the rev 1.3 session-nonce binding, and marks a pre-1.3 raw-nonce quote ✘ [E_NONCE]", async () => {
    const ok = await stack();
    const t = io();
    expect(await runCli(["verify"], ok.env, t.io, t.write)).toBe(0);
    expect(t.out.join("\n")).toContain(`✔ report_data binds client nonce as a session quote (SHA256("PLR-v1/session-nonce" ‖ nonce))`);

    const bad = await stack();
    bad.r.behaviour.quotePurpose = "raw-nonce";
    const u = io();
    expect(await runCli(["verify"], bad.env, u.io, u.write)).toBe(1);
    const text = u.out.join("\n");
    expect(text).toMatch(/✘ report_data binds client nonce as a session quote .*\[E_NONCE\]/);
    expect(text).toMatch(/✔ report_data binds router keys/);
    expect(text).toMatch(/· event log digests and boot sequence/);
  });

  it("verify attributes E_REGISTRY_UNAVAILABLE to the registry step that failed", async () => {
    const { env } = await stack();
    const t = io();
    expect(await runCli(["verify"], { ...env, PLR_NEAR_RPC: "http://127.0.0.1:1" }, t.io, t.write)).toBe(1);
    expect(t.out.join("\n")).toMatch(/✘ pinned root == registry root == verifier root\s+\[E_REGISTRY_UNAVAILABLE\]/);
  });

  it("chat streams the answer and reports the verified receipt", async () => {
    const { r, env } = await stack();
    const t = io();
    expect(await runCli(["chat", "hello there"], env, t.io, t.write)).toBe(0);
    expect(t.deltas.join("")).toBe("Hello, wörld 🌍\n");
    expect(t.err.join("\n")).toContain(r.composeHash);
    expect(JSON.parse(r.stats.plaintexts[0]!).messages).toEqual([{ role: "user", content: "hello there" }]);
  });

  it("chat refuses an unapproved router and sends nothing", async () => {
    const { r, env } = await stack();
    r.registry.revokeOs(r.osHash);
    const t = io();
    expect(await runCli(["chat", "secret"], env, t.io, t.write)).toBe(1);
    expect(t.err.join("\n")).toContain("E_OS_NOT_ALLOWED");
    expect(r.stats.chats).toBe(0);
  });

  it("usage and config errors exit 2 and fail closed", async () => {
    const t = io();
    expect(await runCli([], {}, t.io, t.write)).toBe(2);
    expect(await runCli(["chat"], {}, t.io, t.write)).toBe(2);
    expect(await runCli(["verify"], {}, t.io, t.write)).toBe(2);
    expect(() => loadConfig({ PLR_REGISTRY: "r.near" })).toThrow(ConfigError);
    expect(() => loadConfig({ PLR_REGISTRY: "r.near", PLR_TRUSTED_ROOT: "AB".repeat(64) })).toThrow(ConfigError);
    expect(() => loadConfig({ PLR_REGISTRY: "r.near", PLR_TRUSTED_ROOT: "00".repeat(64) })).toThrow(ConfigError);
  });
});
