import { describe, it, expect, afterEach } from "vitest";
import { connect as tcpConnect, createServer as tcpServer, type AddressInfo } from "node:net";
import { toHex } from "@plr/shared";
import { runCli, loadVpnConfig, ConfigError } from "../src/index.js";
import { startFakeExit, startDestination } from "./fake-exit.js";
import { registryHandler, startFakeRpc } from "./fake-rpc.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function stack() {
  const X = await startFakeExit();
  const rpc = await startFakeRpc(registryHandler(X.registry));
  closers.push(X.close, rpc.close);
  const env = { PLR_VPN_URL: X.url, PLR_NEAR_RPC: rpc.url, PLR_VPN_REGISTRY: "vpnregistry.test.near", PLR_TRUSTED_ROOT: toHex(X.root.publicKey) };
  return { X, env };
}

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (s: string) => out.push(s), err: (s: string) => err.push(s) } };
}

describe("plr vpn verify", () => {
  it("prints every check with ✔ (incl. the per-connection registry re-check), MOCK ROOT, build policy, instance", async () => {
    const { X, env } = await stack();
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text.match(/✔/g)!.length).toBeGreaterThanOrEqual(16);
    expect(text).not.toContain("✘");
    expect(text).toContain("MOCK ROOT (local test root, NOT Intel)");
    expect(text).toContain("registry re-check before each connection");
    expect(text).toContain("remote DNS");
    expect(text).toContain(X.composeHash);
    expect(text).toContain("plr-vpn · egress deny_private=true allow_loopback=true");
    expect(text).toContain("TEST BUILD");
    expect(text).toContain("vpn-operator.test.near");
  });

  it("shows the exit policy of a plr-combo compose (SPEC-COMBO: router + exit in one TD)", async () => {
    const h = (b: string) => b.repeat(32);
    const combo = JSON.stringify({
      manifest_version: 1,
      name: "plr-combo",
      router: {
        bundle_sha256: h("11"), entry: "router.bundle.mjs", node_sha256: h("44"),
        llm: { kind: "mock", model_sha256: h("22"), runtime: "node", runtime_sha256: h("44") },
        policy: { disk: "none", egress: [], logs: "none" },
      },
      vpn: {
        bundle_sha256: h("33"), entry: "vpn.bundle.mjs", node_sha256: h("44"),
        policy: { disk: "none", dns: { doh: ["https://1.1.1.1/dns-query"] }, egress: { allow_loopback: false, deny_private: true }, logs: "none" },
      },
    }) + "\n";
    const X = await startFakeExit({ composeText: combo });
    const rpc = await startFakeRpc(registryHandler(X.registry));
    closers.push(X.close, rpc.close);
    const t = io();
    const env = { PLR_VPN_URL: X.url, PLR_NEAR_RPC: rpc.url, PLR_VPN_REGISTRY: "vpnregistry.test.near", PLR_TRUSTED_ROOT: toHex(X.root.publicKey) };
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text).toContain("plr-combo · egress deny_private=true allow_loopback=false · DNS over HTTPS via https://1.1.1.1/dns-query");
    expect(text).not.toContain("TEST BUILD");
  });

  it("marks the failing check with ✘ and exits 1", async () => {
    const { X, env } = await stack();
    X.registry.revokeOs(X.osHash);
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toMatch(/✘ OS measurement allowed by registry\s+\[E_OS_NOT_ALLOWED\]/);
    expect(text).toMatch(/✔ compose hash allowed by registry/);
    expect(text).toMatch(/· registry re-check before each connection .*\(not checked\)/);
    expect(text).toContain("REFUSED — E_OS_NOT_ALLOWED");
  });

  it("uses PLR_VPN_REGISTRY, not PLR_REGISTRY, and requires it", async () => {
    const { env } = await stack();
    const t = io();
    const { PLR_VPN_REGISTRY: _, ...noVpnReg } = env;
    expect(await runCli(["vpn", "verify"], { ...noVpnReg, PLR_REGISTRY: "registry.test.near" }, t.io)).toBe(2);
    expect(t.err.join("\n")).toContain("PLR_VPN_REGISTRY is required");
  });
});

describe("plr vpn", () => {
  it("verifies, serves SOCKS5 on the configured loopback port, prints the socks5h URL, stops cleanly", async () => {
    const { env } = await stack();
    const D = await startDestination();
    closers.push(D.close);
    let stop!: () => void;
    const stopped = new Promise<void>((r) => (stop = r));
    const t = io();
    // Port 0 is not allowed via env (must be a fixed port); pick a free ephemeral one first.
    const free = await new Promise<number>((ok) => {
      const s = tcpServer().listen(0, "127.0.0.1", () => {
        const p = (s.address() as AddressInfo).port;
        s.close(() => ok(p));
      });
    });
    const run = runCli(["vpn"], { ...env, PLR_VPN_SOCKS_PORT: String(free) }, t.io, undefined, undefined, () => stopped);
    for (let i = 0; i < 100 && !t.out.join("\n").includes("socks5h://"); i++) await new Promise((r) => setTimeout(r, 20));
    const text = t.out.join("\n");
    expect(text).toContain(`socks5h://127.0.0.1:${free}`);
    expect(text).toContain("VPN exit verified");
    expect(text).toMatch(new RegExp(`^✔ SOCKS5 proxy on socks5h://127\\.0\\.0\\.1:${free}$`, "m"));
    expect(text).toContain("remote DNS, CONNECT only");
    // One request through the proxy.
    const got = await new Promise<string>((ok, fail) => {
      const sock = tcpConnect(free, "127.0.0.1");
      let buf = Buffer.alloc(0);
      sock.on("error", fail);
      sock.on("connect", () => {
        sock.write(Buffer.from([5, 1, 0]));
        sock.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, D.port >> 8, D.port & 0xff]));
        sock.write("GET /cli HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n");
      });
      sock.on("data", (c: Buffer) => (buf = Buffer.concat([buf, c])));
      sock.on("end", () => {
        sock.end();
        ok(buf.toString("latin1"));
      });
    });
    expect(got).toContain("dest-ok:/cli");
    stop();
    expect(await run).toBe(0);
  });

  it("refuses to start when the exit fails verification", async () => {
    const { X, env } = await stack();
    X.registry.revokeCompose(X.composeHash);
    const t = io();
    expect(await runCli(["vpn"], env, t.io, undefined, undefined, () => Promise.resolve())).toBe(1);
    expect(t.err.join("\n")).toContain("E_COMPOSE_NOT_ALLOWED");
    expect(t.out.join("\n")).not.toContain("socks5h://");
  });

  it("usage errors and help", async () => {
    const t = io();
    expect(await runCli(["vpn", "nope"], {}, t.io)).toBe(2);
    expect(t.err.join("\n")).toContain("plr vpn verify");
    const h = io();
    expect(await runCli(["--help"], {}, h.io)).toBe(2);
    expect(h.err.join("\n")).toContain("plr vpn [verify]");
    expect(h.err.join("\n")).toContain("PLR_VPN_REGISTRY");
  });

  it("loadVpnConfig validates every variable and applies the SPEC-VPN defaults", async () => {
    const { env } = await stack();
    const base = { PLR_VPN_REGISTRY: "vpn.test.near", PLR_TRUSTED_ROOT: env.PLR_TRUSTED_ROOT };
    const c = loadVpnConfig(base);
    expect(c.exitUrl).toBe("http://127.0.0.1:18200");
    expect(c.socksPort).toBe(18180);
    expect(c.rpcUrl).toBe("http://127.0.0.1:3030");
    expect(c.attestTtlMs).toBe(60_000);
    expect(loadVpnConfig({ ...base, PLR_VPN_ATTEST_TTL_MS: "0" }).attestTtlMs).toBe(0);
    for (const bad of [
      { ...base, PLR_TRUSTED_ROOT: "" },
      { ...base, PLR_TRUSTED_ROOT: "ab".repeat(64) },
      { ...base, PLR_VPN_REGISTRY: "" },
      { ...base, PLR_NEAR_RPC: "http://rpc.example.com" },
      { ...base, PLR_VPN_SOCKS_PORT: "70000" },
      { ...base, PLR_VPN_SOCKS_PORT: "-1" },
      { ...base, PLR_VPN_ATTEST_TTL_MS: "1.5" },
      { ...base, PLR_VPN_ATTEST_TTL_MS: "99999999" },
    ])
      expect(() => loadVpnConfig(bad), JSON.stringify(bad)).toThrow(ConfigError);
  });
});

// ---------------------------------------------------------------- two-hop (SPEC-VPN §10)

async function twoHopStack() {
  const E = await startFakeExit({ operator: "entry-op.test.near" });
  const X = await startFakeExit({ root: E.root, registry: E.registry, operator: "exit-op.test.near", bundleSha: "55".repeat(32) });
  E.registry.approveOperator("entry-op.test.near", "org-a");
  E.registry.approveOperator("exit-op.test.near", "org-b");
  const rpc = await startFakeRpc(registryHandler(E.registry));
  closers.push(E.close, X.close, rpc.close);
  const env = {
    PLR_VPN_ENTRY_URL: E.url,
    PLR_VPN_URL: X.url,
    PLR_NEAR_RPC: rpc.url,
    PLR_VPN_REGISTRY: "vpnregistry.test.near",
    PLR_TRUSTED_ROOT: toHex(E.root.publicKey),
  };
  return { E, X, env };
}

describe("plr vpn verify — two-hop (PLR_VPN_ENTRY_URL)", () => {
  it("prints every check of both hops and the operator-organization check", async () => {
    const { E, X, env } = await twoHopStack();
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(0);
    const text = t.out.join("\n");
    expect(text).not.toContain("✘");
    expect(text).toContain("two-hop");
    expect(text).toMatch(/entry hop[\s\S]*exit hop/);
    expect(text.match(/registry re-check before each connection/g)).toHaveLength(2);
    expect(text).toContain("✔ entry operator approved by the registry owner (organization org-a)");
    expect(text).toContain("✔ exit operator approved by the registry owner (organization org-b)");
    expect(text).toContain("✔ entry and exit run by different organizations (org-a ≠ org-b)");
    expect(text).toContain("VERIFIED (two-hop: org-a → org-b)");
    expect(text).toContain(E.composeHash);
    expect(text).toContain(X.composeHash);
    expect(text).toContain("exit-op.test.near");
    expect(text).toContain("entry-op.test.near");
    expect(text.match(/✔/g)!.length).toBeGreaterThanOrEqual(30);
  });

  it("same organization ⇒ ✘ on the organization line, exit code 1", async () => {
    const { E, env } = await twoHopStack();
    E.registry.approveOperator("exit-op.test.near", "org-a");
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toContain("✔ exit operator approved by the registry owner (organization org-a)");
    expect(text).toMatch(/✘ entry and exit run by different organizations\s+\[E_SAME_OPERATOR\]/);
    expect(text).toContain("REFUSED — E_SAME_OPERATOR");
  });

  it("unapproved entry operator ⇒ ✘ on the entry, the exit is not checked", async () => {
    const { E, X, env } = await twoHopStack();
    E.registry.revokeOperator("entry-op.test.near");
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(1);
    const text = t.out.join("\n");
    expect(text).toMatch(/✘ entry operator approved by the registry owner\s+\[E_OPERATOR_UNAPPROVED\]/);
    expect(text).toContain("exit hop  (not checked)");
    expect(X.stats.attestations).toBe(0);
  });

  it("a failing exit check is attributed to the exit hop", async () => {
    const { E, X, env } = await twoHopStack();
    E.registry.revokeCompose(X.composeHash);
    const t = io();
    expect(await runCli(["vpn", "verify"], env, t.io)).toBe(1);
    const text = t.out.join("\n");
    const exitPart = text.slice(text.indexOf("exit hop ("));
    expect(exitPart).toMatch(/✘ compose hash allowed by registry\s+\[E_COMPOSE_NOT_ALLOWED\]/);
    expect(exitPart).toMatch(/· exit operator approved.*\(not checked\)/);
    expect(text.slice(0, text.indexOf("exit hop ("))).not.toContain("✘");
  });
});

describe("plr vpn — two-hop", () => {
  it("verifies both hops, serves SOCKS5, proxies through entry → exit", async () => {
    const { E, X, env } = await twoHopStack();
    const D = await startDestination();
    closers.push(D.close);
    let stop!: () => void;
    const stopped = new Promise<void>((r) => (stop = r));
    const t = io();
    const free = await new Promise<number>((ok) => {
      const s = tcpServer().listen(0, "127.0.0.1", () => {
        const p = (s.address() as AddressInfo).port;
        s.close(() => ok(p));
      });
    });
    const run = runCli(["vpn"], { ...env, PLR_VPN_SOCKS_PORT: String(free) }, t.io, undefined, undefined, () => stopped);
    for (let i = 0; i < 200 && !t.out.join("\n").includes("socks5h://"); i++) await new Promise((r) => setTimeout(r, 20));
    const text = t.out.join("\n");
    expect(text).toContain("two-hop VPN verified");
    expect(text).toContain("entry (org-a) → exit (org-b)");
    expect(text).toContain(`socks5h://127.0.0.1:${free}`);
    expect(text).toMatch(new RegExp(`^✔ SOCKS5 proxy on socks5h://127\\.0\\.0\\.1:${free}$`, "m"));
    expect(text).toContain("remote DNS, CONNECT only");
    const got = await new Promise<string>((ok, fail) => {
      const sock = tcpConnect(free, "127.0.0.1");
      let buf = Buffer.alloc(0);
      sock.on("error", fail);
      sock.on("connect", () => {
        sock.write(Buffer.from([5, 1, 0]));
        sock.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, D.port >> 8, D.port & 0xff]));
        sock.write("GET /cli-two HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n");
      });
      sock.on("data", (c: Buffer) => (buf = Buffer.concat([buf, c])));
      sock.on("end", () => {
        sock.end();
        ok(buf.toString("latin1"));
      });
    });
    expect(got).toContain("dest-ok:/cli-two");
    expect(X.stats.destinations).toContain(`127.0.0.1:${D.port}`);
    expect(E.stats.destinations.every((d) => d === `127.0.0.1:${new URL(X.url).port}`)).toBe(true);
    stop();
    expect(await run).toBe(0);
  });

  it("refuses to start when the organizations are the same", async () => {
    const { E, env } = await twoHopStack();
    E.registry.approveOperator("exit-op.test.near", "org-a");
    const t = io();
    expect(await runCli(["vpn"], env, t.io, undefined, undefined, () => Promise.resolve())).toBe(1);
    expect(t.err.join("\n")).toContain("E_SAME_OPERATOR");
    expect(t.out.join("\n")).not.toContain("socks5h://");
  });

  it("loadVpnConfig: PLR_VPN_ENTRY_URL is optional and validated; usage mentions it", async () => {
    const { env } = await twoHopStack();
    const base = { PLR_VPN_REGISTRY: "vpn.test.near", PLR_TRUSTED_ROOT: env.PLR_TRUSTED_ROOT };
    expect(loadVpnConfig(base).entryUrl).toBeUndefined();
    expect(loadVpnConfig({ ...base, PLR_VPN_ENTRY_URL: "" }).entryUrl).toBeUndefined();
    expect(loadVpnConfig({ ...base, PLR_VPN_ENTRY_URL: "http://127.0.0.1:18201" }).entryUrl).toBe("http://127.0.0.1:18201");
    expect(() => loadVpnConfig({ ...base, PLR_VPN_ENTRY_URL: "socks5://x" })).toThrow(ConfigError);
    expect(() => loadVpnConfig({ ...base, PLR_VPN_URL: "nope" })).toThrow(ConfigError);
    const t = io();
    expect(await runCli(["vpn", "nope"], {}, t.io)).toBe(2);
    expect(t.err.join("\n")).toContain("PLR_VPN_ENTRY_URL");
  });
});
