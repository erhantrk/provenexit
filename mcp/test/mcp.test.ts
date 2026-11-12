// MCP server against local stubs (fake exit, fake NEAR RPC, local HTTP destination). No real network.
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { toHex } from "@plr/shared";
import { createServer } from "../src/server.js";
import { parseFetchUrl, parseMaxBytes, UrlRefused } from "../src/fetch.js";
import { startFakeExit, startDestination, type FakeExit, type FakeDestination } from "../../client/test/fake-exit.js";
import { startFakeRpc, registryHandler, type FakeRpc } from "../../client/test/fake-rpc.js";

let X: FakeExit;
let D: FakeDestination;
let R: FakeRpc;
const closers: (() => Promise<void>)[] = [];
beforeEach(async () => {
  X = await startFakeExit();
  D = await startDestination();
  R = await startFakeRpc(registryHandler(X.registry));
  closers.push(X.close, D.close, R.close);
});
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function connectClient(over: { exitUrl?: string; rpcUrl?: string } = {}): Promise<Client> {
  const server = createServer({
    allowedPorts: [D.port, 80, 443],
    options: { env: {}, exitUrl: over.exitUrl ?? X.url, registry: "vpnregistry.test.near", trustedRoot: toHex(X.root.publicKey), rpcUrl: over.rpcUrl ?? R.url, timeouts: { verify: 5000, chain: 2000, egress: 5000 } },
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  closers.push(async () => { await client.close(); });
  return client;
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}): Promise<{ isError: boolean; json: Record<string, any> }> => {
  const r = (await c.callTool({ name, arguments: args })) as { isError?: boolean; content: { type: string; text: string }[] };
  return { isError: r.isError === true, json: JSON.parse(r.content[0]!.text) as Record<string, any> };
};

describe("tools", () => {
  it("lists verify_exit, fetch_via_exit, registry_status", async () => {
    const c = await connectClient();
    const { tools } = await c.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["fetch_via_exit", "registry_status", "verify_exit"]);
    const f = tools.find((t) => t.name === "fetch_via_exit")!;
    expect(Object.keys((f.inputSchema as { properties: object }).properties).sort()).toEqual(["max_bytes", "url"]);
  });

  it("verify_exit returns the verdict and the ordered checks", async () => {
    const c = await connectClient();
    const r = await call(c, "verify_exit");
    expect(r.isError).toBe(false);
    expect(r.json.verdict).toBe("VERIFIED");
    expect(r.json.checks.at(-2).name).toContain("registry re-check");
    expect(r.json.checks.every((k: { ok: boolean }) => k.ok)).toBe(true);
  });

  it("fetch_via_exit fetches through the attested tunnel and truncates to max_bytes", async () => {
    const c = await connectClient();
    const r = await call(c, "fetch_via_exit", { url: `http://127.0.0.1:${D.port}/hello` });
    expect(r.isError).toBe(false);
    expect(r.json).toMatchObject({ via: "provenexit", status: 200, body: "dest-ok:/hello", truncated: false });
    expect(r.json.headers["content-type"]).toBe("text/plain");
    expect(X.stats.connects).toBe(1);
    const t = await call(c, "fetch_via_exit", { url: `http://127.0.0.1:${D.port}/hello`, max_bytes: 4 });
    expect(t.json).toMatchObject({ body: "dest", truncated: true, bytes: 4 });
  });

  it("fetch_via_exit refuses with the error code, and contacts nothing, when the build is revoked", async () => {
    const c = await connectClient();
    X.registry.revokeCompose(X.composeHash);
    const r = await call(c, "fetch_via_exit", { url: `http://127.0.0.1:${D.port}/x` });
    expect(r.isError).toBe(true);
    expect(r.json).toMatchObject({ refused: true, code: "E_COMPOSE_NOT_ALLOWED", failed_check: "compose hash allowed by registry" });
    expect(D.hits()).toBe(0);
    expect(X.stats.connects).toBe(0);
    const v = await call(c, "verify_exit");
    expect(v.json).toMatchObject({ verdict: "REFUSED", code: "E_COMPOSE_NOT_ALLOWED" });
  });

  it("fetch_via_exit refuses when the exit is stopped (never falls back to a direct connection)", async () => {
    const dead = await startFakeExit();
    await dead.close();
    const c = await connectClient({ exitUrl: dead.url });
    const r = await call(c, "fetch_via_exit", { url: `http://127.0.0.1:${D.port}/x` });
    expect(r.isError).toBe(true);
    expect(r.json.refused).toBe(true);
    expect(r.json.code).toBe("E_BAD_RESPONSE");
    expect(D.hits()).toBe(0);
  });

  it("fetch_via_exit validates the URL before anything else", async () => {
    const c = await connectClient();
    for (const url of ["ftp://example.com/", "file:///etc/passwd", "https://example.com:8443/", "http://example.com:22/", "https://user:pw@example.com/", "not a url", "javascript:alert(1)"]) {
      const r = await call(c, "fetch_via_exit", { url });
      expect(r.isError, url).toBe(true);
      expect(r.json.code, url).toBe("E_BAD_INPUT");
    }
    expect(X.stats.attestations).toBe(0);
    await expect(c.callTool({ name: "fetch_via_exit", arguments: { url: "https://example.com", max_bytes: 0 } })).resolves.toMatchObject({ isError: true });
  });

  it("registry_status reports an unreadable registry as an error", async () => {
    const c = await connectClient({ rpcUrl: "http://127.0.0.1:1" });
    const r = await call(c, "registry_status");
    expect(r.isError).toBe(true);
    expect(r.json.error).toMatch(/registry unreadable/);
    expect(r.json.registry.owner).toBeNull();
  });
});

describe("URL and size validation", () => {
  it("accepts http(s) on 80/443 only", () => {
    expect(parseFetchUrl("https://example.com/a?b=1#frag")).toMatchObject({ host: "example.com", port: 443, tls: true, path: "/a?b=1", hostHeader: "example.com" });
    expect(parseFetchUrl("http://example.com")).toMatchObject({ port: 80, tls: false, path: "/" });
    expect(parseFetchUrl("http://example.com:443/")).toMatchObject({ port: 443, tls: false, hostHeader: "example.com:443" });
    expect(() => parseFetchUrl("http://example.com:8080/")).toThrow(UrlRefused);
    expect(() => parseFetchUrl("gopher://example.com/")).toThrow(UrlRefused);
  });
  it("bounds max_bytes", () => {
    expect(parseMaxBytes(undefined)).toBe(20_000);
    expect(parseMaxBytes(5)).toBe(5);
    expect(() => parseMaxBytes(0)).toThrow(UrlRefused);
    expect(() => parseMaxBytes(2_000_000)).toThrow(UrlRefused);
    expect(() => parseMaxBytes(1.5)).toThrow(UrlRefused);
  });
});
