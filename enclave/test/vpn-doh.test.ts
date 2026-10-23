/**
 * Encrypted DNS inside the exit (SPEC-VPN §6.1, RFC 8484): DoH only, resolvers in order, both families, E_DNS on
 * failure, never the host's resolver; and the exit wiring (resolvers from the measured compose, RFC 6761 rule).
 * The resolver is a local fake (test/doh-server.ts); a hung resolver is bounded by a short per-resolver deadline,
 * so the outcome never depends on timing.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DNS, FRAME, encodeDnsQuery, parseConnectErr } from "@plr/shared";
import { createDohLookup } from "../src/vpn/doh.js";
import { startFakeDoh, type FakeDoh } from "./doh-server.js";
import { TestTunnel, attestExit, startEchoUpstream, startTestExit, type TestExit } from "./vpn-helpers.js";

const codeOf = (p: Promise<unknown>) => p.then(() => "NO_THROW", (e: { code?: string }) => e.code ?? "E_?");
const sorted = (a: ReadonlyArray<{ address: string; family: number }>) => [...a].map((x) => `${x.family}:${x.address}`).sort();

let r1: FakeDoh, r2: FakeDoh;
beforeAll(async () => { r1 = await startFakeDoh(); r2 = await startFakeDoh(); });
afterAll(async () => { await r1.close(); await r2.close(); });
beforeEach(() => { r1.mode = "ok"; r2.mode = "ok"; r1.requests.length = 0; r2.requests.length = 0; });

describe("createDohLookup (RFC 8484 lookup)", () => {
  it("POSTs A and AAAA queries (exact §6.1 bytes, dns-message headers) and returns both families", async () => {
    r1.set("dual.plr.test", ["93.184.216.34", "2001:4860:4860::8888"]);
    const lookup = createDohLookup([r1.url]);
    expect(sorted(await lookup("Dual.PLR.test."))).toEqual(["4:93.184.216.34", "6:2001:4860:4860::8888"]);
    expect(r1.requests.map((q) => q.qtype).sort((a, b) => a - b)).toEqual([1, 28]);
    for (const q of r1.requests) {
      expect([q.method, q.path, q.contentType, q.accept]).toEqual(["POST", "/dns-query", DNS.CONTENT_TYPE, DNS.CONTENT_TYPE]);
      expect(q.qname).toBe("dual.plr.test");
      expect(q.length).toBe(encodeDnsQuery("dual.plr.test", q.qtype === 1 ? "A" : "AAAA").length);
      expect(q.length % 128).toBe(0); // EDNS0 padding
    }
  });

  it("a single family is enough (AAAA-only and A-only names)", async () => {
    r1.set("v6only.plr.test", ["2606:4700::6810:84e5"]);
    r1.set("v4only.plr.test", ["1.2.3.4"]);
    const lookup = createDohLookup([r1.url]);
    expect(sorted(await lookup("v6only.plr.test"))).toEqual(["6:2606:4700::6810:84e5"]);
    expect(sorted(await lookup("v4only.plr.test"))).toEqual(["4:1.2.3.4"]);
  });

  it("NXDOMAIN / no addresses ⇒ E_DNS, and the next resolver is not asked (it is an answer)", async () => {
    r2.set("missing.plr.test", ["1.2.3.4"]);
    const lookup = createDohLookup([r1.url, r2.url]);
    expect(await codeOf(lookup("missing.plr.test"))).toBe("E_DNS");
    expect(r1.hits()).toBe(2);
    expect(r2.hits()).toBe(0);
  });

  it("resolvers are tried in order: a failing first resolver falls through to the second", async () => {
    r2.set("dest.plr.test", ["127.0.0.1"]);
    for (const mode of ["down", "wrong-type", "huge", "garbage", "servfail"] as const) {
      r1.mode = mode;
      r1.requests.length = 0;
      r2.requests.length = 0;
      const lookup = createDohLookup([r1.url, r2.url]);
      expect(sorted(await lookup("dest.plr.test")), mode).toEqual(["4:127.0.0.1"]);
      expect(r1.hits(), mode).toBe(2);
      expect(r2.hits(), mode).toBe(2);
    }
  });

  it("all resolvers failing ⇒ E_DNS (no plaintext / system-resolver fallback, even for names the host can resolve)", async () => {
    r1.mode = "down";
    r2.mode = "garbage";
    const lookup = createDohLookup([r1.url, r2.url]);
    for (const name of ["example.com", "dest.plr.test", "localhost"]) expect(await codeOf(lookup(name)), name).toBe("E_DNS");
    expect(r1.hits()).toBe(6);
    expect(r2.hits()).toBe(6);
  });

  it("an unreachable resolver ⇒ next resolver; a hung one is cut off by the per-resolver deadline", async () => {
    r2.set("dest.plr.test", ["127.0.0.1"]);
    const dead = "http://127.0.0.1:9/dns-query"; // discard port: nothing listens
    expect(sorted(await createDohLookup([dead, r2.url])("dest.plr.test"))).toEqual(["4:127.0.0.1"]);
    // The deadline is triggered by hand once the hung resolver has both queries: no race with a real timer.
    r1.mode = "hang";
    r2.requests.length = 0;
    const deadlines: Array<{ ms: number; ac: AbortController }> = [];
    const lookup = createDohLookup([r1.url, r2.url], { deadline: (ms) => { const ac = new AbortController(); deadlines.push({ ms, ac }); return ac.signal; } });
    const p = lookup("dest.plr.test");
    await r1.waitHits(2);
    expect(r2.hits()).toBe(0);
    expect(deadlines.map((d) => d.ms)).toEqual([DNS.RESOLVER_TIMEOUT_MS]); // 5 s per resolver (SPEC-VPN §6.1)
    deadlines[0]!.ac.abort();
    expect(sorted(await p)).toEqual(["4:127.0.0.1"]);
    expect(deadlines).toHaveLength(2);
    // The real timer (short here): a lone hung resolver ⇒ E_DNS. Only the outcome is asserted, never a duration.
    expect(await codeOf(createDohLookup([r1.url], { timeoutMs: 200 })("dest.plr.test"))).toBe("E_DNS");
  });

  it("the caller's signal (dial deadline / tunnel closed) aborts the lookup with E_DNS; later resolvers are not asked", async () => {
    r1.mode = "hang";
    const ac = new AbortController();
    const p = createDohLookup([r1.url, r2.url])("dest.plr.test", ac.signal);
    await r1.waitHits(2);
    ac.abort();
    expect(await codeOf(p)).toBe("E_DNS");
    expect(r2.hits()).toBe(0);
    const pre = new AbortController();
    pre.abort();
    expect(await codeOf(createDohLookup([r2.url])("dest.plr.test", pre.signal))).toBe("E_DNS");
    expect(r2.hits()).toBe(0);
  });

  it("IP literals and malformed names are never queried; errors carry no name", async () => {
    const lookup = createDohLookup([r1.url]);
    for (const h of ["1.2.3.4", "::1", "bad name!", "-x.example", "", "a".repeat(254)]) {
      const err = await lookup(h).then(() => null, (e: Error & { code?: string }) => e);
      expect(err?.code, h).toBe("E_DNS");
      expect(String(err?.message) + String(err?.stack)).not.toContain("bad name");
    }
    expect(r1.hits()).toBe(0);
    r1.mode = "down";
    const err = await lookup("secret-name.plr.test").then(() => null, (e: Error) => e);
    expect(String(err?.message) + String(err?.stack)).not.toMatch(/secret-name|127\.0\.0\.1|dns-query/);
  });

  it("refuses a malformed resolver list at construction", () => {
    for (const bad of [[], ["https://dns.example/dns-query"], ["ftp://1.1.1.1/x"], ["not a url"], Array(5).fill("https://1.1.1.1/dns-query"), [42]]) {
      expect(() => createDohLookup(bad as string[]), JSON.stringify(bad)).toThrow();
    }
    expect(() => createDohLookup(["https://1.1.1.1/dns-query"], { timeoutMs: 0 })).toThrow();
  });
});

describe("the exit resolves only through the DoH resolvers of its measured compose", () => {
  let up: Awaited<ReturnType<typeof startEchoUpstream>>;
  const exits: TestExit[] = [];
  beforeAll(async () => { up = await startEchoUpstream(); });
  afterAll(async () => { await up.close(); });
  afterEach(async () => { for (const e of exits.splice(0)) await e.close(); });

  async function outcome(e: TestExit, host: string, port: number): Promise<string> {
    const v = await attestExit(e.url, e.root.publicKey);
    const t = await TestTunnel.open(e.port, v, v.nonce);
    t.connect(host, port);
    expect(await t.until(() => t.frames.length > 0)).toBe(true);
    const f = t.frames[0]!;
    t.sock.destroy();
    return f.type === FRAME.CONNECT_OK ? "OK" : f.type === FRAME.CONNECT_ERR ? parseConnectErr(f.payload) : `TYPE_${f.type}`;
  }
  async function exitOn(doh: string[], allowLoopback = true): Promise<TestExit> {
    const e = await startTestExit({ allowLoopback, doh });
    exits.push(e);
    return e;
  }

  it("a name only the DoH resolver knows is resolved, egress-checked and dialled by IP", async () => {
    r1.set("dest.plr.test", ["127.0.0.1"]);
    const e = await exitOn([r1.url]);
    const before = up.connections();
    expect(await outcome(e, "dest.plr.test", up.port)).toBe("OK");
    expect(r1.hits()).toBe(2);
    expect(up.connections()).toBe(before + 1);
  });

  it("NXDOMAIN / resolver down ⇒ E_DNS and the destination is never contacted", async () => {
    const e = await exitOn([r1.url]);
    const before = up.connections();
    expect(await outcome(e, "missing.plr.test", up.port)).toBe("E_DNS");
    r1.mode = "down";
    r1.set("dest.plr.test", ["127.0.0.1"]);
    expect(await outcome(e, "dest.plr.test", up.port)).toBe("E_DNS");
    expect(await outcome(e, "example.com", 443)).toBe("E_DNS");
    expect(up.connections()).toBe(before);
  });

  it("localhost names are refused before resolution even on the loopback-allowing build; private answers by egress", async () => {
    const e = await exitOn([r1.url]);
    for (const h of ["localhost", "LOCALHOST.", "x.localhost"]) expect(await outcome(e, h, up.port), h).toBe("E_EGRESS_DENIED");
    expect(r1.hits()).toBe(0);
    r1.set("private.plr.test", ["93.184.216.34", "10.0.0.5"]);
    expect(await outcome(e, "private.plr.test", 80)).toBe("E_EGRESS_DENIED");
    r1.set("loop.plr.test", ["127.0.0.1"]);
    const prod = await startTestExit({ allowLoopback: false, lookup: createDohLookup([r1.url]) }); // production policy, test resolver
    exits.push(prod);
    expect(await outcome(prod, "loop.plr.test", up.port)).toBe("E_EGRESS_DENIED");
  });

  it("the default test compose points at 127.0.0.1:18253 (nothing listens in unit tests ⇒ E_DNS, never the host resolver)", async () => {
    const e = await startTestExit({});
    exits.push(e);
    expect(JSON.parse(new TextDecoder().decode(e.composeBytes)).policy.dns.doh).toEqual(["http://127.0.0.1:18253/dns-query"]);
    expect(await outcome(e, "example.com", 443)).toBe("E_DNS");
  });
});

describe("no system-resolver path in the exit sources", () => {
  it("src/vpn/** never imports node:dns or calls a system lookup; destinations reach net.connect only as IP literals", async () => {
    const { readdirSync, readFileSync } = await import("node:fs");
    const { join, resolve } = await import("node:path");
    const dir = resolve(import.meta.dirname, "..", "src", "vpn");
    const files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
    expect(files).toContain("doh.ts");
    for (const f of files) {
      const src = readFileSync(join(dir, f), "utf8");
      expect(src, f).not.toMatch(/from\s+["'](node:)?dns(\/promises)?["']/);
      expect(src, f).not.toMatch(/\bdns\.(lookup|resolve\w*|promises)\b|getaddrinfo/);
    }
    expect(readFileSync(join(dir, "egress.ts"), "utf8")).toContain("lookup: refuseLookup");
  });
});
