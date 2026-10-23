// LOCKED — SPEC-VPN: end-to-end scenarios against near-sandbox (VPN registry) and the mock TDX host.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connect as tcpConnect, type Socket } from "node:net";
import { lookup as realLookup } from "node:dns";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { PlrError } from "@plr/shared";
import { VpnClient, PrivateClient, startVpn, type VpnStream } from "@plr/client";
import { startStack, type Stack, type ExitHandle, type Destination } from "../src/harness.js";

const MARK = "vpn-secret-" + Math.random().toString(36).slice(2);

let S: Stack;
let exit: ExitHandle;      // approved vpn-honest-test (loopback allowed, so tests can reach the local destination)
let dest: Destination;
const lookups: string[] = [];
const spyLookup = ((host: string, ...rest: unknown[]) => { lookups.push(host); return (realLookup as any)(host, ...rest); }) as typeof realLookup;

beforeAll(async () => {
  S = await startStack({ llm: "mock" });
  await S.approveVpnBuild("vpn-honest-test");
  exit = await S.startExit("vpn-honest-test");
  dest = await S.startDestination();
  S.dns.set("dest.plr.test", ["127.0.0.1"]); // only the local DoH resolver knows this name
}, 300_000);
afterAll(async () => { await S?.stop(); });

const vpn = (url: string, o: { attestTtlMs?: number } = {}) =>
  new VpnClient({ exitUrl: url, registry: S.vpnRegistry, trustedRoot: S.trustedRoot, lookup: spyLookup, ...o });

async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}

/** Send an HTTP/1.1 request over a stream and collect everything until EOF or error. */
function httpOver(s: VpnStream | Socket, path: string, body?: string): Promise<{ data: string; error: unknown }> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let done = false;
    const fin = (error: unknown) => { if (!done) { done = true; ok({ data: Buffer.concat(chunks).toString("latin1"), error }); } };
    s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
    s.on("end", () => { s.end(); fin(null); }); // half-close our side after the response EOF ⇒ c2s FIN ⇒ receipt
    s.on("error", (e) => fin(e));
    s.on("close", () => fin(null));
    const m = body === undefined ? "GET" : "POST";
    s.write(`${m} ${path} HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n` + (body === undefined ? "\r\n" : `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`));
  });
}

/** Independent minimal SOCKS5 client (RFC 1928): returns the REP code and the socket. */
function socks(proxyPort: number, host: string, port: number): Promise<{ rep: number; sock: Socket }> {
  return new Promise((ok, fail) => {
    const sock = tcpConnect(proxyPort, "127.0.0.1");
    let buf = Buffer.alloc(0), stage = 0;
    sock.on("error", fail);
    sock.on("connect", () => sock.write(Buffer.from([5, 1, 0])));
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (stage === 0 && buf.length >= 2) {
        expect([...buf.subarray(0, 2)]).toEqual([5, 0]);
        buf = buf.subarray(2); stage = 1;
        const h = Buffer.from(host);
        sock.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 0xff])]));
      }
      if (stage === 1 && buf.length >= 10) {
        sock.off("data", onData);
        const rep = buf[1]!;
        const rest = buf.subarray(10);
        if (rest.length) sock.unshift(rest);
        ok({ rep, sock });
      }
    };
    sock.on("data", onData);
  });
}

describe("1. honest exit", () => {
  it("tunnels a request end-to-end and returns a verified receipt", async () => {
    const c = vpn(exit.url);
    const v = await c.attest();
    expect(v.rootKind).toBe("MOCK");
    expect(v.osMeasurement.length).toBe(32);
    const s = await c.connect("127.0.0.1", dest.port);
    const r = await httpOver(s, `/${MARK}/one`);
    expect(r.error).toBeNull();
    expect(r.data).toContain(`dest-ok:/${MARK}/one`);
    const { receipt } = await s.receipt();
    expect(receipt.compose_hash).toBe(exit.composeHash);
    expect(receipt.key_hash).toBe(exit.keyHash);
    expect(receipt.ts_open_ms).toBeLessThanOrEqual(receipt.ts_close_ms);
  });

  it("POST bodies flow client → destination intact (large payload, many frames)", async () => {
    const body = MARK + "x".repeat(200_000);
    const s = await vpn(exit.url).connect("127.0.0.1", dest.port);
    const r = await httpOver(s, "/echo", body);
    expect(r.error).toBeNull();
    expect(r.data.endsWith(body)).toBe(true);
  });

  it("receipts are anchored on the VPN registry", async () => {
    const c = vpn(exit.url);
    const s = await c.connect("127.0.0.1", dest.port);
    await httpOver(s, "/anchor");
    const { receipt } = await s.receipt();
    let ok = false;
    for (let i = 0; i < 60 && !ok; i++) {
      try { ok = await c.verifyAnchored(receipt); }
      catch (e) { if ((e as PlrError).code !== "E_NOT_ANCHORED") throw e; await new Promise((r) => setTimeout(r, 1000)); }
    }
    expect(ok, "receipt was never anchored").toBe(true);
  }, 90_000);

  it("works through the SOCKS5 proxy with remote DNS (the client never resolves the destination)", async () => {
    lookups.length = 0;
    const p = await startVpn({ port: 0, client: vpn(exit.url) });
    expect(p.url).toMatch(/^socks5h:\/\/127\.0\.0\.1:\d+$/);
    const { rep, sock } = await socks(p.port, "dest.plr.test", dest.port);
    expect(rep).toBe(0);
    const r = await httpOver(sock, `/${MARK}/socks`);
    expect(r.data).toContain(`dest-ok:/${MARK}/socks`);
    expect(lookups).not.toContain("dest.plr.test");
    await p.close();
  });
});

describe("2. evil exit that logs destinations", () => {
  it("is refused before the destination is contacted", async () => {
    const evil = await S.startExit("vpn-evil-logger");
    expect(evil.composeHash).not.toBe(exit.composeHash);
    const before = dest.hits();
    expect(await codeOf(vpn(evil.url).connect("127.0.0.1", dest.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    const p = await startVpn({ port: 0, client: vpn(evil.url) });
    const { rep, sock } = await socks(p.port, "127.0.0.1", dest.port);
    expect(rep).toBe(2);
    sock.destroy();
    await p.close();
    expect(dest.hits()).toBe(before);
    expect(evil.output()).not.toContain(MARK);
    await evil.stop();
  });
});

describe("3. MITM swaps the tunnel key", () => {
  it("is refused (report_data does not bind the advertised key)", async () => {
    const m = await S.startExit("vpn-mitm-key");
    const before = dest.hits();
    expect(await codeOf(vpn(m.url).connect("127.0.0.1", dest.port))).toBe("E_REPORT_DATA_KEYS");
    expect(dest.hits()).toBe(before);
    await m.stop();
  });
});

describe("4. replayed attestation", () => {
  it("is refused on a fresh attestation (stale nonce)", async () => {
    const m = await S.startExit("vpn-replay-quote");
    await vpn(m.url, { attestTtlMs: 0 }).attest();
    expect(await codeOf(vpn(m.url, { attestTtlMs: 0 }).attest())).toBe("E_NONCE");
    await m.stop();
  });
});

describe("5. revocation on-chain", () => {
  it("applies to the very next connection even with a cached attestation", async () => {
    const c = vpn(exit.url, { attestTtlMs: 600_000 });
    const s1 = await c.connect("127.0.0.1", dest.port);
    await httpOver(s1, "/before-revoke");
    await S.callVpn("owner", "revoke_compose", { hash: exit.composeHash });
    const before = dest.hits();
    expect(await codeOf(c.connect("127.0.0.1", dest.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(dest.hits()).toBe(before);
    await S.callVpn("owner", "allow_compose", { hash: exit.composeHash });
    const s2 = await c.connect("127.0.0.1", dest.port);
    expect((await httpOver(s2, "/after-reallow")).data).toContain("dest-ok:/after-reallow");
  });
});

describe("6. tampered / truncated tunnel", () => {
  it("a flipped ciphertext byte ⇒ E_DECRYPT, no corrupted bytes delivered", async () => {
    const m = await S.startExit("vpn-tamper-stream");
    const s = await vpn(m.url).connect("127.0.0.1", dest.port);
    const r = await httpOver(s, "/tamper");
    expect(r.error).toBeInstanceOf(PlrError);
    expect((r.error as PlrError).code).toBe("E_DECRYPT");
    expect(r.data).toBe(""); // the first DATA frame was the tampered one: nothing may reach the application
    await m.stop();
  });
  it("a cut connection ⇒ E_TRUNCATED, never a clean EOF", async () => {
    const m = await S.startExit("vpn-truncate-stream");
    const s = await vpn(m.url).connect("127.0.0.1", dest.port);
    const r = await httpOver(s, "/truncate-" + "y".repeat(40_000));
    expect(r.error).toBeInstanceOf(PlrError);
    expect((r.error as PlrError).code).toBe("E_TRUNCATED");
    await m.stop();
  });
});

describe("7. production egress policy", () => {
  it("the production build refuses loopback, private, link-local/metadata and reserved targets", async () => {
    await S.approveVpnBuild("vpn-honest");
    const prod = await S.startExit("vpn-honest");
    expect(prod.composeHash).not.toBe(exit.composeHash); // test policy is a different measurement
    const c = vpn(prod.url);
    const before = dest.hits();
    for (const host of ["127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1"])
      expect(await codeOf(c.connect(host, dest.port)), host).toBe("E_EGRESS_DENIED");
    expect(await codeOf(c.connect("bad host!", 80))).toBe("E_BAD_INPUT");
    expect(dest.hits()).toBe(before);
    await prod.stop();
  });
});

describe("8. unregistered instance of an approved build", () => {
  it("is refused", async () => {
    const u = await S.startExit("vpn-honest-test", { register: false });
    expect(await codeOf(vpn(u.url).connect("127.0.0.1", dest.port))).toBe("E_INSTANCE_NOT_REGISTERED");
    await u.stop();
  });
});

describe("9. no retention by the honest exit", () => {
  it("never writes destinations or payloads to its output or the run directory", async () => {
    const s = await vpn(exit.url).connect("127.0.0.1", dest.port);
    await httpOver(s, `/${MARK}/retention`, MARK + "-body");
    const out = exit.output();
    expect(out).not.toContain(MARK);
    const walk = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
    for (const f of walk(S.runDir)) {
      if (statSync(f).size > 5_000_000) continue;
      expect(readFileSync(f).includes(Buffer.from(MARK)), `marker found in ${f}`).toBe(false);
    }
    expect(dest.received()).toContain(MARK); // sanity: the destination did receive it
  });
});

describe("10. registries are independent", () => {
  it("a VPN build is not approved on the LLM registry and vice versa", async () => {
    expect(await S.registry.isComposeAllowed(exit.composeHash)).toBe(false);
    await S.approveBuild("honest");
    const router = await S.startRouter("honest");
    expect(await S.vpnRegistry.isComposeAllowed(router.composeHash)).toBe(false);
    expect(await codeOf(new PrivateClient({ routerUrl: exit.url, registry: S.registry, trustedRoot: S.trustedRoot }).attest())).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(await codeOf(vpn(router.url).attest())).toBe("E_COMPOSE_NOT_ALLOWED");
    await router.stop();
  });
});

describe("11. encrypted DNS inside the exit (DoH, no plaintext fallback)", () => {
  it("resolves names only through the measured DoH resolver", async () => {
    const before = S.dns.hits();
    const s1 = await vpn(exit.url).connect("dest.plr.test", dest.port); // unresolvable by the system resolver (.test)
    expect((await httpOver(s1, "/doh")).data).toContain("dest-ok:/doh");
    expect(S.dns.hits()).toBeGreaterThan(before);
  });
  it("NXDOMAIN ⇒ E_DNS, destination never contacted", async () => {
    const before = dest.hits();
    expect(await codeOf(vpn(exit.url).connect("missing.plr.test", dest.port))).toBe("E_DNS");
    expect(dest.hits()).toBe(before);
  });
  it("resolver down ⇒ E_DNS (never falls back to the host resolver)", async () => {
    S.dns.setDown(true);
    try {
      expect(await codeOf(vpn(exit.url).connect("dest.plr.test", dest.port))).toBe("E_DNS");
      expect(await codeOf(vpn(exit.url).connect("example.com", 443))).toBe("E_DNS");
    } finally { S.dns.setDown(false); }
  });
  it("localhost names are refused before resolution even on the loopback-allowing test build", async () => {
    const before = S.dns.hits();
    for (const h of ["localhost", "LOCALHOST.", "x.localhost"])
      expect(await codeOf(vpn(exit.url).connect(h, dest.port)), h).toBe("E_EGRESS_DENIED");
    expect(S.dns.hits()).toBe(before);
  });
  it("a name resolving to a private address is refused by egress", async () => {
    S.dns.set("private.plr.test", ["10.0.0.5"]);
    expect(await codeOf(vpn(exit.url).connect("private.plr.test", 80))).toBe("E_EGRESS_DENIED");
  });
});
