// LOCKED — SPEC-VPN §10: two-hop routing with on-chain operator organizations.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { lookup as realLookup } from "node:dns";
import { connect as tcpConnect, type Socket } from "node:net";
import { PlrError } from "@plr/shared";
import { TwoHopClient, startVpn, type VpnStream } from "@plr/client";
import { startStack, type Stack, type ExitHandle, type Destination } from "../src/harness.js";

const MARK = "twohop-secret-" + Math.random().toString(36).slice(2);
let S: Stack;
let entry: ExitHandle; // operator → org-a
let exit: ExitHandle;  // operator2 → org-b
let dest: Destination;
const lookups: string[] = [];
const spyLookup = ((host: string, ...rest: unknown[]) => { lookups.push(host); return (realLookup as any)(host, ...rest); }) as typeof realLookup;

beforeAll(async () => {
  S = await startStack();
  await S.approveVpnBuild("vpn-honest-test");
  await S.approveOperator("operator", "org-a");
  await S.approveOperator("operator2", "org-b");
  entry = await S.startExit("vpn-honest-test", { operator: "operator" });
  exit = await S.startExit("vpn-honest-test", { operator: "operator2" });
  dest = await S.startDestination();
  S.dns.set("dest.plr.test", ["127.0.0.1"]);
}, 300_000);
afterAll(async () => { await S?.stop(); });

const two = (entryUrl: string, exitUrl: string, o: { attestTtlMs?: number } = {}) =>
  new TwoHopClient({ entryUrl, exitUrl, registry: S.vpnRegistry, trustedRoot: S.trustedRoot, lookup: spyLookup, ...o });

async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}

function httpOver(s: VpnStream | Socket, path: string): Promise<{ data: string; error: unknown }> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let done = false;
    const fin = (error: unknown) => { if (!done) { done = true; ok({ data: Buffer.concat(chunks).toString("latin1"), error }); } };
    s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
    s.on("end", () => { s.end(); fin(null); });
    s.on("error", (e) => fin(e));
    s.on("close", () => fin(null));
    s.write(`GET ${path} HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n`);
  });
}

function socks(proxyPort: number, host: string, port: number): Promise<{ rep: number; sock: Socket }> {
  return new Promise((ok, fail) => {
    const sock = tcpConnect(proxyPort, "127.0.0.1");
    let buf = Buffer.alloc(0), stage = 0;
    sock.on("error", fail);
    sock.on("connect", () => sock.write(Buffer.from([5, 1, 0])));
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (stage === 0 && buf.length >= 2) {
        buf = buf.subarray(2); stage = 1;
        const h = Buffer.from(host);
        sock.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 0xff])]));
      }
      if (stage === 1 && buf.length >= 10) {
        sock.off("data", onData);
        const rest = buf.subarray(10);
        if (rest.length) sock.unshift(rest);
        ok({ rep: buf[1]!, sock });
      }
    };
    sock.on("data", onData);
  });
}

describe("1. two hops, different organizations", () => {
  it("attests both hops and reports their orgs", async () => {
    const a = await two(entry.url, exit.url).attest();
    expect(a.entryOrg).toBe("org-a");
    expect(a.exitOrg).toBe("org-b");
    expect(a.entry.rootKind).toBe("MOCK");
    expect(a.exit.rootKind).toBe("MOCK");
  });

  it("tunnels end-to-end; exit and entry receipts verify", async () => {
    lookups.length = 0;
    const s = await two(entry.url, exit.url).connect("dest.plr.test", dest.port);
    const r = await httpOver(s, `/${MARK}/hop`);
    expect(r.error).toBeNull();
    expect(r.data).toContain(`dest-ok:/${MARK}/hop`);
    const { receipt } = await s.receipt();
    expect(receipt.key_hash).toBe(exit.keyHash);
    const e = await s.entryReceipt();
    expect(e.receipt.key_hash).toBe(entry.keyHash);
    expect(lookups).not.toContain("dest.plr.test");
  });

  it("works behind the SOCKS5 proxy", async () => {
    const p = await startVpn({ port: 0, client: two(entry.url, exit.url) });
    const { rep, sock } = await socks(p.port, "dest.plr.test", dest.port);
    expect(rep).toBe(0);
    expect((await httpOver(sock, "/socks-two")).data).toContain("dest-ok:/socks-two");
    await p.close();
  });
});

describe("2. operator rules", () => {
  it("same organization on both hops ⇒ E_SAME_OPERATOR, destination untouched", async () => {
    await S.approveOperator("operator2", "org-a");
    try {
      const before = dest.hits();
      expect(await codeOf(two(entry.url, exit.url).connect("dest.plr.test", dest.port))).toBe("E_SAME_OPERATOR");
      expect(dest.hits()).toBe(before);
    } finally { await S.approveOperator("operator2", "org-b"); }
  });

  it("an unapproved operator on either hop ⇒ E_OPERATOR_UNAPPROVED", async () => {
    await S.revokeOperator("operator2");
    try { expect(await codeOf(two(entry.url, exit.url).connect("dest.plr.test", dest.port))).toBe("E_OPERATOR_UNAPPROVED"); }
    finally { await S.approveOperator("operator2", "org-b"); }
    await S.revokeOperator("operator");
    try { expect(await codeOf(two(entry.url, exit.url).connect("dest.plr.test", dest.port))).toBe("E_OPERATOR_UNAPPROVED"); }
    finally { await S.approveOperator("operator", "org-a"); }
  });

  it("an org change applies to the very next connection, even with cached attestations", async () => {
    const c = two(entry.url, exit.url, { attestTtlMs: 600_000 });
    await httpOver(await c.connect("dest.plr.test", dest.port), "/cached-1");
    await S.approveOperator("operator2", "org-a");
    try { expect(await codeOf(c.connect("dest.plr.test", dest.port))).toBe("E_SAME_OPERATOR"); }
    finally { await S.approveOperator("operator2", "org-b"); }
    expect((await httpOver(await c.connect("dest.plr.test", dest.port), "/cached-2")).data).toContain("dest-ok:/cached-2");
  });

  it("an unapproved exit build is refused through the entry", async () => {
    const evilExit = await S.startExit("vpn-evil-logger", { operator: "operator2" });
    expect(await codeOf(two(entry.url, evilExit.url).connect("dest.plr.test", dest.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(evilExit.output()).not.toContain(MARK);
    await evilExit.stop();
  });
});

describe("3. separation of knowledge", () => {
  it("even an approved entry that logs everything sees only the exit's address — never the destination or payload", async () => {
    await S.approveVpnBuild("vpn-evil-logger");
    const spy = await S.startExit("vpn-evil-logger", { operator: "operator" }); // org-a, logs every CONNECT + first bytes
    const s = await two(spy.url, exit.url).connect("dest.plr.test", dest.port);
    const r = await httpOver(s, `/${MARK}/separation`);
    expect(r.data).toContain(`dest-ok:/${MARK}/separation`);
    const out = spy.output();
    expect(out).toContain(String(new URL(exit.url).port)); // sanity: the logger works and saw the exit
    expect(out).not.toContain(MARK);
    expect(out).not.toContain("dest.plr.test");
    expect(out).not.toContain("separation");
    await spy.stop();
  });
});
