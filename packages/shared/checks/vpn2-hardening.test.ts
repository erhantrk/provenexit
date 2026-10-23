// Extra (unlocked) hardening checks for SPEC-VPN rev 2 library pieces: handshake v2, DoH codec, operator orgs.
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/hashes/utils.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import {
  tunnelClientStart, tunnelServerAccept, encodeHello, parseHello, parseServerHello, encodeDnsQuery, parseDnsResponse,
  isLocalhostName, isInstanceRecord, isOrgId, MemoryRegistry, socksReplyFor, PlrError, toHex, type InstanceRecord,
} from "../src/index.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const enc = (s: string) => new TextEncoder().encode(s);
const cat = (...a: Uint8Array[]) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const u16 = (n: number) => new Uint8Array([n >> 8, n & 0xff]);
const u32 = (n: number) => new Uint8Array([n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
const qname = (name: string) => cat(...name.split(".").map((l) => cat(new Uint8Array([l.length]), enc(l))), new Uint8Array([0]));
const keys = () => {
  const xs = x25519.utils.randomSecretKey(), xp = x25519.getPublicKey(xs);
  const ep = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
  return { xs, xp, ep };
};
type RR = { name: Uint8Array; type: number; cls?: number; ttl?: number; data: Uint8Array };
function resp(o: { flags?: number; answers?: RR[]; additional?: RR[]; qn?: string }): Uint8Array {
  const an = o.answers ?? [], ad = o.additional ?? [];
  const rr = (r: RR) => cat(r.name, u16(r.type), u16(r.cls ?? 1), u32(r.ttl ?? 300), u16(r.data.length), r.data);
  return cat(u16(0), u16(o.flags ?? 0x8180), u16(1), u16(an.length), u16(0), u16(ad.length),
    qname(o.qn ?? "example.com"), u16(1), u16(1), ...an.map(rr), ...ad.map(rr));
}
const PTR_Q = new Uint8Array([0xc0, 12]);

describe("handshake v2", () => {
  it("abort() makes finish fail and is idempotent", () => {
    const k = keys();
    const c = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce: randomBytes(32) });
    const s = tunnelServerAccept({ ...k, hello: c.hello });
    c.abort(); c.abort();
    expect(code(() => c.finish(s.serverHello))).toBe("E_TUNNEL_PROTOCOL");
  });
  it("a failed finish consumes the handshake", () => {
    const k = keys();
    const c = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce: randomBytes(32) });
    const s = tunnelServerAccept({ ...k, hello: c.hello });
    expect(code(() => c.finish(new Uint8Array(33)))).toBe("E_TUNNEL_PROTOCOL"); // version 0
    expect(code(() => c.finish(s.serverHello))).toBe("E_TUNNEL_PROTOCOL");
  });
  it("rejects malformed keys and inconsistent exit key pairs", () => {
    const k = keys();
    expect(code(() => tunnelClientStart({ xp: k.xp.slice(1), ep: k.ep, attNonce: randomBytes(32) }))).toBe("E_BAD_INPUT");
    expect(code(() => tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce: randomBytes(31) }))).toBe("E_BAD_INPUT");
    const hello = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce: randomBytes(32) }).hello;
    expect(code(() => tunnelServerAccept({ ...k, xp: keys().xp, hello }))).toBe("E_BAD_INPUT");
    expect(code(() => parseHello("x" as unknown as Uint8Array))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => parseServerHello(new Uint8Array(34)))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => encodeHello(randomBytes(32), randomBytes(33)))).toBe("E_BAD_INPUT");
  });
  it("hello bytes are a copy (caller mutation cannot affect the handshake)", () => {
    const k = keys();
    const c = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce: randomBytes(32) });
    const h = c.hello.slice();
    c.hello.fill(0);
    const s = tunnelServerAccept({ ...k, hello: h });
    expect(c.finish(s.serverHello).kC2s).toEqual(s.kC2s);
  });
});

describe("dns codec extras", () => {
  it("query rejects bad types and IPv6 literals", () => {
    expect(code(() => encodeDnsQuery("example.com", "MX" as "A"))).toBe("E_BAD_INPUT");
    expect(code(() => encodeDnsQuery("::1", "AAAA"))).toBe("E_BAD_INPUT");
    expect(code(() => encodeDnsQuery("a.123", "A"))).toBe("E_BAD_INPUT");
  });
  it("pointer into the header is rejected", () => {
    expect(code(() => parseDnsResponse(resp({ answers: [{ name: new Uint8Array([0xc0, 4]), type: 1, data: new Uint8Array(4) }] }), "example.com", "A"))).toBe("E_DNS");
  });
  it("CNAME loops terminate; conflicting CNAMEs are rejected", () => {
    const loop = resp({ answers: [
      { name: PTR_Q, type: 5, data: qname("a.net") },
      { name: qname("a.net"), type: 5, data: qname("example.com") },
    ] });
    expect(parseDnsResponse(loop, "example.com", "A")).toEqual([]);
    const conflict = resp({ answers: [{ name: PTR_Q, type: 5, data: qname("a.net") }, { name: PTR_Q, type: 5, data: qname("b.net") }] });
    expect(code(() => parseDnsResponse(conflict, "example.com", "A"))).toBe("E_DNS");
    const badRdata = resp({ answers: [{ name: PTR_Q, type: 5, data: cat(qname("a.net"), new Uint8Array([1])) }] });
    expect(code(() => parseDnsResponse(badRdata, "example.com", "A"))).toBe("E_DNS");
  });
  it("EDNS extended RCODE ≠ 0 is an error; a normal OPT RR is fine; duplicates are removed", () => {
    const a = { name: PTR_Q, type: 1, data: new Uint8Array([1, 2, 3, 4]) };
    const opt = (ttl: number) => ({ name: new Uint8Array([0]), type: 41, cls: 4096, ttl, data: new Uint8Array() });
    expect(parseDnsResponse(resp({ answers: [a, a], additional: [opt(0)] }), "example.com", "A")).toEqual(["1.2.3.4"]);
    expect(code(() => parseDnsResponse(resp({ answers: [a], additional: [opt(1 << 24)] }), "example.com", "A"))).toBe("E_DNS");
    expect(code(() => parseDnsResponse(resp({ answers: [a], additional: [opt(0), opt(0)] }), "example.com", "A"))).toBe("E_DNS");
  });
  it("IPv4-mapped AAAA answers are returned in a form the egress check classifies by the embedded IPv4", () => {
    const six = new Uint8Array(16); six[10] = 0xff; six[11] = 0xff; six[12] = 127; six[15] = 1;
    const r = cat(u16(0), u16(0x8180), u16(1), u16(1), u16(0), u16(0), qname("example.com"), u16(28), u16(1), PTR_Q, u16(28), u16(1), u32(1), u16(16), six);
    expect(parseDnsResponse(r, "example.com", "AAAA")).toEqual(["::ffff:127.0.0.1"]);
  });
  it("never throws anything but PlrError(E_DNS) on random / mutated input", () => {
    const base = resp({ answers: [
      { name: PTR_Q, type: 5, data: qname("x.cdn.net") },
      { name: qname("x.cdn.net"), type: 1, data: new Uint8Array([9, 9, 9, 9]) },
    ] });
    for (let i = 0; i < 20000; i++) {
      let m: Uint8Array;
      if (i % 2 === 0) m = randomBytes(randomBytes(1)[0]! % 120);
      else {
        m = base.slice();
        const flips = 1 + (randomBytes(1)[0]! % 4);
        for (let j = 0; j < flips; j++) { const r = randomBytes(2); m[r[0]! % m.length] = r[1]!; }
      }
      try {
        const out = parseDnsResponse(m, "example.com", "A");
        expect(Array.isArray(out)).toBe(true);
      } catch (e) {
        expect(e).toBeInstanceOf(PlrError);
        expect((e as PlrError).code).toBe("E_DNS");
      }
    }
  });
  it("error messages carry no names", () => {
    try { parseDnsResponse(resp({ qn: "secret-name.com" }), "example.com", "A"); } catch (e) { expect(String(e)).not.toMatch(/secret|example/); }
  });
  it("localhost rule edge cases", () => {
    for (const n of [".localhost", "LOCALHOST.", "a.b.c.localhost"]) expect(isLocalhostName(n), n).toBe(true);
    for (const n of ["", ".", "localhost..", "localhost.localdomain", 1 as unknown as string]) expect(isLocalhostName(n), String(n)).toBe(false);
  });
});

describe("operator organizations (SPEC §7 rev 1.2)", () => {
  const h = (b: number) => toHex(new Uint8Array(32).fill(b));
  const rec = (org: unknown): Record<string, unknown> => ({
    compose_hash: h(1), os_measurement: h(2), x25519: h(3), ed25519: h(4), operator: "op.near", org_id: org,
    registered_at_ms: 1, expires_at_ms: Date.now() + 60_000, next_seq: 0,
  });
  it("isOrgId / isInstanceRecord", () => {
    for (const o of ["a", "acme-hosting.eu", "0", "a".repeat(64), "a_b"]) expect(isOrgId(o), o).toBe(true);
    for (const o of ["", "Org-A", "-org", "org a", "o".repeat(65), "org/a", ".a", null, 1]) expect(isOrgId(o), String(o)).toBe(false);
    expect(isInstanceRecord(rec(null))).toBe(true);
    expect(isInstanceRecord(rec("acme"))).toBe(true);
    expect(isInstanceRecord(rec("Acme"))).toBe(false);
    const missing = rec(null); delete missing.org_id;
    expect(isInstanceRecord(missing)).toBe(false);
  });
  it("MemoryRegistry returns the live org of the operator", async () => {
    const r = new MemoryRegistry({ root: { kind: "MOCK", p256: "00".repeat(64) }, compose: [], os: [], instances: { [h(9)]: rec(null) as unknown as InstanceRecord } });
    expect((await r.getInstance(h(9)))!.org_id).toBeNull();
    r.approveOperator("op.near", "org-a");
    expect((await r.getInstance(h(9)))!.org_id).toBe("org-a");
    expect(await r.getOperator("op.near")).toBe("org-a");
    r.approveOperator("op.near", "org-b");
    expect((await r.getInstance(h(9)))!.org_id).toBe("org-b");
    r.revokeOperator("op.near");
    expect((await r.getInstance(h(9)))!.org_id).toBeNull();
    expect(code(() => r.approveOperator("op.near", "Bad"))).toBe("E_BAD_INPUT");
    const r2 = new MemoryRegistry({ root: { kind: "MOCK", p256: "00".repeat(64) }, compose: [], os: [], instances: { [h(9)]: rec(null) as unknown as InstanceRecord }, operators: { "op.near": "x" } });
    expect((await r2.getInstance(h(9)))!.org_id).toBe("x");
  });
  it("SOCKS mapping of the new codes", () => {
    expect(socksReplyFor("E_OPERATOR_UNAPPROVED")).toBe(2);
    expect(socksReplyFor("E_SAME_OPERATOR")).toBe(2);
  });
});
