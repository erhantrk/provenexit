// LOCKED — SPEC-VPN §6, §6.1 (RFC 8484 / RFC 1035 codec, RFC 8467 padding)
import { describe, it, expect } from "vitest";
import { encodeDnsQuery, parseDnsResponse, isLocalhostName, PlrError } from "../src/index.js";
import { cat, enc } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const u16 = (n: number) => new Uint8Array([n >> 8, n & 0xff]);
const u32 = (n: number) => new Uint8Array([n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
const qname = (name: string) => cat(...name.replace(/\.$/, "").toLowerCase().split(".").map((l) => cat(new Uint8Array([l.length]), enc(l))), new Uint8Array([0]));
const A = 1, AAAA = 28, CNAME = 5, TXT = 16;

// ---- independent reference query encoder (§6.1)
function refQuery(name: string, qtype: number): Uint8Array {
  const head = cat(u16(0), u16(0x0100), u16(1), u16(0), u16(0), u16(1));
  const q = cat(qname(name), u16(qtype), u16(1));
  const base = head.length + q.length + 11 + 4;
  const P = (128 - (base % 128)) % 128;
  return cat(head, q, new Uint8Array([0]), u16(41), u16(4096), u32(0), u16(4 + P), u16(12), u16(P), new Uint8Array(P));
}

// ---- independent response builder
type RR = { name: Uint8Array; type: number; cls?: number; data: Uint8Array };
function resp(o: { id?: number; flags?: number; qn?: string; qt?: number; qd?: number; answers?: RR[]; ancount?: number; tail?: Uint8Array }): Uint8Array {
  const answers = o.answers ?? [];
  const head = cat(u16(o.id ?? 0), u16(o.flags ?? 0x8180), u16(o.qd ?? 1), u16(o.ancount ?? answers.length), u16(0), u16(0));
  const q = (o.qd ?? 1) ? cat(qname(o.qn ?? "example.com"), u16(o.qt ?? A), u16(1)) : new Uint8Array();
  const rrs = answers.map((r) => cat(r.name, u16(r.type), u16(r.cls ?? 1), u32(300), u16(r.data.length), r.data));
  return cat(head, q, ...rrs, o.tail ?? new Uint8Array());
}
const PTR_Q = new Uint8Array([0xc0, 12]); // pointer to the question name at offset 12
const v4 = (...b: number[]) => new Uint8Array(b);

describe("encodeDnsQuery", () => {
  it("produces the exact §6.1 bytes, padded to 128", () => {
    for (const [n, t, qt] of [["example.com", "A", A], ["Example.COM.", "AAAA", AAAA], ["a.b.c.d.e.f.g.dest.plr.test", "A", A]] as const) {
      const q = encodeDnsQuery(n, t);
      expect(q).toEqual(refQuery(n, qt));
      expect(q.length % 128).toBe(0);
    }
    expect(encodeDnsQuery("x".repeat(63) + ".com", "A").length % 128).toBe(0);
  });
  it("rejects invalid names", () => {
    for (const n of ["", "a..b", "-a.com", "a".repeat(64) + ".com", "exa mple.com", "127.0.0.1"])
      expect(code(() => encodeDnsQuery(n, "A")), n).toBe("E_BAD_INPUT");
  });
});

describe("parseDnsResponse", () => {
  it("returns A and AAAA addresses (compressed owner names)", () => {
    const r = resp({ answers: [{ name: PTR_Q, type: A, data: v4(93, 184, 215, 14) }, { name: PTR_Q, type: A, data: v4(1, 2, 3, 4) }] });
    expect(parseDnsResponse(r, "example.com", "A")).toEqual(["93.184.215.14", "1.2.3.4"]);
    const six = new Uint8Array(16); six[0] = 0x26; six[1] = 0x06; six[2] = 0x28; six[3] = 0x00; six[15] = 1;
    const r6 = resp({ qt: AAAA, answers: [{ name: PTR_Q, type: AAAA, data: six }] });
    expect(parseDnsResponse(r6, "example.com", "AAAA")).toEqual(["2606:2800::1"]);
  });

  it("matches the question case-insensitively and accepts a trailing dot", () => {
    const r = resp({ qn: "EXAMPLE.com", answers: [{ name: PTR_Q, type: A, data: v4(8, 8, 8, 8) }] });
    expect(parseDnsResponse(r, "example.COM.", "A")).toEqual(["8.8.8.8"]);
  });

  it("follows a CNAME chain and ignores unrelated records", () => {
    const r = resp({ answers: [
      { name: PTR_Q, type: CNAME, data: qname("edge.cdn.net") },
      { name: qname("edge.cdn.net"), type: CNAME, data: qname("x.cdn.net") },
      { name: qname("x.cdn.net"), type: A, data: v4(9, 9, 9, 9) },
      { name: qname("other.net"), type: A, data: v4(6, 6, 6, 6) },          // not in the chain
      { name: PTR_Q, type: TXT, data: cat(new Uint8Array([2]), enc("hi")) }, // other type
      { name: PTR_Q, type: A, cls: 3, data: v4(7, 7, 7, 7) },                // other class
    ] });
    expect(parseDnsResponse(r, "example.com", "A")).toEqual(["9.9.9.9"]);
  });

  it("caps the CNAME chain at 8 hops", () => {
    const chain = (n: number) => {
      const rrs: RR[] = [];
      let cur = "example.com";
      for (let i = 0; i < n; i++) { const nx = `c${i}.net`; rrs.push({ name: qname(cur), type: CNAME, data: qname(nx) }); cur = nx; }
      rrs.push({ name: qname(cur), type: A, data: v4(5, 5, 5, 5) });
      return resp({ answers: rrs });
    };
    expect(parseDnsResponse(chain(8), "example.com", "A")).toEqual(["5.5.5.5"]);
    expect(parseDnsResponse(chain(9), "example.com", "A")).toEqual([]);
  });

  it("NXDOMAIN and NODATA ⇒ []", () => {
    expect(parseDnsResponse(resp({ flags: 0x8183 }), "example.com", "A")).toEqual([]);
    expect(parseDnsResponse(resp({}), "example.com", "A")).toEqual([]);
  });

  it("ignores trailing bytes after the counted sections", () => {
    const r = resp({ answers: [{ name: PTR_Q, type: A, data: v4(1, 1, 1, 1) }], tail: new Uint8Array([1, 2, 3]) });
    expect(parseDnsResponse(r, "example.com", "A")).toEqual(["1.1.1.1"]);
  });

  const bad: Array<[string, () => Uint8Array, string?, ("A" | "AAAA")?]> = [
    ["too short", () => new Uint8Array(11)],
    ["id ≠ 0", () => resp({ id: 7 })],
    ["QR = 0", () => resp({ flags: 0x0180 })],
    ["opcode ≠ 0", () => resp({ flags: 0x8980 })],
    ["truncated (TC)", () => resp({ flags: 0x8380 })],
    ["SERVFAIL", () => resp({ flags: 0x8182 })],
    ["REFUSED", () => resp({ flags: 0x8185 })],
    ["QDCOUNT 0", () => resp({ qd: 0 })],
    ["question name mismatch", () => resp({ qn: "evil.com" })],
    ["question type mismatch", () => resp({ qt: AAAA })],
    ["ANCOUNT > 32", () => resp({ answers: Array.from({ length: 33 }, () => ({ name: PTR_Q, type: A, data: v4(1, 1, 1, 1) })) })],
    ["ANCOUNT larger than present", () => resp({ ancount: 2, answers: [{ name: PTR_Q, type: A, data: v4(1, 1, 1, 1) }] })],
    ["A with rdlength 5", () => resp({ answers: [{ name: PTR_Q, type: A, data: v4(1, 1, 1, 1, 1) }] })],
    ["AAAA with rdlength 4", () => resp({ qt: AAAA, answers: [{ name: PTR_Q, type: AAAA, data: v4(1, 1, 1, 1) }] }), "example.com", "AAAA"],
    ["forward compression pointer", () => resp({ answers: [{ name: new Uint8Array([0xc0, 200]), type: A, data: v4(1, 1, 1, 1) }] })],
    ["self-referencing pointer loop", () => {
      const r = resp({ answers: [{ name: new Uint8Array([0xc0, 0]), type: A, data: v4(1, 1, 1, 1) }] });
      const off = 12 + qname("example.com").length + 4; r[off] = 0xc0 | (off >> 8); r[off + 1] = off & 0xff; return r;
    }],
    ["label > 63 (0x40 flag bits)", () => resp({ answers: [{ name: new Uint8Array([0x40, 0]), type: A, data: v4(1, 1, 1, 1) }] })],
    ["name longer than 255", () => resp({ answers: [{ name: cat(...Array.from({ length: 5 }, () => cat(new Uint8Array([63]), new Uint8Array(63).fill(97))), new Uint8Array([0])), type: A, data: v4(1, 1, 1, 1) }] })],
    ["RR overruns the message", () => resp({ answers: [{ name: PTR_Q, type: A, data: v4(1, 1, 1, 1) }] }).slice(0, -2)],
  ];
  for (const [name, mk, qn, qt] of bad) it(`E_DNS: ${name}`, () => expect(code(() => parseDnsResponse(mk(), qn ?? "example.com", qt ?? "A"))).toBe("E_DNS"));
});

describe("isLocalhostName (RFC 6761)", () => {
  it("matches localhost and *.localhost in any case, with optional trailing dot", () => {
    for (const n of ["localhost", "LOCALHOST", "localhost.", "a.localhost", "x.y.LocalHost."]) expect(isLocalhostName(n), n).toBe(true);
    for (const n of ["localhost.com", "mylocalhost", "localhostx", "127.0.0.1", "example.com"]) expect(isLocalhostName(n), n).toBe(false);
  });
});
