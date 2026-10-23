// LOCKED — SPEC-VPN §8, §9.1 (RFC 1928 server side, CONNECT + no-auth)
import { describe, it, expect } from "vitest";
import { parseSocksGreeting, parseSocksRequest, encodeSocksReply, socksReplyFor, PlrError } from "../src/index.js";
import { enc, cat } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const b = (...xs: number[]) => new Uint8Array(xs);
const port = (p: number) => b(p >> 8, p & 0xff);

describe("greeting", () => {
  it("parses VER 5 + methods, needs more bytes when partial", () => {
    expect(parseSocksGreeting(b(5, 1, 0))).toEqual({ consumed: 3, methods: [0] });
    expect(parseSocksGreeting(b(5, 2, 0, 2, 99))).toEqual({ consumed: 4, methods: [0, 2] });
    expect(parseSocksGreeting(b(5))).toBeNull();
    expect(parseSocksGreeting(b(5, 3, 0))).toBeNull();
    expect(parseSocksGreeting(b())).toBeNull();
  });
  it("rejects wrong version / zero methods", () => {
    expect(code(() => parseSocksGreeting(b(4, 1, 0)))).toBe("E_BAD_INPUT");
    expect(code(() => parseSocksGreeting(b(5, 0)))).toBe("E_BAD_INPUT");
  });
});

describe("request", () => {
  it("domain, IPv4 and IPv6 CONNECT", () => {
    const d = cat(b(5, 1, 0, 3, 11), enc("example.com"), port(443));
    expect(parseSocksRequest(d)).toEqual({ consumed: d.length, cmd: 1, atyp: "domain", host: "example.com", port: 443 });
    const v4 = cat(b(5, 1, 0, 1, 8, 8, 4, 4), port(53));
    expect(parseSocksRequest(v4)).toEqual({ consumed: 10, cmd: 1, atyp: "ipv4", host: "8.8.4.4", port: 53 });
    const v6 = cat(b(5, 1, 0, 4), b(0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11), port(443));
    expect(parseSocksRequest(v6)).toEqual({ consumed: 22, cmd: 1, atyp: "ipv6", host: "2606:4700:4700::1111", port: 443 });
    const lo6 = cat(b(5, 1, 0, 4), new Uint8Array(15), b(1), port(80));
    expect(parseSocksRequest(lo6)!.host).toBe("::1");
  });
  it("reports other commands (caller replies 0x07) and keeps trailing bytes unconsumed", () => {
    const bind = cat(b(5, 2, 0, 1, 1, 2, 3, 4), port(80));
    expect(parseSocksRequest(bind)!.cmd).toBe(2);
    const withData = cat(b(5, 1, 0, 1, 1, 2, 3, 4), port(80), enc("GET /"));
    expect(parseSocksRequest(withData)!.consumed).toBe(10);
  });
  it("returns null until the request is complete", () => {
    const d = cat(b(5, 1, 0, 3, 11), enc("example.com"), port(443));
    for (let i = 0; i < d.length; i++) expect(parseSocksRequest(d.slice(0, i)), `len ${i}`).toBeNull();
  });
  it("rejects malformed requests", () => {
    expect(code(() => parseSocksRequest(cat(b(4, 1, 0, 1, 1, 2, 3, 4), port(80))))).toBe("E_BAD_INPUT");
    expect(code(() => parseSocksRequest(cat(b(5, 1, 1, 1, 1, 2, 3, 4), port(80))))).toBe("E_BAD_INPUT"); // RSV ≠ 0
    expect(code(() => parseSocksRequest(cat(b(5, 1, 0, 3, 0), port(80))))).toBe("E_BAD_INPUT");       // empty domain
    expect(code(() => parseSocksRequest(cat(b(5, 1, 0, 9, 1, 2, 3, 4), port(80))))).toBe("E_BAD_INPUT"); // unknown ATYP
  });
});

describe("replies", () => {
  it("encodes VER 5, REP, RSV 0, ATYP 1, 0.0.0.0:0", () => {
    expect(encodeSocksReply(0)).toEqual(b(5, 0, 0, 1, 0, 0, 0, 0, 0, 0));
    expect(encodeSocksReply(2)).toEqual(b(5, 2, 0, 1, 0, 0, 0, 0, 0, 0));
  });
  it("maps PLR codes per SPEC-VPN §8", () => {
    expect(socksReplyFor(null)).toBe(0);
    for (const c of ["E_COMPOSE_NOT_ALLOWED", "E_REPORT_DATA_KEYS", "E_NONCE", "E_QUOTE_SIG", "E_INSTANCE_NOT_REGISTERED",
      "E_OS_NOT_ALLOWED", "E_DEBUG_TD", "E_ROOT_UNTRUSTED", "E_REGISTRY_UNAVAILABLE", "E_EGRESS_DENIED"]) expect(socksReplyFor(c), c).toBe(2);
    expect(socksReplyFor("E_DNS")).toBe(4);
    expect(socksReplyFor("E_CONNECT_FAILED")).toBe(5);
    expect(socksReplyFor("E_DECRYPT")).toBe(1);
    expect(socksReplyFor("E_SOMETHING_ELSE")).toBe(1);
  });
});
