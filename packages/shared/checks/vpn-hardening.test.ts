// Extra (unlocked) hardening checks for the PLR-VPN-v1 library pieces.
import { describe, it, expect } from "vitest";
import { isIP } from "node:net";
import { randomBytes } from "@noble/hashes/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  parseIpv4, parseIpv6, formatIpv6, classifyIp, egressAllowed, validateDestination, TunnelWriter, TunnelReader, FRAME, TUNNEL,
  encodeConnect, parseConnect, encodeConnectErr, parseConnectErr, encodeReceiptPayload, parseReceiptPayload, signVpnReceipt,
  verifyVpnReceipt, isVpnReceipt, parseSocksRequest, PlrError, egressIdentity, CONNECT_ERR_CODES, CONNECT_PADDED_LEN, CONNECT_ERR_PADDED_LEN, type VpnReceipt,
} from "../src/index.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const enc = (s: string) => new TextEncoder().encode(s);
const u32be = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; };

describe("ip parsing", () => {
  it("is never more lenient than node:net", () => {
    const alphabet = "0123456789abcdefABCDEF:.%[]x ";
    for (let i = 0; i < 20000; i++) {
      const n = 1 + (randomBytes(1)[0]! % 20);
      let s = "";
      for (const r of randomBytes(n)) s += alphabet[r % alphabet.length];
      if (parseIpv4(s) !== null) expect(isIP(s), s).toBe(4);
      if (parseIpv6(s) !== null) expect(isIP(s), s).toBe(6);
    }
  });
  it("formats random addresses in RFC 5952 form that round-trips (WHATWG URL agrees for non-mapped)", () => {
    for (let i = 0; i < 2000; i++) {
      const b = randomBytes(16);
      for (let j = 0; j < 16; j++) if (randomBytes(1)[0]! < 128) b[j] = 0; // many zero runs
      const s = formatIpv6(b);
      expect(parseIpv6(s), s).toEqual(b);
      expect(s).toBe(s.toLowerCase());
      const mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
      if (!mapped) expect(new URL(`http://[${s}]/`).hostname, s).toBe(`[${s}]`);
    }
    expect(formatIpv6(parseIpv6("2001:db8:0:0:1:0:0:1")!)).toBe("2001:db8::1:0:0:1");
    expect(formatIpv6(parseIpv6("2001:db8:0:1:1:1:1:1")!)).toBe("2001:db8:0:1:1:1:1:1");
    expect(formatIpv6(parseIpv6("::ffff:7f00:1")!)).toBe("::ffff:127.0.0.1");
  });
  it("rejects malformed IPv6 forms", () => {
    for (const s of [":", ":::", "1:", ":1", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "12345::", "g::",
      "::1.2.3", "::01.2.3.4", "1.2.3.4::", "::1.2.3.4:1", "1:2:3:4:5:6:7:1.2.3.4", "fe80::1%eth0", "::ffff:256.0.0.1"])
      expect(parseIpv6(s), s).toBeNull();
    expect(parseIpv6("1:2:3:4:5:6:1.2.3.4")).not.toBeNull();
    expect(parseIpv6("1:2:3:4:5:6:7::")).not.toBeNull();
  });
});

describe("egress extras", () => {
  it("covers SIIT, Teredo, NAT64 local-use, non-global-unicast IPv6", () => {
    expect(classifyIp("::ffff:0:127.0.0.1")).toBe("loopback");
    expect(classifyIp("::ffff:0:a9fe:a9fe")).toBe("link-local");
    expect(classifyIp("2001::1")).toBe("reserved");
    expect(classifyIp("64:ff9b:1::7f00:1")).toBe("reserved");
    expect(classifyIp("fec0::1")).toBe("reserved");
    expect(classifyIp("4000::1")).toBe("reserved");
    expect(classifyIp("::8.8.8.8")).toBe("public");
    expect(classifyIp("::0.0.0.2")).toBe("unspecified");
    expect(classifyIp("FE80::1")).toBe("link-local");
  });
  it("denies on malformed policies", () => {
    expect(egressAllowed("8.8.8.8", { allow_loopback: false, deny_private: false })).toBe(false);
    expect(egressAllowed("127.0.0.1", { allow_loopback: "yes", deny_private: true } as never)).toBe(false);
    expect(egressAllowed("8.8.8.8", null as never)).toBe(false);
    expect(egressAllowed(42 as never, { allow_loopback: true, deny_private: true })).toBe(false);
  });
  it("validateDestination errors never echo the input", () => {
    try { validateDestination("secret-host_name.example", 80); } catch (e) { expect(String((e as Error).message)).not.toContain("secret"); }
    expect(code(() => validateDestination(undefined as never, 80))).toBe("E_BAD_INPUT");
    expect(code(() => validateDestination("a".repeat(250) + ".com", 80))).toBe("E_BAD_INPUT");
    expect(code(() => validateDestination(".", 80))).toBe("E_BAD_INPUT");
    expect(code(() => validateDestination("example.com..", 80))).toBe("E_BAD_INPUT");
    expect(code(() => validateDestination("1.2.3.4.", 80))).toBe("E_BAD_INPUT");
  });
});

describe("tunnel reader extras", () => {
  const key = randomBytes(32), th = randomBytes(32);
  it("rejects a huge header before buffering the body; end() after error rethrows", () => {
    const r = new TunnelReader(key, th, 2);
    expect(code(() => r.push(u32be(0xffffffff)))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => r.end())).toBe("E_TUNNEL_PROTOCOL");
  });
  it("enforces per-direction types and per-type payload sizes", () => {
    const evil = new TunnelWriter(key, th, 2);
    expect(code(() => evil.seal(FRAME.CONNECT, enc("{}")))).toBe("E_BAD_INPUT");   // c2s-only type
    expect(code(() => evil.seal(FRAME.DATA, new Uint8Array()))).toBe("E_BAD_INPUT"); // DATA ≥ 1 byte
    expect(code(() => evil.seal(FRAME.FIN, enc("x")))).toBe("E_BAD_INPUT");         // FIN is empty
    expect(code(() => new TunnelWriter(key, th, 3 as never))).toBe("E_BAD_INPUT");
    const c = new TunnelWriter(key, th, 1);
    expect(code(() => c.seal(FRAME.CONNECT, new Uint8Array(513)))).toBe("E_BAD_INPUT");
    expect(code(() => c.seal(FRAME.RECEIPT, enc("{}")))).toBe("E_BAD_INPUT");
  });
  it("push after a clean end() is refused; empty chunks are fine", () => {
    const w = new TunnelWriter(key, th, 1);
    const r = new TunnelReader(key, th, 1);
    expect(r.push(new Uint8Array())).toEqual([]);
    expect(r.push(w.seal(FRAME.FIN, new Uint8Array()))).toHaveLength(1);
    r.end();
    expect(() => r.push(new Uint8Array(1))).toThrow(PlrError);
  });
  it("a good frame followed by a tampered one in the same chunk yields nothing", () => {
    const w = new TunnelWriter(key, th, 2);
    const a = w.seal(FRAME.DATA, enc("a")), b = w.seal(FRAME.DATA, enc("b"));
    b[b.length - 1]! ^= 1;
    const r = new TunnelReader(key, th, 2);
    const buf = new Uint8Array(a.length + b.length); buf.set(a); buf.set(b, a.length);
    expect(code(() => r.push(buf))).toBe("E_DECRYPT");
  });
  it("MAX_FRAME_LEN frames are accepted", () => {
    const f = new TunnelWriter(key, th, 1).seal(FRAME.DATA, randomBytes(TUNNEL.MAX_PAYLOAD));
    expect(f.length).toBe(4 + TUNNEL.MAX_FRAME_LEN);
    expect(new TunnelReader(key, th, 1).push(f)[0]!.payload.length).toBe(TUNNEL.MAX_PAYLOAD);
  });
});

describe("payload codecs", () => {
  it("CONNECT round-trips and is strict", () => {
    expect(parseConnect(encodeConnect("example.com", 443))).toEqual({ host: "example.com", port: 443 });
    expect(parseConnect(encodeConnect("::1", 80))).toEqual({ host: "::1", port: 80 });
    for (const s of ['{"host":"a.com","port":80,"x":1}', '{"host":"a.com","port":80.0}', '{"host":"a.com","port":"80"}', '[]', 'null',
      '{"host":"a b","port":80}', '{"host":"a.com","port":8e1}', '{"port":80}'])
      expect(code(() => parseConnect(enc(s))), s).toBe("E_BAD_INPUT");
    expect(code(() => parseConnect(new Uint8Array([0xff, 0xfe])))).toBe("E_BAD_INPUT");
    expect(code(() => encodeConnect("bad host", 80))).toBe("E_BAD_INPUT");
  });
  // Review finding (low): unpadded payloads told the two-hop entry the destination name's length and which
  // CONNECT error the exit returned, from the inner frame lengths.
  it("CONNECT and CONNECT_ERR have one fixed size each (no name-length / error-kind leak); unpadded JSON still parses", () => {
    const sizes = new Set(["a.io", "wikileaks.org", "protonmail.com", "x".repeat(63) + "." + "y".repeat(63) + ".com", "::1", "8.8.8.8"]
      .flatMap((h) => [1, 443, 65535].map((p) => encodeConnect(h, p).length)));
    expect([...sizes]).toEqual([CONNECT_PADDED_LEN]);
    expect(CONNECT_PADDED_LEN).toBe(512);
    expect(parseConnect(encodeConnect("wikileaks.org", 443))).toEqual({ host: "wikileaks.org", port: 443 });
    expect(parseConnect(enc('{"host":"a.io","port":443}'))).toEqual({ host: "a.io", port: 443 });
    const longest = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
    expect(longest.length).toBe(253);
    expect(parseConnect(encodeConnect(longest, 65535))).toEqual({ host: longest, port: 65535 });
    expect(new Set(CONNECT_ERR_CODES.map((c) => encodeConnectErr(c).length))).toEqual(new Set([CONNECT_ERR_PADDED_LEN]));
    for (const c of CONNECT_ERR_CODES) expect(parseConnectErr(encodeConnectErr(c))).toBe(c);
    expect(parseConnectErr(enc('{"code":"E_DNS"}'))).toBe("E_DNS");
    // Padding is whitespace only: anything else after the object is still rejected.
    expect(code(() => parseConnect(enc('{"host":"a.io","port":443}' + "x".repeat(10))))).toBe("E_BAD_INPUT");
    expect(code(() => parseConnect(enc('{"host":"a.io","port":443}' + " ".repeat(500))))).toBe("E_BAD_INPUT"); // > 512
  });
  it("CONNECT_ERR carries only the four generic codes", () => {
    expect(parseConnectErr(encodeConnectErr("E_DNS"))).toBe("E_DNS");
    expect(code(() => encodeConnectErr("E_DECRYPT" as never))).toBe("E_BAD_INPUT");
    expect(code(() => parseConnectErr(enc('{"code":"E_DECRYPT"}')))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => parseConnectErr(enc('{"code":"E_DNS","host":"x"}')))).toBe("E_TUNNEL_PROTOCOL");
  });
  it("RECEIPT payload round-trips; out-of-order timestamps are not a receipt", () => {
    const sk = ed25519.utils.randomSecretKey();
    const receipt: VpnReceipt = { v: 1, th: "aa".repeat(32), compose_hash: "bb".repeat(32), key_hash: "cc".repeat(32), seq: 0, ts_open_ms: 1, ts_close_ms: 2 };
    const sig = signVpnReceipt(receipt, sk);
    const p = parseReceiptPayload(encodeReceiptPayload({ receipt, sig }));
    expect(p).toEqual({ receipt, sig });
    expect(verifyVpnReceipt(p.receipt, p.sig, ed25519.getPublicKey(sk))).toBe(true);
    expect(isVpnReceipt({ ...receipt, ts_open_ms: 3 })).toBe(false);
    expect(isVpnReceipt({ ...receipt, dest: "x" })).toBe(false);
    expect(code(() => parseReceiptPayload(enc(JSON.stringify({ receipt: { ...receipt, bytes: 5 }, sig }))))).toBe("E_TUNNEL_PROTOCOL");
  });
});

describe("socks extras", () => {
  it("domain bytes are returned verbatim (one char per byte) and rejected later", () => {
    const d = new Uint8Array([5, 1, 0, 3, 3, 0x61, 0xc3, 0xa4, 0, 80]);
    const r = parseSocksRequest(d)!;
    expect(r.host.length).toBe(3);
    expect(code(() => validateDestination(r.host, r.port))).toBe("E_BAD_INPUT");
  });
});

describe("egressIdentity (exit-side denylists)", () => {
  it("maps every IPv4-embedding IPv6 form to the dotted quad classifyIp uses, others to RFC 5952", () => {
    for (let i = 0; i < 2000; i++) {
      const b = randomBytes(4);
      const v4 = `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
      const h = (x: number, y: number) => ((x << 8) | y).toString(16);
      for (const form of [v4, `::ffff:${v4}`, `::ffff:${h(b[0]!, b[1]!)}:${h(b[2]!, b[3]!)}`, `64:ff9b::${h(b[0]!, b[1]!)}:${h(b[2]!, b[3]!)}`, `2002:${h(b[0]!, b[1]!)}:${h(b[2]!, b[3]!)}::5`, `::ffff:0:${v4}`]) {
        expect(egressIdentity(form), form).toBe(v4);
        expect(classifyIp(form), form).toBe(classifyIp(v4));
      }
    }
    expect(egressIdentity("::")).toBe("::");
    expect(egressIdentity("::1")).toBe("::1");
    expect(egressIdentity("64:ff9b:1::1")).toBe("64:ff9b:1::1");
    expect(classifyIp("64:ff9b:1::1")).toBe("reserved");
    expect(egressIdentity("2A01:04F8::0007")).toBe("2a01:4f8::7");
    for (const bad of ["", "1.2.3", "[::1]", "fe80::1%en0", "localhost", "01.2.3.4"]) expect(egressIdentity(bad), bad).toBeNull();
  });
});
