// LOCKED — SPEC-VPN §6
import { describe, it, expect } from "vitest";
import { classifyIp, egressAllowed, validateDestination, PlrError } from "../src/index.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const PROD = { allow_loopback: false, deny_private: true };
const TEST = { allow_loopback: true, deny_private: true };

describe("classifyIp", () => {
  const table: Array<[string, ReturnType<typeof classifyIp>]> = [
    ["8.8.8.8", "public"], ["1.1.1.1", "public"], ["93.184.215.14", "public"], ["172.15.255.255", "public"], ["172.32.0.1", "public"],
    ["100.63.255.255", "public"], ["100.128.0.0", "public"], ["198.17.255.255", "public"], ["223.255.255.255", "public"],
    ["0.0.0.0", "unspecified"], ["0.1.2.3", "unspecified"],
    ["127.0.0.1", "loopback"], ["127.255.255.254", "loopback"],
    ["10.0.0.1", "private"], ["172.16.0.1", "private"], ["172.31.255.255", "private"], ["192.168.1.1", "private"],
    ["169.254.169.254", "link-local"], ["169.254.0.1", "link-local"],
    ["100.64.0.1", "cgnat"], ["100.127.255.255", "cgnat"],
    ["224.0.0.1", "multicast"], ["239.255.255.255", "multicast"],
    ["192.0.0.8", "reserved"], ["192.0.2.1", "reserved"], ["198.18.0.1", "reserved"], ["198.19.255.255", "reserved"],
    ["198.51.100.7", "reserved"], ["203.0.113.9", "reserved"], ["240.0.0.1", "reserved"], ["255.255.255.255", "reserved"],
    ["2606:4700:4700::1111", "public"], ["2001:4860:4860::8888", "public"],
    ["::", "unspecified"], ["::1", "loopback"], ["0:0:0:0:0:0:0:1", "loopback"],
    ["fc00::1", "private"], ["fd12:3456::1", "private"], ["fe80::1", "link-local"], ["febf::1", "link-local"],
    ["ff02::1", "multicast"], ["2001:db8::1", "reserved"], ["100::1", "reserved"],
    // IPv4 embedded in IPv6 → classified by the embedded address
    ["::ffff:127.0.0.1", "loopback"], ["::ffff:7f00:1", "loopback"], ["::ffff:10.0.0.1", "private"], ["::ffff:8.8.8.8", "public"],
    ["::127.0.0.1", "loopback"], ["64:ff9b::a9fe:a9fe", "link-local"], ["64:ff9b::8.8.8.8", "public"],
    ["2002:7f00:0001::1", "loopback"], ["2002:c0a8:0101::", "private"], ["2002:0808:0808::1", "public"],
    // not IP literals
    ["", "invalid"], ["localhost", "invalid"], ["example.com", "invalid"], ["1.2.3", "invalid"], ["1.2.3.4.5", "invalid"],
    ["256.1.1.1", "invalid"], ["01.2.3.4", "invalid"], ["1.2.3.04", "invalid"], ["0x7f.0.0.1", "invalid"], ["2130706433", "invalid"],
    ["[::1]", "invalid"], ["::1%lo0", "invalid"], ["1::2::3", "invalid"], [" 8.8.8.8", "invalid"],
  ];
  for (const [ip, cls] of table) it(`${JSON.stringify(ip)} → ${cls}`, () => expect(classifyIp(ip)).toBe(cls));
});

describe("egressAllowed", () => {
  it("production policy allows only public addresses", () => {
    expect(egressAllowed("8.8.8.8", PROD)).toBe(true);
    expect(egressAllowed("2606:4700:4700::1111", PROD)).toBe(true);
    for (const ip of ["127.0.0.1", "::1", "::ffff:127.0.0.1", "10.1.2.3", "192.168.0.10", "169.254.169.254", "100.64.0.1",
      "224.0.0.251", "0.0.0.0", "::", "fe80::1", "fd00::1", "240.0.0.1", "2002:7f00:1::", "64:ff9b::a9fe:a9fe", "localhost", "garbage"])
      expect(egressAllowed(ip, PROD), ip).toBe(false);
  });
  it("test policy additionally allows loopback only", () => {
    expect(egressAllowed("127.0.0.1", TEST)).toBe(true);
    expect(egressAllowed("::1", TEST)).toBe(true);
    expect(egressAllowed("::ffff:127.0.0.1", TEST)).toBe(true);
    for (const ip of ["10.0.0.1", "169.254.169.254", "0.0.0.0", "fd00::1", "localhost"]) expect(egressAllowed(ip, TEST), ip).toBe(false);
  });
});

describe("validateDestination", () => {
  it("accepts domains and IP literals with valid ports", () => {
    for (const [h, p] of [["example.com", 443], ["EXAMPLE.com.", 80], ["a-b.c-d.io", 1], ["localhost", 65535], ["8.8.8.8", 53],
      ["2606:4700:4700::1111", 443], ["xn--bcher-kva.example", 8443], ["a".repeat(63) + ".com", 80]] as const)
      expect(() => validateDestination(h, p), `${h}:${p}`).not.toThrow();
  });
  it("rejects bad hosts and ports with E_BAD_INPUT", () => {
    const bad: Array<[string, number]> = [
      ["", 80], ["-a.com", 80], ["a-.com", 80], ["a..com", 80], ["a_b.com", 80], ["exa mple.com", 80], ["a".repeat(64) + ".com", 80],
      [("a".repeat(62) + ".").repeat(4) + "abcde", 80], ["[::1]", 80], ["example.com:80", 80], ["exämple.com", 80], ["01.2.3.4", 80],
      ["example.com", 0], ["example.com", 65536], ["example.com", 80.5], ["example.com", -1], ["example.com", NaN],
    ];
    for (const [h, p] of bad) expect(code(() => validateDestination(h, p)), `${JSON.stringify(h)}:${p}`).toBe("E_BAD_INPUT");
  });
});
