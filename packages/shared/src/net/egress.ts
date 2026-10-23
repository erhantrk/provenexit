/**
 * Destination validation and egress policy (SPEC-VPN §6). Pure functions, no DNS, no I/O.
 *
 * Errors are content-free: the rejected host/port never appears in an error message.
 */
import { PlrError } from "../errors.js";
import { isPlainObject } from "../bytes.js";
import { formatIpv4, formatIpv6, parseIpv4, parseIpv6 } from "./ip.js";

export type IpClass =
  | "public" | "loopback" | "private" | "link-local" | "cgnat" | "multicast" | "unspecified" | "reserved" | "invalid";

export interface EgressPolicy {
  allow_loopback: boolean;
  deny_private: boolean;
}

/** Max DNS name length (SPEC-VPN §6: total ≤ 253 chars, the optional trailing dot included). */
export const MAX_DNS_NAME_LEN = 253;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const ALL_DIGITS_RE = /^[0-9]+$/;

/** `[prefix bytes (big-endian u32), prefix length]` */
type Cidr4 = readonly [number, number];
const V4_TABLE: ReadonlyArray<readonly [Exclude<IpClass, "public" | "invalid">, readonly Cidr4[]]> = [
  ["unspecified", [[0x00000000, 8]]],
  ["loopback", [[0x7f000000, 8]]],
  ["private", [[0x0a000000, 8], [0xac100000, 12], [0xc0a80000, 16]]],
  ["link-local", [[0xa9fe0000, 16]]],
  ["cgnat", [[0x64400000, 10]]],
  ["multicast", [[0xe0000000, 4]]],
  ["reserved", [
    [0xc0000000, 24], // 192.0.0.0/24   IETF protocol assignments
    [0xc0000200, 24], // 192.0.2.0/24   TEST-NET-1
    [0xc6120000, 15], // 198.18.0.0/15  benchmarking
    [0xc6336400, 24], // 198.51.100.0/24 TEST-NET-2
    [0xcb007100, 24], // 203.0.113.0/24 TEST-NET-3
    [0xf0000000, 4], //  240.0.0.0/4    reserved, incl. 255.255.255.255
  ]],
];

function inCidr4(a: number, [prefix, len]: Cidr4): boolean {
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  return ((a & mask) >>> 0) === prefix;
}

function classifyV4(b: Uint8Array): Exclude<IpClass, "invalid"> {
  const a = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
  for (const [cls, cidrs] of V4_TABLE) if (cidrs.some((c) => inCidr4(a, c))) return cls;
  return "public";
}

function zeros(b: Uint8Array, from: number, to: number): boolean {
  for (let i = from; i < to; i++) if (b[i] !== 0) return false;
  return true;
}

/**
 * The IPv4 address embedded in an IPv6 address (SPEC-VPN §6: IPv4-mapped, IPv4-compatible, SIIT, NAT64 /96,
 * 6to4), or null. `::` and `::1` are not treated as embedding an IPv4 address.
 */
function embeddedV4(b: Uint8Array): Uint8Array | null {
  if (zeros(b, 0, 15) && (b[15] === 0 || b[15] === 1)) return null; //                ::, ::1
  if (zeros(b, 0, 10) && b[10] === 0xff && b[11] === 0xff) return b.subarray(12); // ::ffff:0:0/96 mapped
  if (zeros(b, 0, 12)) return b.subarray(12); //                                    ::/96 IPv4-compatible
  if (zeros(b, 0, 8) && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) {
    return b.subarray(12); //                                                       ::ffff:0:0:0/96 IPv4-translated (SIIT)
  }
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zeros(b, 4, 12)) return b.subarray(12); // 64:ff9b::/96 NAT64
  if (b[0] === 0x20 && b[1] === 0x02) return b.subarray(2, 6); //                 2002::/16 6to4
  return null;
}

function classifyV6(b: Uint8Array): Exclude<IpClass, "invalid"> {
  if (zeros(b, 0, 16)) return "unspecified"; //                                    ::
  if (zeros(b, 0, 15) && b[15] === 1) return "loopback"; //                         ::1
  // ---- IPv4 embedded in IPv6: classified by the embedded IPv4 address ----
  const v4 = embeddedV4(b);
  if (v4) return classifyV4(v4);
  // rest of 64:ff9b::/32 incl. 64:ff9b:1::/48 local-use NAT64 (RFC 8215)
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return "reserved";
  // ---- IPv6 special ranges ----
  if (b[0] === 0xff) return "multicast"; //                                         ff00::/8
  if ((b[0]! & 0xfe) === 0xfc) return "private"; //                                fc00::/7
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return "link-local"; //            fe80::/10
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return "reserved"; // 2001:db8::/32
  if (b[0] === 0x01 && b[1] === 0x00 && zeros(b, 2, 8)) return "reserved"; //       100::/64 discard-only
  // Fail closed beyond the SPEC table: "public" means global unicast (2000::/3) only. Everything else
  // (deprecated site-local fec0::/10, unassigned space, …) is not routable on the internet and is "reserved",
  // as are the special-purpose blocks inside 2000::/3 that are not globally reachable or embed an IPv4 address
  // in an obfuscated form: 2001::/23 (IETF protocol assignments, incl. Teredo 2001::/32) and 3fff::/20 (docs).
  if ((b[0]! & 0xe0) !== 0x20) return "reserved";
  if (b[0] === 0x20 && b[1] === 0x01 && (b[2]! & 0xfe) === 0x00) return "reserved"; // 2001::/23
  if (b[0] === 0x3f && b[1] === 0xff && (b[2]! & 0xf0) === 0x00) return "reserved"; // 3fff::/20
  return "public";
}

/** Classifies a strict IP literal (SPEC-VPN §6). Anything that is not a strict literal is `invalid`. */
export function classifyIp(ip: string): IpClass {
  const v4 = parseIpv4(ip);
  if (v4 !== null) return classifyV4(v4);
  const v6 = parseIpv6(ip);
  if (v6 !== null) return classifyV6(v6);
  return "invalid";
}

/**
 * The address a connection to `ip` actually reaches, in one canonical text form, so that two spellings of the
 * same host compare equal: IPv4 and every IPv6 form embedding an IPv4 address (as {@link classifyIp} treats
 * them) → dotted quad; other IPv6 → RFC 5952; anything else → null. Used for exit-side denylists.
 */
export function egressIdentity(ip: string): string | null {
  const v4 = parseIpv4(ip);
  if (v4 !== null) return formatIpv4(v4);
  const v6 = parseIpv6(ip);
  if (v6 === null) return null;
  const e = embeddedV4(v6);
  return e ? formatIpv4(e) : formatIpv6(v6);
}

/** Strict shape check of the compose `policy.egress` object (booleans, `deny_private` MUST be true). */
export function isEgressPolicy(p: unknown): p is EgressPolicy {
  return isPlainObject(p) && typeof p.allow_loopback === "boolean" && p.deny_private === true;
}

/**
 * True iff `ip` is `public`, or `loopback` and `policy.allow_loopback`. Everything else — including invalid
 * input and a malformed policy (or one with `deny_private` not `true`) — is denied. Never throws.
 */
export function egressAllowed(ip: string, policy: EgressPolicy): boolean {
  if (!isEgressPolicy(policy)) return false;
  const cls = classifyIp(ip);
  return cls === "public" || (cls === "loopback" && policy.allow_loopback === true);
}

/** True for a valid DNS name per SPEC-VPN §6 (ASCII LDH labels, last label not all-digits). */
export function isDnsName(host: unknown): host is string {
  if (typeof host !== "string" || host.length === 0 || host.length > MAX_DNS_NAME_LEN) return false;
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  if (name.length === 0) return false;
  const labels = name.split(".");
  for (const l of labels) if (!LABEL_RE.test(l)) return false;
  return !ALL_DIGITS_RE.test(labels[labels.length - 1]!);
}

/** True for a TCP port 1..65535 (an integer number). */
export function isPort(port: unknown): port is number {
  return typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * `host` is a strict IPv4 dotted-quad, an IPv6 literal (no brackets/zone) or a DNS name (SPEC-VPN §6);
 * `port` is an integer 1..65535.
 * @throws PlrError E_BAD_INPUT (content-free message)
 */
export function validateDestination(host: string, port: number): void {
  if (!isPort(port)) throw new PlrError("E_BAD_INPUT", "bad destination port");
  if (parseIpv4(host) !== null || parseIpv6(host) !== null || isDnsName(host)) return;
  throw new PlrError("E_BAD_INPUT", "bad destination host");
}
