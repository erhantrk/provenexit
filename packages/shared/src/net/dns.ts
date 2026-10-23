/**
 * DNS-over-HTTPS message codec (SPEC-VPN §6.1, RFC 8484 / RFC 1035, EDNS0 padding RFC 8467) and the RFC 6761
 * localhost rule (SPEC-VPN §6). Pure functions, no I/O.
 *
 * `parseDnsResponse` parses attacker-controlled bytes (a resolver or anything on its path): every read is
 * bounds-checked, every loop is bounded by the message length or a small constant, compression pointers must
 * point strictly backwards (so no cycles), and every failure is the content-free `E_DNS` — no name, address or
 * byte of the message ever appears in an error.
 */
import { PlrError } from "../errors.js";
import { isBytes } from "../bytes.js";
import { formatIpv4, formatIpv6, isIpLiteral } from "./ip.js";
import { isDnsName } from "./egress.js";

export const DNS = Object.freeze({
  /** RFC 8484 media type for both `content-type` and `accept`. */
  CONTENT_TYPE: "application/dns-message",
  QTYPE_A: 1,
  QTYPE_CNAME: 5,
  QTYPE_AAAA: 28,
  QTYPE_OPT: 41,
  CLASS_IN: 1,
  /** EDNS0 advertised UDP payload size. */
  EDNS_UDP_SIZE: 4096,
  /** EDNS0 option code: Padding (RFC 7830). */
  OPT_PADDING: 12,
  /** queries are padded to a multiple of this (RFC 8467 §4.1, "block-length padding"). */
  PAD_BLOCK: 128,
  /** SPEC-VPN §6.1 parse limits */
  MAX_ANSWERS: 32,
  MAX_POINTER_HOPS: 16,
  MAX_NAME_WIRE_LEN: 255,
  MAX_LABEL_LEN: 63,
  MAX_CNAME_HOPS: 8,
  /** A DNS message never exceeds 65535 bytes (u16 length over TCP / DoH practice). */
  MAX_MESSAGE_LEN: 65535,
  /** per-resolver timeout (SPEC-VPN §6.1) */
  RESOLVER_TIMEOUT_MS: 5000,
} as const);

export type DnsType = "A" | "AAAA";

const HEADER_LEN = 12;
const FLAG_QR = 0x8000;
const FLAG_TC = 0x0200;
const RCODE_NOERROR = 0;
const RCODE_NXDOMAIN = 3;

function dnsFail(detail: string): never {
  throw new PlrError("E_DNS", detail);
}

function qtypeOf(type: unknown): number {
  if (type === "A") return DNS.QTYPE_A;
  if (type === "AAAA") return DNS.QTYPE_AAAA;
  throw new PlrError("E_BAD_INPUT", "bad dns query type");
}

/** ASCII-only lowercase of one byte (DNS case-insensitivity is ASCII-only, RFC 4343). */
function lowerByte(c: number): number {
  return c >= 0x41 && c <= 0x5a ? c + 0x20 : c;
}

/**
 * Lowercased labels of a §6 DNS name (not an IP literal), without the optional trailing dot.
 * @throws PlrError E_BAD_INPUT
 */
function nameLabels(name: unknown): string[] {
  if (isIpLiteral(name) || !isDnsName(name)) throw new PlrError("E_BAD_INPUT", "bad dns name");
  const n = name.endsWith(".") ? name.slice(0, -1) : name;
  // isDnsName guarantees ASCII LDH labels, so this lowercasing is ASCII-only.
  return n.toLowerCase().split(".");
}

/**
 * Canonical comparison key of a name: per label `char(len) ‖ lowercase(label)`, so labels containing dots or
 * any other byte can never alias a different label sequence.
 */
function labelsKey(labels: readonly string[]): string {
  let k = "";
  for (const l of labels) k += String.fromCharCode(l.length) + l;
  return k;
}

/**
 * `encodeDnsQuery(name, type)` — SPEC-VPN §6.1 exact bytes: header (id 0, RD, QD 1, AR 1), the question, and an
 * EDNS0 OPT RR whose Padding option makes the whole message a multiple of 128 bytes.
 * @throws PlrError E_BAD_INPUT (not a §6 DNS name, IP literal, or bad type)
 */
export function encodeDnsQuery(name: string, type: DnsType): Uint8Array {
  const qtype = qtypeOf(type);
  const labels = nameLabels(name);
  let qnameLen = 1;
  for (const l of labels) qnameLen += 1 + l.length;
  const base = HEADER_LEN + qnameLen + 4 + 11 + 4; // header, question, OPT RR fixed part, padding option header
  const pad = (DNS.PAD_BLOCK - (base % DNS.PAD_BLOCK)) % DNS.PAD_BLOCK;
  const out = new Uint8Array(base + pad); // padding bytes are zero
  const v = new DataView(out.buffer);
  // header
  v.setUint16(0, 0); //      id
  v.setUint16(2, 0x0100); // RD
  v.setUint16(4, 1); //      QDCOUNT
  v.setUint16(6, 0); //      ANCOUNT
  v.setUint16(8, 0); //      NSCOUNT
  v.setUint16(10, 1); //     ARCOUNT
  let o = HEADER_LEN;
  for (const l of labels) {
    out[o++] = l.length;
    for (let i = 0; i < l.length; i++) out[o++] = l.charCodeAt(i);
  }
  out[o++] = 0;
  v.setUint16(o, qtype); o += 2;
  v.setUint16(o, DNS.CLASS_IN); o += 2;
  // OPT RR: root name, TYPE 41, CLASS = UDP size, TTL 0, RDLEN, then the Padding option
  out[o++] = 0;
  v.setUint16(o, DNS.QTYPE_OPT); o += 2;
  v.setUint16(o, DNS.EDNS_UDP_SIZE); o += 2;
  v.setUint32(o, 0); o += 4;
  v.setUint16(o, 4 + pad); o += 2;
  v.setUint16(o, DNS.OPT_PADDING); o += 2;
  v.setUint16(o, pad); o += 2;
  if (o + pad !== out.length || out.length % DNS.PAD_BLOCK !== 0) throw new PlrError("E_BAD_INPUT", "dns query layout");
  return out;
}

interface DecodedName {
  /** {@link labelsKey} form, lowercased */
  key: string;
  /** offset right after the name at its original position (after the first pointer, if any) */
  end: number;
}

/**
 * Decodes a (possibly compressed) name at `start`. Pointers must point strictly backwards and not into the
 * header, ≤ 16 pointer hops, labels ≤ 63 (the 0x40 / 0x80 label types are rejected), total wire length ≤ 255.
 */
function readName(m: Uint8Array, start: number): DecodedName {
  let pos = start;
  let end = -1;
  let hops = 0;
  let wireLen = 0;
  let key = "";
  for (;;) {
    if (pos >= m.length) dnsFail("name overruns the message");
    const len = m[pos]!;
    const kind = len & 0xc0;
    if (kind === 0xc0) {
      if (pos + 1 >= m.length) dnsFail("pointer overruns the message");
      const target = ((len & 0x3f) << 8) | m[pos + 1]!;
      if (target >= pos || target < HEADER_LEN) dnsFail("bad compression pointer");
      if (++hops > DNS.MAX_POINTER_HOPS) dnsFail("too many compression pointers");
      if (end < 0) end = pos + 2;
      pos = target;
      continue;
    }
    if (kind !== 0) dnsFail("bad label type");
    wireLen += 1 + len;
    if (wireLen > DNS.MAX_NAME_WIRE_LEN) dnsFail("name too long");
    if (len === 0) {
      if (end < 0) end = pos + 1;
      return { key, end };
    }
    if (pos + 1 + len > m.length) dnsFail("label overruns the message");
    key += String.fromCharCode(len);
    for (let i = pos + 1; i <= pos + len; i++) key += String.fromCharCode(lowerByte(m[i]!));
    pos += 1 + len;
  }
}

interface Rr {
  owner: string;
  type: number;
  cls: number;
  ttl: number;
  rdStart: number;
  rdEnd: number;
}

function u16at(m: Uint8Array, o: number): number {
  return (m[o]! << 8) | m[o + 1]!;
}

function readRr(m: Uint8Array, start: number): Rr {
  const name = readName(m, start);
  const o = name.end;
  if (o + 10 > m.length) dnsFail("rr overruns the message");
  const rdLen = u16at(m, o + 8);
  const rdStart = o + 10;
  const rdEnd = rdStart + rdLen;
  if (rdEnd > m.length) dnsFail("rdata overruns the message");
  const ttl = ((m[o + 4]! << 24) | (m[o + 5]! << 16) | (m[o + 6]! << 8) | m[o + 7]!) >>> 0;
  return { owner: name.key, type: u16at(m, o), cls: u16at(m, o + 2), ttl, rdStart, rdEnd };
}

/**
 * `parseDnsResponse(bytes, name, type)` (SPEC-VPN §6.1) → the addresses of the requested type owned by the
 * question name or a name on its CNAME chain (≤ 8 hops), in message order without duplicates: IPv4 dotted quad,
 * IPv6 RFC 5952. NXDOMAIN ⇒ `[]`.
 * @throws PlrError E_DNS (any malformed / mismatching / failed response), E_BAD_INPUT (bad `name` / `type`)
 */
export function parseDnsResponse(b: Uint8Array, name: string, type: DnsType): string[] {
  const qtype = qtypeOf(type);
  const qkey = labelsKey(nameLabels(name));
  if (!isBytes(b) || b.length < HEADER_LEN || b.length > DNS.MAX_MESSAGE_LEN) dnsFail("bad message length");
  const m = b;

  // ---- header
  const flags = u16at(m, 2);
  if (u16at(m, 0) !== 0) dnsFail("bad id");
  if ((flags & FLAG_QR) === 0) dnsFail("not a response");
  if (((flags >> 11) & 0x0f) !== 0) dnsFail("bad opcode");
  if ((flags & FLAG_TC) !== 0) dnsFail("truncated");
  const rcode = flags & 0x0f;
  const qd = u16at(m, 4), an = u16at(m, 6), ns = u16at(m, 8), ar = u16at(m, 10);
  if (qd !== 1) dnsFail("bad question count");
  if (an > DNS.MAX_ANSWERS) dnsFail("too many answers");

  // ---- question: must equal (name, type, IN)
  const q = readName(m, HEADER_LEN);
  if (q.end + 4 > m.length) dnsFail("question overruns the message");
  if (q.key !== qkey || u16at(m, q.end) !== qtype || u16at(m, q.end + 2) !== DNS.CLASS_IN) dnsFail("question mismatch");
  if (rcode !== RCODE_NOERROR && rcode !== RCODE_NXDOMAIN) dnsFail("resolver error");

  // ---- every counted RR must decode and fit; each RR takes ≥ 11 bytes, so this loop is bounded by the length
  let off = q.end + 4;
  const answers: Rr[] = [];
  let optSeen = false;
  const total = an + ns + ar;
  for (let i = 0; i < total; i++) {
    const rr = readRr(m, off);
    off = rr.rdEnd;
    if (i < an) {
      answers.push(rr);
    } else if (i >= an + ns && rr.type === DNS.QTYPE_OPT) {
      // EDNS0 (RFC 6891): a single OPT RR; a non-zero extended RCODE is an error we must not ignore.
      if (optSeen || rr.owner !== "") dnsFail("bad opt record");
      optSeen = true;
      if ((rr.ttl >>> 24) !== 0) dnsFail("resolver error");
    }
  }
  if (rcode === RCODE_NXDOMAIN) return [];

  // ---- CNAME chain from the question name (class IN only)
  const cnames: Array<{ owner: string; target: string }> = [];
  for (const rr of answers) {
    if (rr.type !== DNS.QTYPE_CNAME || rr.cls !== DNS.CLASS_IN) continue;
    const t = readName(m, rr.rdStart);
    if (t.end !== rr.rdEnd) dnsFail("bad cname rdata");
    cnames.push({ owner: rr.owner, target: t.key });
  }
  const chain = new Set<string>([qkey]);
  let cur = qkey;
  for (let hop = 0; hop < DNS.MAX_CNAME_HOPS; hop++) {
    let next: string | null = null;
    for (const c of cnames) {
      if (c.owner !== cur) continue;
      if (next !== null && next !== c.target) dnsFail("conflicting cname records");
      next = c.target;
    }
    if (next === null || chain.has(next)) break;
    chain.add(next);
    cur = next;
  }

  // ---- addresses of the requested type owned by a name in the chain
  const wantLen = qtype === DNS.QTYPE_A ? 4 : 16;
  const out: string[] = [];
  for (const rr of answers) {
    if (rr.type !== qtype || rr.cls !== DNS.CLASS_IN) continue;
    if (rr.rdEnd - rr.rdStart !== wantLen) dnsFail("bad address length");
    if (!chain.has(rr.owner)) continue;
    const raw = m.subarray(rr.rdStart, rr.rdEnd);
    const ip = wantLen === 4 ? formatIpv4(raw) : formatIpv6(raw);
    if (!out.includes(ip)) out.push(ip);
  }
  return out;
}

/**
 * RFC 6761 special-use names `localhost` and `*.localhost` (ASCII case-insensitive, optional single trailing
 * dot). The exit refuses them with E_EGRESS_DENIED before any resolution (SPEC-VPN §6). Never throws.
 */
export function isLocalhostName(host: string): boolean {
  // No length cap on purpose: refusing more is the safe direction (destinations are length-validated anyway).
  if (typeof host !== "string" || host.length === 0) return false;
  let n = host.endsWith(".") ? host.slice(0, -1) : host;
  n = n.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0x20));
  return n === "localhost" || n.endsWith(".localhost");
}
