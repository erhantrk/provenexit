/**
 * Strict IP literal parsing and formatting. Implemented by hand on purpose: no leniency (no octal/hex/short
 * IPv4 forms, no leading zeros, no zone ids, no brackets, no whitespace), independent of `node:net`.
 */

/** Longest textual IPv6 form: `ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`. */
export const MAX_IPV6_TEXT_LEN = 45;
const MAX_IPV4_TEXT_LEN = 15;

/** One decimal octet 0..255, no leading zeros. */
const OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
const IPV4_RE = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);
const HEXTET_RE = /^[0-9a-fA-F]{1,4}$/;

/** Parses a strict dotted-quad IPv4 literal (4 decimal octets, no leading zeros). Returns null if invalid. */
export function parseIpv4(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || s.length > MAX_IPV4_TEXT_LEN || !IPV4_RE.test(s)) return null;
  const out = new Uint8Array(4);
  const parts = s.split(".");
  for (let i = 0; i < 4; i++) out[i] = Number(parts[i]);
  return out;
}

/**
 * Parses a strict RFC 4291 §2.2 IPv6 literal (no brackets, no zone id). Hex is case-insensitive; groups have
 * 1..4 hex digits; at most one `::`, which stands for ≥ 1 zero group; an optional trailing strict dotted-quad
 * IPv4 counts as two groups. Returns 16 bytes or null.
 */
export function parseIpv6(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || s.length < 2 || s.length > MAX_IPV6_TEXT_LEN) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string, allowV4Tail: boolean): number[] | null => {
    if (side === "") return [];
    const parts = side.split(":");
    const words: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i]!;
      if (allowV4Tail && i === parts.length - 1 && p.includes(".")) {
        const v4 = parseIpv4(p);
        if (v4 === null) return null;
        words.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
      } else {
        if (!HEXTET_RE.test(p)) return null; // also rejects "" (leading/trailing single ':')
        words.push(Number.parseInt(p, 16));
      }
    }
    return words;
  };
  let words: number[];
  if (halves.length === 1) {
    const all = parseSide(halves[0]!, true);
    if (all === null || all.length !== 8 || halves[0] === "") return null;
    words = all;
  } else {
    const head = parseSide(halves[0]!, false);
    const tail = parseSide(halves[1]!, true);
    if (head === null || tail === null) return null;
    const zeros = 8 - head.length - tail.length;
    if (zeros < 1) return null;
    words = [...head, ...new Array<number>(zeros).fill(0), ...tail];
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[2 * i] = words[i]! >> 8;
    out[2 * i + 1] = words[i]! & 0xff;
  }
  return out;
}

/** True if `s` is a strict IPv4 or IPv6 literal. */
export function isIpLiteral(s: unknown): s is string {
  return parseIpv4(s) !== null || parseIpv6(s) !== null;
}

export function formatIpv4(b: Uint8Array): string {
  if (!(b instanceof Uint8Array) || b.length !== 4) throw new TypeError("IPv4 address must be 4 bytes");
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

/**
 * RFC 5952 canonical text form: lowercase, no leading zeros, the longest run (≥ 2) of zero groups compressed
 * to `::` (the first one on a tie), and IPv4-mapped addresses (`::ffff:0:0/96`) in mixed notation (§5).
 */
export function formatIpv6(b: Uint8Array): string {
  if (!(b instanceof Uint8Array) || b.length !== 16) throw new TypeError("IPv6 address must be 16 bytes");
  let mappedPrefix = true;
  for (let i = 0; i < 10; i++) if (b[i] !== 0) mappedPrefix = false;
  if (mappedPrefix && b[10] === 0xff && b[11] === 0xff) return `::ffff:${formatIpv4(b.subarray(12, 16))}`;

  const words: number[] = [];
  for (let i = 0; i < 8; i++) words.push((b[2 * i]! << 8) | b[2 * i + 1]!);
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hexes = words.map((w) => w.toString(16));
  if (bestLen < 2) return hexes.join(":");
  return `${hexes.slice(0, bestStart).join(":")}::${hexes.slice(bestStart + bestLen).join(":")}`;
}
