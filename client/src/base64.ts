/** Strict, canonical standard base64 (RFC 4648 §4, padded). */

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function base64Encode(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64");
}

/**
 * Decodes canonical padded base64. Returns `null` for anything else: wrong alphabet, missing or extra
 * padding, whitespace, or non-zero trailing bits (so each byte string has exactly one accepted encoding).
 */
export function base64DecodeStrict(s: unknown, maxBytes: number): Uint8Array | null {
  if (typeof s !== "string" || s.length > Math.ceil(maxBytes / 3) * 4 || !B64_RE.test(s)) return null;
  const buf = Buffer.from(s, "base64");
  if (buf.toString("base64") !== s) return null;
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}
