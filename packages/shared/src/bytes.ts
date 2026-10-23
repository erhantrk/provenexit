import { bytesToHex } from "@noble/hashes/utils.js";
import { PlrError, type PlrErrorCode } from "./errors.js";

const HEX_RE = /^(?:[0-9a-f]{2})*$/;

export function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array;
}

/** Lowercase hex, no prefix. */
export function toHex(b: Uint8Array): string {
  if (!isBytes(b)) throw new PlrError("E_BAD_INPUT", "toHex expects bytes");
  return bytesToHex(b);
}

/**
 * Strict hex decoder: lowercase only, no `0x`, even length (SPEC notation).
 * @param expectedLen if given, the exact number of decoded bytes required.
 * @throws PlrError E_BAD_HEX
 */
export function fromHex(h: string, expectedLen?: number): Uint8Array {
  if (typeof h !== "string") throw new PlrError("E_BAD_HEX", "not a string");
  if (expectedLen !== undefined) {
    if (!Number.isSafeInteger(expectedLen) || expectedLen < 0) throw new PlrError("E_BAD_INPUT", "bad expected length");
    if (h.length !== expectedLen * 2) throw new PlrError("E_BAD_HEX", "wrong length");
  }
  if (!HEX_RE.test(h)) throw new PlrError("E_BAD_HEX", "not lowercase even-length hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** True if `h` is strict lowercase hex (optionally of exactly `byteLen` bytes). Never throws. */
export function isHex(h: unknown, byteLen?: number): h is string {
  if (typeof h !== "string") return false;
  if (byteLen !== undefined && h.length !== byteLen * 2) return false;
  return HEX_RE.test(h);
}

export function concatBytes(...a: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const x of a) {
    if (!isBytes(x)) throw new PlrError("E_BAD_INPUT", "concatBytes expects bytes");
    n += x.length;
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}

/** Constant-time (length-public) byte equality. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (!isBytes(a) || !isBytes(b) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Constant-time check that every byte is zero. */
export function isAllZero(a: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i]!;
  return acc === 0;
}

const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** True for a string without lone UTF-16 surrogates (i.e. losslessly UTF-8 encodable). */
export function isWellFormedString(s: unknown): s is string {
  return typeof s === "string" && !LONE_SURROGATE_RE.test(s);
}

/**
 * UTF-8 encode. Rejects strings with lone surrogates (they would silently become U+FFFD, so two different
 * strings could map to the same bytes).
 */
export function utf8(s: string): Uint8Array {
  if (!isWellFormedString(s)) throw new PlrError("E_BAD_INPUT", "not a well-formed string");
  return new TextEncoder().encode(s);
}

export function u8(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff);
}

export function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

const U64_MAX = (1n << 64n) - 1n;

export function u64be(n: bigint | number): Uint8Array {
  const v = typeof n === "bigint" ? n : Number.isSafeInteger(n) ? BigInt(n) : -1n;
  if (v < 0n || v > U64_MAX) throw new PlrError("E_BAD_INPUT", "u64 out of range");
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, false);
  return b;
}

/** Throws PlrError(code) unless `b` is a Uint8Array of exactly `len` bytes. Returns `b`. */
export function requireBytes(b: unknown, len: number, code: PlrErrorCode = "E_BAD_INPUT", what = "bytes"): Uint8Array {
  if (!isBytes(b) || b.length !== len) throw new PlrError(code, `${what} must be ${len} bytes`);
  return b;
}

/** True for a non-negative safe integer. */
export function isUint(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/** True for a plain (non-array, non-null) object. */
export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** `utf8("PLR-v1")` — the protocol domain separator (SPEC header). */
export const DOMAIN: Uint8Array = utf8("PLR-v1");
