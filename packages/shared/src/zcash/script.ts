/** Zcash transparent scripts, hash160, Base58Check t-addresses, ZIP-317 fees. Pure; never does I/O. */
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { PlrError } from "../errors.js";
import { concatBytes, equalBytes, isBytes, isHex, fromHex } from "../bytes.js";
import { compactSize } from "./tx.js";

const bad = (d: string): never => {
  throw new PlrError("E_BAD_INPUT", d);
};

export type ZcashNetwork = "regtest" | "testnet" | "mainnet";
export const ZCASH_NETWORKS: readonly ZcashNetwork[] = Object.freeze(["regtest", "testnet", "mainnet"]);
export function isZcashNetwork(v: unknown): v is ZcashNetwork {
  return v === "regtest" || v === "testnet" || v === "mainnet";
}

export const OP = Object.freeze({ RETURN: 0x6a, PUSHDATA1: 0x4c, DUP: 0x76, HASH160: 0xa9, EQUALVERIFY: 0x88, CHECKSIG: 0xac } as const);
/** Max OP_RETURN data accepted by standard mempools (`max_datacarrier_bytes = 83` ⇒ 80-byte payload). */
export const MAX_OP_RETURN_DATA = 80;

/** `RIPEMD160(SHA256(b))` */
export function hash160(b: Uint8Array): Uint8Array {
  if (!isBytes(b)) return bad("hash160 expects bytes");
  return ripemd160(sha256(b));
}

/** `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` */
export function p2pkhScript(h160: Uint8Array): Uint8Array {
  if (!isBytes(h160) || h160.length !== 20) return bad("hash160 must be 20 bytes");
  return concatBytes(Uint8Array.of(OP.DUP, OP.HASH160, 20), h160, Uint8Array.of(OP.EQUALVERIFY, OP.CHECKSIG));
}

/** The 20-byte hash of a P2PKH script, else null. Never throws. */
export function p2pkhHash(script: Uint8Array): Uint8Array | null {
  if (!isBytes(script) || script.length !== 25) return null;
  if (script[0] !== OP.DUP || script[1] !== OP.HASH160 || script[2] !== 20 || script[23] !== OP.EQUALVERIFY || script[24] !== OP.CHECKSIG) return null;
  return script.slice(3, 23);
}

/** Minimal single push of `data` (direct push ≤ 75 bytes, else OP_PUSHDATA1 ≤ 255). */
export function pushData(data: Uint8Array): Uint8Array {
  if (!isBytes(data)) return bad("push expects bytes");
  if (data.length <= 75) return concatBytes(Uint8Array.of(data.length), data);
  if (data.length <= 255) return concatBytes(Uint8Array.of(OP.PUSHDATA1, data.length), data);
  return bad("push too large");
}

/** `OP_RETURN <data>`, data ≤ 80 bytes. @throws PlrError E_BAD_INPUT */
export function opReturnScript(data: Uint8Array): Uint8Array {
  if (!isBytes(data) || data.length > MAX_OP_RETURN_DATA) return bad("OP_RETURN data must be ≤ 80 bytes");
  return concatBytes(Uint8Array.of(OP.RETURN), pushData(data));
}

/**
 * Splits a script that consists only of data pushes (direct pushes 0x01..0x4b and OP_PUSHDATA1) into the pushed
 * byte strings. Any other opcode or a truncated push ⇒ null. Never throws.
 */
export function parsePushes(script: Uint8Array): Uint8Array[] | null {
  if (!isBytes(script)) return null;
  const out: Uint8Array[] = [];
  let o = 0;
  while (o < script.length) {
    const op = script[o++]!;
    let n: number;
    if (op >= 0x01 && op <= 0x4b) n = op;
    else if (op === OP.PUSHDATA1) {
      if (o >= script.length) return null;
      n = script[o++]!;
    } else return null;
    if (o + n > script.length) return null;
    out.push(script.slice(o, o + n));
    o += n;
  }
  return out;
}

/** The data of `OP_RETURN <single push>` (the whole remainder must be exactly one push), else null. Never throws. */
export function opReturnData(script: Uint8Array): Uint8Array | null {
  if (!isBytes(script) || script.length < 1 || script[0] !== OP.RETURN) return null;
  const pushes = parsePushes(script.subarray(1));
  return pushes !== null && pushes.length === 1 ? pushes[0]! : null;
}

// ---------------------------------------------------------------- Base58Check

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP: ReadonlyMap<string, number> = new Map(Array.from(B58, (c, i) => [c, i] as const));
const MAX_B58_LEN = 128;

const sha256d = (b: Uint8Array): Uint8Array => sha256(sha256(b));

export function base58Encode(b: Uint8Array): string {
  let zeros = 0;
  while (zeros < b.length && b[zeros] === 0) zeros++;
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)]! + s;
    n /= 58n;
  }
  return "1".repeat(zeros) + s;
}

/** Strict Base58 decode; null on any invalid character or excessive length. Never throws. */
export function base58Decode(s: string): Uint8Array | null {
  if (typeof s !== "string" || s.length === 0 || s.length > MAX_B58_LEN) return null;
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  let n = 0n;
  for (const c of s) {
    const v = B58_MAP.get(c);
    if (v === undefined) return null;
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes]);
}

export function base58CheckEncode(payload: Uint8Array): string {
  return base58Encode(concatBytes(payload, sha256d(payload).subarray(0, 4)));
}

/** Payload of a Base58Check string, or null on a bad checksum / encoding. Never throws. */
export function base58CheckDecode(s: string): Uint8Array | null {
  const b = base58Decode(s);
  if (b === null || b.length < 5) return null;
  const payload = b.subarray(0, b.length - 4);
  return equalBytes(sha256d(payload).subarray(0, 4), b.subarray(b.length - 4)) ? payload.slice() : null;
}

/** P2PKH t-address version prefixes. */
export const T_ADDR_PREFIX = Object.freeze({
  mainnet: Uint8Array.of(0x1c, 0xb8),
  test: Uint8Array.of(0x1d, 0x25),
});

/** Base58Check P2PKH t-address (regtest and testnet share the `tm` prefix). @throws PlrError E_BAD_INPUT */
export function tAddress(h160: Uint8Array, network: ZcashNetwork): string {
  if (!isBytes(h160) || h160.length !== 20) return bad("hash160 must be 20 bytes");
  if (!isZcashNetwork(network)) return bad("bad network");
  return base58CheckEncode(concatBytes(network === "mainnet" ? T_ADDR_PREFIX.mainnet : T_ADDR_PREFIX.test, h160));
}

/** Parses a P2PKH t-address. @throws PlrError E_BAD_INPUT (bad checksum, P2SH, unknown prefix) */
export function parseTAddress(a: string): { network: "test" | "mainnet"; hash160: Uint8Array } {
  const p = typeof a === "string" ? base58CheckDecode(a) : null;
  if (p === null || p.length !== 22) return bad("bad t-address");
  const pre = p.subarray(0, 2);
  const network = equalBytes(pre, T_ADDR_PREFIX.mainnet) ? "mainnet" : equalBytes(pre, T_ADDR_PREFIX.test) ? "test" : null;
  if (network === null) return bad("not a P2PKH t-address");
  return { network, hash160: p.slice(2) };
}

/** True if `a` is a P2PKH t-address of `network`. Never throws. */
export function isTAddress(a: unknown, network?: ZcashNetwork): a is string {
  if (typeof a !== "string") return false;
  try {
    const p = parseTAddress(a);
    return network === undefined || p.network === (network === "mainnet" ? "mainnet" : "test");
  } catch {
    return false;
  }
}

/**
 * secp256k1 secret key from 64 hex chars or a WIF string (Base58Check `0x80` mainnet / `0xef` test, optional
 * compressed flag `0x01`). @throws PlrError E_BAD_INPUT
 */
export function parseZcashSecretKey(s: string): Uint8Array {
  if (typeof s !== "string") return bad("bad secret key");
  const t = s.trim();
  if (isHex(t.toLowerCase(), 32)) return fromHex(t.toLowerCase(), 32);
  const p = base58CheckDecode(t);
  if (p === null || (p[0] !== 0x80 && p[0] !== 0xef)) return bad("bad secret key");
  if (p.length === 34 && p[33] === 0x01) return p.slice(1, 33);
  if (p.length === 33) return p.slice(1, 33);
  return bad("bad secret key");
}

// ---------------------------------------------------------------- ZIP-317

export const ZIP317 = Object.freeze({ MARGINAL_FEE: 5000n, GRACE_ACTIONS: 2, P2PKH_STANDARD_INPUT_SIZE: 150, P2PKH_STANDARD_OUTPUT_SIZE: 34 } as const);

/**
 * ZIP-317 conventional fee of a transparent-only transaction with `inputs` P2PKH inputs and the given output scripts:
 * `5000 × max(2, max(ceil(inputs·150 / 150), ceil(Σ(8 + compactSize(len) + len) / 34)))`.
 */
export function zip317Fee(p: { inputs: number; outputScripts: Uint8Array[] }): bigint {
  if (typeof p !== "object" || p === null || !Number.isSafeInteger(p.inputs) || p.inputs < 0 || !Array.isArray(p.outputScripts)) return bad("bad fee params");
  let outSize = 0;
  for (const s of p.outputScripts) {
    if (!isBytes(s)) return bad("bad output script");
    outSize += 8 + compactSize(s.length).length + s.length;
  }
  const inSize = p.inputs * ZIP317.P2PKH_STANDARD_INPUT_SIZE;
  const ceilDiv = (a: number, b: number) => Math.ceil(a / b);
  const logical = Math.max(ceilDiv(inSize, ZIP317.P2PKH_STANDARD_INPUT_SIZE), ceilDiv(outSize, ZIP317.P2PKH_STANDARD_OUTPUT_SIZE));
  return ZIP317.MARGINAL_FEE * BigInt(Math.max(ZIP317.GRACE_ACTIONS, logical));
}
