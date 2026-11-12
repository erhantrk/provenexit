/** Small helpers for replies from the (untrusted) exit: strict JSON parsing and fail-closed errors. */
import { PlrError, parseJsonIntegers, type PlrErrorCode } from "@plr/shared";

/**
 * Parses UTF-8 JSON strictly (fatal decoding; non-integer number literals such as `3.0` / `3e0` become NaN so
 * they can never pass as integers — same acceptance as the Rust contract). Returns `undefined` on any failure.
 */
export function parseJsonBytes(b: Uint8Array): unknown {
  try {
    return parseJsonIntegers(new TextDecoder("utf-8", { fatal: true }).decode(b));
  } catch {
    return undefined;
  }
}

/** Throws PlrError(code) — tiny helper for expression positions. */
export function fail(code: PlrErrorCode, detail?: string): never {
  throw new PlrError(code, detail);
}
