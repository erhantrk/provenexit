/**
 * JSON parsing that never lets a non-integer number literal pass as an integer.
 *
 * `JSON.parse` maps `3`, `3.0`, `3e0` and `0.3e1` to the same value, so a TypeScript verifier would accept
 * event logs (or other integer fields) that the Rust contract (serde_json, `as_u64`) rejects. This parser
 * keeps every integer literal (`0`, `-?[1-9][0-9]*` within the safe-integer range) and turns every other
 * number literal (fraction, exponent, `-0`, unsafe magnitude) into `NaN`, which fails every integer / equality
 * check downstream — e.g. `imr: 3.0` is rejected by `verifyEventLog` with `E_EVENT_LOG`, exactly like Rust.
 *
 * Requires JSON.parse source-text access (V8 ≥ 11.4, Node ≥ 21); fails closed if it is unavailable.
 */
const INT_LITERAL_RE = /^(?:0|-?[1-9]\d*)$/;

interface ReviverContext {
  source?: unknown;
}

/** Replaces any number whose source literal is not a canonical safe integer with `NaN`. */
function integerOnlyReviver(this: unknown, _key: string, value: unknown, context?: ReviverContext): unknown {
  if (typeof value !== "number") return value;
  const src = context?.source;
  if (typeof src !== "string") return Number.NaN; // no source-text access: fail closed
  return INT_LITERAL_RE.test(src) && Number.isSafeInteger(value) ? value : Number.NaN;
}

/**
 * `JSON.parse(text)` where only canonical integer literals survive as numbers (see module doc).
 * Throws exactly like `JSON.parse` on syntax errors (callers map that to their own content-free code).
 */
export function parseJsonIntegers(text: string): unknown {
  return JSON.parse(text, integerOnlyReviver as (this: unknown, key: string, value: unknown) => unknown) as unknown;
}
