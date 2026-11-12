/**
 * Strict validation of query parameters at the exit's HTTP boundary (SPEC §6.4). Errors carry only a code; no input
 * content is ever copied into an error.
 */
import { PlrError } from "@plr/shared";

const U64_DEC_RE = /^(?:0|[1-9][0-9]{0,15})$/;

/** Strict decimal non-negative safe integer (no sign, no leading zeros, no exponent). */
export function parseUintParam(s: string | null): number {
  if (s === null || !U64_DEC_RE.test(s)) throw new PlrError("E_BAD_REQUEST");
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new PlrError("E_BAD_REQUEST");
  return n;
}
