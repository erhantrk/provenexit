/** Small HTTP helpers for talking to the (untrusted) router: bounded body reads and error-code mapping. */
import { PlrError, parseJsonIntegers, type PlrErrorCode } from "@plr/shared";

/** Thrown internally when a body exceeds its size limit. */
export class BodyTooLargeError extends Error {
  constructor() {
    super("body too large");
    this.name = "BodyTooLargeError";
  }
}

/** Reads a fetch `Response` body fully, refusing more than `maxBytes`. Cancels the stream on overflow. */
export async function readBodyLimited(res: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = res.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw new BodyTooLargeError();
  }
  if (res.body === null) return new Uint8Array(0);
  const reader = res.body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new BodyTooLargeError();
      parts.push(value);
    }
  } catch (e) {
    await reader.cancel().catch(() => undefined);
    throw e;
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}

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

/** Pre-decrypt router error codes (SPEC §6.3) and the HTTP status each is sent with. */
const ROUTER_ERRORS: ReadonlyMap<string, number> = new Map<PlrErrorCode, number>([
  ["E_BAD_REQUEST", 400],
  ["E_DECRYPT", 400],
  ["E_TOO_LARGE", 413],
  ["E_UPSTREAM", 503],
]);

const MAX_ERROR_BODY = 4 * 1024;

/**
 * Maps a non-200 router reply to a PlrError code. The body is unauthenticated, so it is only trusted when
 * it names one of the §6.3 codes with its matching status; otherwise the status alone decides.
 */
export async function routerErrorCode(res: Response): Promise<PlrErrorCode> {
  let bodyCode: unknown;
  try {
    const j = parseJsonBytes(await readBodyLimited(res, MAX_ERROR_BODY));
    if (typeof j === "object" && j !== null && !Array.isArray(j)) bodyCode = (j as Record<string, unknown>).error;
  } catch {
    bodyCode = undefined;
  }
  if (typeof bodyCode === "string" && ROUTER_ERRORS.get(bodyCode) === res.status) return bodyCode as PlrErrorCode;
  switch (res.status) {
    case 400:
      return "E_BAD_REQUEST";
    case 413:
      return "E_TOO_LARGE";
    case 502:
    case 503:
    case 504:
      return "E_UPSTREAM";
    default:
      return "E_BAD_RESPONSE";
  }
}

/** An AbortController that fires after `ms` and can be re-armed (idle timeouts) or cleared. */
export class Deadline {
  readonly controller = new AbortController();
  #timer: NodeJS.Timeout | undefined;
  readonly #unlink: (() => void) | undefined;

  constructor(
    readonly ms: number,
    parent?: AbortSignal,
  ) {
    this.arm();
    if (parent !== undefined) {
      if (parent.aborted) this.controller.abort();
      const onAbort = (): void => this.controller.abort();
      parent.addEventListener("abort", onAbort, { once: true });
      this.#unlink = () => parent.removeEventListener("abort", onAbort);
    }
  }

  get signal(): AbortSignal {
    return this.controller.signal;
  }

  arm(): void {
    clearTimeout(this.#timer);
    this.#timer = setTimeout(() => this.controller.abort(), this.ms);
    this.#timer.unref?.();
  }

  clear(): void {
    clearTimeout(this.#timer);
    this.#unlink?.();
  }
}

/** Throws PlrError(code) — tiny helper for expression positions. */
export function fail(code: PlrErrorCode, detail?: string): never {
  throw new PlrError(code, detail);
}
