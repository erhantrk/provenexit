/** Small shared helpers. */

/** True for a plain JSON object (not null, not an array, prototype Object or null). */
export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** True for a string without lone UTF-16 surrogates (losslessly UTF-8 encodable). */
export function isWellFormed(s: string): boolean {
  return !LONE_SURROGATE_RE.test(s);
}

/** Resolves/rejects like `p`, but rejects as soon as `signal` aborts (even if `p` ignores the signal). */
export function raceAbort<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error("aborted"));
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(e instanceof Error ? e : new Error("failed"));
      },
    );
  });
}
