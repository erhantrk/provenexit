/**
 * Content-free logging. Every line is built from a fixed tag plus fields whose values are restricted to
 * numbers, error codes and lowercase hex identifiers (public keys / hashes): no free-form strings can reach
 * stdout, so request or response content cannot be logged by accident.
 */
import { isPlrError } from "@plr/shared";

type Field = number | boolean | Code | Hex | Route | UrlField;
declare const brand: unique symbol;
type Branded<T, B extends string> = T & { readonly [brand]: B };
export type Code = Branded<string, "code">;
export type Hex = Branded<string, "hex">;
export type Route = Branded<string, "route">;
export type UrlField = Branded<string, "url">;

const CODE_RE = /^E_[A-Z0-9_]{1,48}$/;
const HEX_RE = /^[0-9a-f]{1,128}$/;
const ROUTES = new Set(["/v1/attestation", "/v1/private/chat", "/v1/receipts/proof", "/healthz", "other"]);
const URL_RE = /^http:\/\/(?:127\.0\.0\.1|\[::1\]|localhost|0\.0\.0\.0|[0-9.]{7,15}):[0-9]{1,5}$/;

/** An error code; anything that is not shaped like one is replaced by `E_INTERNAL`. */
export function code(c: string): Code {
  return (CODE_RE.test(c) ? c : "E_INTERNAL") as Code;
}
export function hex(h: string): Hex {
  return (HEX_RE.test(h) ? h : "invalid") as Hex;
}
export function route(r: string): Route {
  return (ROUTES.has(r) ? r : "other") as Route;
}
export function url(u: string): UrlField {
  return (URL_RE.test(u) ? u : "invalid") as UrlField;
}

/** The code of a PlrError, or a code extracted from an error message (e.g. a contract panic), else fallback. */
export function codeOf(e: unknown, fallback = "E_INTERNAL"): Code {
  if (isPlrError(e)) return code(e.code);
  const m = e instanceof Error && typeof e.message === "string" ? /\bE_[A-Z0-9_]{2,48}\b/.exec(e.message) : null;
  return code(m ? m[0] : fallback);
}

export type Sink = (line: string) => void;

const stdoutSink: Sink = (line) => {
  process.stdout.write(line + "\n");
};

export class Logger {
  readonly #tag: string;
  readonly #sink: Sink;
  constructor(tag: "plr-router" | "plr-host", sink: Sink = stdoutSink) {
    this.#tag = tag;
    this.#sink = sink;
  }

  /** `event` is a fixed identifier chosen by the caller's code, never data. */
  info(event: Lowercase<string>, fields: Record<string, Field> = {}): void {
    if (!/^[a-z][a-z0-9_.-]{0,47}$/.test(event)) event = "event";
    const parts = [this.#tag + ":", event];
    for (const [k, v] of Object.entries(fields)) {
      if (!/^[a-z][a-z0-9_]{0,31}$/.test(k)) continue;
      parts.push(`${k}=${typeof v === "number" ? (Number.isFinite(v) ? String(Math.round(v)) : "nan") : String(v)}`);
    }
    this.#sink(parts.join(" "));
  }
}
