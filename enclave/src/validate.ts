/**
 * Strict validation of everything that crosses the router's HTTP boundary (SPEC §6.3). Errors carry only a
 * code; no input content is ever copied into an error.
 */
import { PlrError, fromHex, isHex } from "@plr/shared";

/** SPEC §6.3: request body ≤ 1 MiB. */
export const MAX_BODY_BYTES = 1024 * 1024;

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Canonical, padded standard base64 → bytes. Rejects whitespace, URL-safe alphabet, non-zero pad bits. */
export function fromBase64Strict(s: unknown): Uint8Array {
  if (typeof s !== "string" || !B64_RE.test(s)) throw new PlrError("E_BAD_REQUEST");
  const buf = Buffer.from(s, "base64");
  if (buf.toString("base64") !== s) throw new PlrError("E_BAD_REQUEST");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function toBase64(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64");
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function hasExactKeys(o: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(o);
  for (const k of required) if (!Object.hasOwn(o, k)) return false;
  return keys.every((k) => required.includes(k) || optional.includes(k));
}

/** JSON.parse that maps every failure (including the input-quoting SyntaxError) to a content-free code. */
export function parseJson(text: string, code: "E_BAD_REQUEST" = "E_BAD_REQUEST"): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new PlrError(code);
  }
}

/** Fatal UTF-8 decoding; invalid sequences are an error rather than U+FFFD. */
export function decodeUtf8(b: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b);
  } catch {
    throw new PlrError("E_BAD_REQUEST");
  }
}

export interface ChatEnvelope {
  attNonce: Uint8Array;
  epk: Uint8Array;
  ct: Uint8Array;
}

/** `{ "v": 1, "att_nonce": "<64 hex>", "epk": "<64 hex>", "ct": "<base64>" }`, nothing else. */
export function parseChatEnvelope(body: Uint8Array): ChatEnvelope {
  const o = parseJson(decodeUtf8(body));
  if (!isPlainObject(o) || !hasExactKeys(o, ["v", "att_nonce", "epk", "ct"])) throw new PlrError("E_BAD_REQUEST");
  if (o.v !== 1 || !isHex(o.att_nonce, 32) || !isHex(o.epk, 32)) throw new PlrError("E_BAD_REQUEST");
  return { attNonce: fromHex(o.att_nonce, 32), epk: fromHex(o.epk, 32), ct: fromBase64Strict(o.ct) };
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/** The only fields ever forwarded to the LLM (the router adds `stream: true`). */
export interface ChatRequest {
  model?: string;
  messages: ChatMessage[];
  max_tokens?: number;
  temperature?: number;
}

export const MAX_MESSAGES = 256;
export const MAX_MAX_TOKENS = 32_768;
const ROLES: ReadonlySet<string> = new Set(["system", "user", "assistant"]);
const MODEL_RE = /^[\x21-\x7e]{1,128}$/;
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Decrypted plaintext → a whitelisted OpenAI chat-completions request. Unknown fields are refused (nothing
 * unexpected is forwarded upstream). A client-supplied `stream` flag is accepted and ignored: the router
 * always streams.
 */
export function parseChatPlaintext(pt: Uint8Array): ChatRequest {
  const o = parseJson(decodeUtf8(pt));
  if (!isPlainObject(o) || !hasExactKeys(o, ["messages"], ["model", "max_tokens", "temperature", "stream"])) {
    throw new PlrError("E_BAD_REQUEST");
  }
  if (o.stream !== undefined && typeof o.stream !== "boolean") throw new PlrError("E_BAD_REQUEST");
  const msgs = o.messages;
  if (!Array.isArray(msgs) || msgs.length === 0 || msgs.length > MAX_MESSAGES) throw new PlrError("E_BAD_REQUEST");
  const messages: ChatMessage[] = msgs.map((m: unknown) => {
    if (!isPlainObject(m) || !hasExactKeys(m, ["role", "content"])) throw new PlrError("E_BAD_REQUEST");
    if (typeof m.role !== "string" || !ROLES.has(m.role)) throw new PlrError("E_BAD_REQUEST");
    if (typeof m.content !== "string" || LONE_SURROGATE_RE.test(m.content)) throw new PlrError("E_BAD_REQUEST");
    return { role: m.role as ChatMessage["role"], content: m.content };
  });
  const req: ChatRequest = { messages };
  if (o.model !== undefined) {
    if (typeof o.model !== "string" || !MODEL_RE.test(o.model)) throw new PlrError("E_BAD_REQUEST");
    req.model = o.model;
  }
  if (o.max_tokens !== undefined) {
    const n = o.max_tokens;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1 || n > MAX_MAX_TOKENS) throw new PlrError("E_BAD_REQUEST");
    req.max_tokens = n;
  }
  if (o.temperature !== undefined) {
    const t = o.temperature;
    if (typeof t !== "number" || !Number.isFinite(t) || t < 0 || t > 2) throw new PlrError("E_BAD_REQUEST");
    req.temperature = t;
  }
  return req;
}

const U64_DEC_RE = /^(?:0|[1-9][0-9]{0,15})$/;

/** Strict decimal non-negative safe integer (no sign, no leading zeros, no exponent). */
export function parseUintParam(s: string | null): number {
  if (s === null || !U64_DEC_RE.test(s)) throw new PlrError("E_BAD_REQUEST");
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new PlrError("E_BAD_REQUEST");
  return n;
}
