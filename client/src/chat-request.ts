/** Validation and canonical encoding of the chat request that is encrypted to the router (SPEC §6.3). */
import { PlrError, utf8 } from "@plr/shared";
import { isPlainObject, isWellFormed } from "./util.js";

export interface ChatMessage {
  role: string;
  content: string;
}

export interface ChatRequest {
  messages: ChatMessage[];
  max_tokens?: number;
  temperature?: number;
  model?: string;
}

export const DEFAULT_MODEL = "plr";
/** Limits mirror the router's plaintext whitelist, so a request it would refuse is never sent. */
export const MAX_MESSAGES = 256;
export const MAX_TOKENS_LIMIT = 32_768;
export const ROLES: ReadonlySet<string> = new Set(["system", "user", "assistant"]);
const MODEL_RE = /^[\x21-\x7e]{1,128}$/;

const bad = (detail: string): never => {
  throw new PlrError("E_BAD_INPUT", detail);
};


/** Validates `req` and returns a normalised copy containing only the §6.3 fields. @throws PlrError E_BAD_INPUT */
export function normalizeChatRequest(req: unknown): Required<Pick<ChatRequest, "messages" | "model">> & ChatRequest {
  if (!isPlainObject(req)) return bad("request must be an object");
  const { messages, max_tokens, temperature, model } = req;
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > MAX_MESSAGES) {
    return bad(`messages must be an array of 1..${MAX_MESSAGES} entries`);
  }
  const msgs: ChatMessage[] = messages.map((m: unknown) => {
    if (!isPlainObject(m)) return bad("message must be an object");
    if (typeof m.role !== "string" || !ROLES.has(m.role)) return bad("message role must be system, user or assistant");
    if (typeof m.content !== "string") return bad("message content must be a string");
    if (!isWellFormed(m.content)) return bad("message contains a lone surrogate");
    return { role: m.role, content: m.content };
  });
  const out: Required<Pick<ChatRequest, "messages" | "model">> & ChatRequest = { model: DEFAULT_MODEL, messages: msgs };
  if (model !== undefined) {
    if (typeof model !== "string" || !MODEL_RE.test(model)) return bad("model must be 1..128 printable ASCII chars");
    out.model = model;
  }
  if (max_tokens !== undefined) {
    if (typeof max_tokens !== "number" || !Number.isSafeInteger(max_tokens) || max_tokens < 1 || max_tokens > MAX_TOKENS_LIMIT) {
      return bad("max_tokens must be a positive integer");
    }
    out.max_tokens = max_tokens;
  }
  if (temperature !== undefined) {
    if (typeof temperature !== "number" || !Number.isFinite(temperature) || temperature < 0 || temperature > 2) {
      return bad("temperature must be a number in [0, 2]");
    }
    out.temperature = temperature;
  }
  return out;
}

/** UTF-8 JSON plaintext for the router. Rejects strings with lone surrogates. @throws PlrError E_BAD_INPUT */
export function encodeChatPlaintext(req: ChatRequest): Uint8Array {
  const n = normalizeChatRequest(req);
  const body: Record<string, unknown> = { model: n.model, messages: n.messages, stream: true };
  if (n.max_tokens !== undefined) body.max_tokens = n.max_tokens;
  if (n.temperature !== undefined) body.temperature = n.temperature;
  return utf8(JSON.stringify(body));
}
