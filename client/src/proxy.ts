/**
 * Local OpenAI-compatible proxy (SPEC §12): `POST /v1/chat/completions` (stream true|false) and
 * `GET /v1/models`, backed by a {@link PrivateClient}. The router is verified before any prompt leaves the
 * machine; verification failure → `403 {"error":{"type":"plr_verification_failed","code":...}}` and nothing
 * is forwarded. The proxy never logs or echoes request/response content.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { PlrError, isPlrError, type PlrErrorCode } from "@plr/shared";
import { VERIFICATION_CODES, type ChatResult, type PrivateClient } from "./client.js";
import { normalizeChatRequest, type ChatMessage, type ChatRequest } from "./chat-request.js";
import { isPlainObject } from "./util.js";

export interface ProxyOptions {
  port: number;
  /** Bind address (default `127.0.0.1`). */
  host?: string;
  client: PrivateClient;
}

export interface ProxyHandle {
  url: string;
  close(): Promise<void>;
}

const MAX_BODY = 1024 * 1024;
const MODEL_ID = "plr";
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

interface ErrorBody {
  error: { type: string; code: string; message: string };
}

/** Static, content-free messages. */
const MESSAGES: Partial<Record<PlrErrorCode, string>> = {
  E_BAD_RESPONSE: "router attestation response is malformed or the router is unreachable",
  E_QUOTE_FORMAT: "attestation quote is malformed",
  E_TEE_TYPE: "attestation is not from a TDX TEE",
  E_ROOT_UNTRUSTED: "attestation root is not the trusted root",
  E_QUOTE_SIG: "attestation quote signature is invalid",
  E_DEBUG_TD: "router runs in a debug-mode TD",
  E_REPORT_DATA_KEYS: "attestation does not bind the advertised router keys",
  E_NONCE: "attestation is not a fresh session quote for this request's nonce",
  E_EVENT_LOG: "attestation event log is invalid",
  E_RTMR3: "attestation event log does not replay to RTMR3",
  E_COMPOSE_MISMATCH: "published app-compose does not match the measured compose hash",
  E_COMPOSE_NOT_ALLOWED: "router build (compose hash) is not allowed by the on-chain registry",
  E_OS_NOT_ALLOWED: "router OS measurement is not allowed by the on-chain registry",
  E_INSTANCE_NOT_REGISTERED: "router instance keys are not registered on-chain",
  E_REGISTRY_UNAVAILABLE: "on-chain registry is unreachable",
  E_DECRYPT: "response stream failed authentication",
  E_TRUNCATED: "response stream was truncated",
  E_RECEIPT_SIG: "response receipt signature is invalid",
  E_RECEIPT_MISMATCH: "response receipt does not match the exchanged data",
  E_UPSTREAM: "router reported an upstream LLM failure",
  E_TOO_LARGE: "request too large",
  E_BAD_INPUT: "invalid request",
  E_BAD_REQUEST: "router rejected the request",
};

function errorFor(e: unknown): { status: number; body: ErrorBody } {
  const code: PlrErrorCode | "E_INTERNAL" = isPlrError(e) ? e.code : "E_INTERNAL";
  const message = (code !== "E_INTERNAL" && MESSAGES[code]) || "internal proxy error";
  if (code !== "E_INTERNAL" && VERIFICATION_CODES.has(code)) {
    return { status: 403, body: { error: { type: "plr_verification_failed", code, message } } };
  }
  switch (code) {
    case "E_BAD_INPUT":
      return { status: 400, body: { error: { type: "invalid_request_error", code, message } } };
    case "E_TOO_LARGE":
      return { status: 413, body: { error: { type: "invalid_request_error", code, message } } };
    case "E_DECRYPT":
    case "E_TRUNCATED":
    case "E_RECEIPT_SIG":
    case "E_RECEIPT_MISMATCH":
      return { status: 502, body: { error: { type: "plr_stream_failed", code, message } } };
    case "E_UPSTREAM":
    case "E_BAD_REQUEST":
      return { status: 502, body: { error: { type: "plr_upstream_error", code, message } } };
    default:
      return { status: 500, body: { error: { type: "plr_internal_error", code, message } } };
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  const s = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(s),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(s);
}

function simpleError(res: ServerResponse, status: number, type: string, message: string): void {
  sendJson(res, status, { error: { type, code: null, message } });
}

/** Reads the request body up to `MAX_BODY` bytes; resolves `null` if it is larger. */
function readBody(req: IncomingMessage): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const declared = req.headers["content-length"];
    if (declared !== undefined && /^\d+$/.test(declared) && Number(declared) > MAX_BODY) {
      resolve(null);
      req.resume();
      return;
    }
    const parts: Buffer[] = [];
    let n = 0;
    let over = false;
    req.on("data", (c: Buffer) => {
      if (over) return;
      n += c.length;
      if (n > MAX_BODY) {
        over = true;
        parts.length = 0;
        resolve(null);
        return;
      }
      parts.push(c);
    });
    req.on("end", () => {
      if (!over) resolve(Buffer.concat(parts));
    });
    req.on("error", reject);
  });
}


/** OpenAI message content: a string, or an array of `{type:"text", text}` parts (concatenated). */
function openAiContent(c: unknown): string {
  if (typeof c === "string") return c;
  if (Array.isArray(c)) {
    return c
      .map((p: unknown) => {
        if (!isPlainObject(p) || p.type !== "text" || typeof p.text !== "string") {
          throw new PlrError("E_BAD_INPUT", "only text content parts are supported");
        }
        return p.text;
      })
      .join("");
  }
  throw new PlrError("E_BAD_INPUT", "message content must be text");
}

/** Converts an OpenAI chat-completions body to a PLR chat request. @throws PlrError E_BAD_INPUT */
function fromOpenAi(j: unknown): { req: ChatRequest; stream: boolean; model: string } {
  if (!isPlainObject(j)) throw new PlrError("E_BAD_INPUT", "body must be a JSON object");
  if (!Array.isArray(j.messages)) throw new PlrError("E_BAD_INPUT", "messages required");
  if (j.n !== undefined && j.n !== null && j.n !== 1) throw new PlrError("E_BAD_INPUT", "only n=1 is supported");
  if (j.stream !== undefined && j.stream !== null && typeof j.stream !== "boolean") throw new PlrError("E_BAD_INPUT", "stream must be boolean");
  const messages: ChatMessage[] = j.messages.map((m: unknown) => {
    if (!isPlainObject(m)) throw new PlrError("E_BAD_INPUT", "message must be an object");
    // OpenAI's newer "developer" role is the system prompt for this purpose.
    const role = m.role === "developer" ? "system" : (m.role as string);
    return { role, content: openAiContent(m.content) };
  });
  const req: ChatRequest = { messages };
  if (j.model !== undefined && j.model !== null) req.model = j.model as string;
  const maxTokens = j.max_tokens ?? j.max_completion_tokens;
  if (maxTokens !== undefined && maxTokens !== null) req.max_tokens = maxTokens as number;
  if (j.temperature !== undefined && j.temperature !== null) req.temperature = j.temperature as number;
  const n = normalizeChatRequest(req); // full validation
  return { req: n, stream: j.stream === true, model: n.model };
}

function plrExtension(r: ChatResult): Record<string, unknown> {
  return {
    receipt: r.receipt,
    sig: r.sig,
    root_kind: r.verified.rootKind,
  };
}

async function handleChat(client: PrivateClient, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const ctype = (req.headers["content-type"] ?? "").toLowerCase();
  // Requiring a JSON content type also blocks CORS "simple" cross-site POSTs from web pages.
  if (!/^application\/json\s*(?:;|$)/.test(ctype)) {
    simpleError(res, 415, "invalid_request_error", "content-type must be application/json");
    return;
  }
  const raw = await readBody(req);
  if (raw === null) {
    sendJson(res, 413, errorFor(new PlrError("E_TOO_LARGE")).body);
    return;
  }
  let parsed: { req: ChatRequest; stream: boolean; model: string };
  try {
    let j: unknown;
    try {
      j = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)) as unknown;
    } catch {
      throw new PlrError("E_BAD_INPUT", "body is not JSON");
    }
    parsed = fromOpenAi(j);
  } catch (e) {
    const { status, body } = errorFor(e);
    sendJson(res, status, body);
    return;
  } finally {
    raw.fill(0);
  }

  // Verify the router before anything derived from the prompt is sent.
  try {
    await client.ensureVerified();
  } catch (e) {
    const { status, body } = errorFor(e);
    sendJson(res, status, body);
    return;
  }

  const abort = new AbortController();
  res.on("close", () => {
    if (!res.writableFinished) abort.abort();
  });
  const id = `chatcmpl-${randomBytes(12).toString("hex")}`;
  const created = Math.floor(Date.now() / 1000);

  if (!parsed.stream) {
    try {
      const r = await client.chat(parsed.req, { signal: abort.signal });
      sendJson(res, 200, {
        id,
        object: "chat.completion",
        created,
        model: parsed.model,
        choices: [{ index: 0, message: { role: "assistant", content: r.content }, finish_reason: "stop", logprobs: null }],
        plr: plrExtension(r),
      });
    } catch (e) {
      const { status, body } = errorFor(e);
      sendJson(res, status, body);
    }
    return;
  }

  // Streaming: headers are sent lazily with the first authenticated delta, so a failure before that still
  // gets a proper HTTP error status.
  const chunk = (delta: Record<string, unknown>, finish: string | null, extra?: Record<string, unknown>): string =>
    `data: ${JSON.stringify({
      id,
      object: "chat.completion.chunk",
      created,
      model: parsed.model,
      choices: [{ index: 0, delta, finish_reason: finish, logprobs: null }],
      ...extra,
    })}\n\n`;
  const start = (): void => {
    if (res.headersSent) return;
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-content-type-options": "nosniff",
    });
    res.write(chunk({ role: "assistant", content: "" }, null));
  };
  try {
    const r = await client.chat(parsed.req, {
      signal: abort.signal,
      onDelta: (d) => {
        start();
        if (d.length > 0) res.write(chunk({ content: d }, null));
      },
    });
    start();
    res.write(chunk({}, "stop", { plr: plrExtension(r) }));
    res.end("data: [DONE]\n\n");
  } catch (e) {
    const { status, body } = errorFor(e);
    if (!res.headersSent) {
      sendJson(res, status, body);
    } else {
      // Mid-stream failure: emit an error event (the OpenAI SDK raises it) and never send [DONE].
      res.end(`data: ${JSON.stringify(body)}\n\n`);
    }
  }
}

function hostAllowed(req: IncomingMessage, boundLoopback: boolean, port: number): boolean {
  if (!boundLoopback) return true;
  const host = req.headers.host;
  if (host === undefined) return false;
  // DNS-rebinding defence: a loopback-bound proxy only answers to loopback host names.
  const allowed = [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`];
  return allowed.includes(host.toLowerCase());
}

/** Starts the proxy. `port: 0` picks a free port; the returned `url` carries the actual one. */
export async function startProxy(o: ProxyOptions): Promise<ProxyHandle> {
  if (!isPlainObject(o)) throw new PlrError("E_BAD_INPUT", "options required");
  const { client } = o;
  if (typeof client !== "object" || client === null || typeof client.chat !== "function") {
    throw new PlrError("E_BAD_INPUT", "client required");
  }
  if (!Number.isSafeInteger(o.port) || o.port < 0 || o.port > 65535) throw new PlrError("E_BAD_INPUT", "bad port");
  const host = o.host ?? "127.0.0.1";
  if (typeof host !== "string" || host.length === 0) throw new PlrError("E_BAD_INPUT", "bad host");
  const boundLoopback = LOOPBACK.has(host);
  let port = o.port;

  const server: Server = createServer((req, res) => {
    void (async () => {
      try {
        if (!hostAllowed(req, boundLoopback, port)) {
          simpleError(res, 421, "invalid_request_error", "host not allowed");
          return;
        }
        const path = (req.url ?? "/").split("?")[0];
        if (path === "/v1/models") {
          if (req.method !== "GET") {
            simpleError(res, 405, "invalid_request_error", "method not allowed");
            return;
          }
          sendJson(res, 200, { object: "list", data: [{ id: MODEL_ID, object: "model", created: 0, owned_by: "plr" }] });
          return;
        }
        if (path === "/v1/chat/completions") {
          if (req.method !== "POST") {
            simpleError(res, 405, "invalid_request_error", "method not allowed");
            return;
          }
          await handleChat(client, req, res);
          return;
        }
        simpleError(res, 404, "invalid_request_error", "not found");
      } catch {
        // Never surface internals (or content) — generic failure only.
        if (!res.headersSent) simpleError(res, 500, "plr_internal_error", "internal proxy error");
        else res.end();
      }
    })();
  });
  server.requestTimeout = 0; // long generations; the client enforces its own timeouts
  server.headersTimeout = 30_000;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  port = (server.address() as AddressInfo).port;
  const urlHost = host.includes(":") ? `[${host}]` : host;
  return {
    url: `http://${urlHost}:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}
