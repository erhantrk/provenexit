// PLR-v1 mock LLM (SPEC §14). Plain JS, zero dependencies: this file's sha256 is the compose
// `llm.model_sha256` when `llm.kind == "mock"`, so it must stay byte-stable.
//
// OpenAI-compatible POST /v1/chat/completions, `stream: true` only, SSE shaped like llama-server's.
// Each answer is "mock-answer-" + 16 random hex chars split into >= 3 deltas, then a finish_reason "stop"
// chunk and `data: [DONE]`. It never echoes the prompt and never logs anything.
// Usage: node server.mjs [--port N]   (default 18081, always bound to 127.0.0.1). GET /health -> {"status":"ok"}.
// If PLR_LLM_API_KEY is set (the mock TDX host sets a per-boot key), every endpoint except /health requires
// `Authorization: Bearer <key>` (like llama-server's --api-key), so no other local process can use it.
import http from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MAX_BODY = 4 * 1024 * 1024;

function json(res, status, obj) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { "content-type": "application/json", "content-length": String(b.length) });
  res.end(b);
}

function chunk(id, created, delta, finish) {
  return {
    choices: [{ finish_reason: finish, index: 0, delta }],
    created,
    id,
    model: "mock",
    system_fingerprint: "plr-mock-llm",
    object: "chat.completion.chunk",
  };
}

function handleChat(req, res) {
  const parts = [];
  let size = 0;
  let tooBig = false;
  req.on("data", (c) => {
    size += c.length;
    if (size > MAX_BODY) tooBig = true;
    else parts.push(c);
  });
  req.on("error", () => res.destroy());
  req.on("end", () => {
    if (tooBig) return json(res, 413, { error: { message: "request too large", type: "invalid_request_error" } });
    let body;
    try {
      body = JSON.parse(Buffer.concat(parts).toString("utf8"));
    } catch {
      return json(res, 400, { error: { message: "invalid JSON", type: "invalid_request_error" } });
    }
    for (const p of parts) p.fill(0);
    if (!body || typeof body !== "object" || !Array.isArray(body.messages) || body.messages.length === 0) {
      return json(res, 400, { error: { message: "messages required", type: "invalid_request_error" } });
    }
    if (body.stream !== true) {
      return json(res, 400, { error: { message: "only stream: true is supported", type: "invalid_request_error" } });
    }
    const answerHex = randomBytes(8).toString("hex");
    const deltas = ["mock-", "answer-", answerHex.slice(0, 8), answerHex.slice(8)];
    const id = "chatcmpl-" + randomBytes(12).toString("hex");
    const created = Math.floor(Date.now() / 1000);
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    const events = [chunk(id, created, { role: "assistant", content: null }, null)];
    for (const d of deltas) events.push(chunk(id, created, { content: d }, null));
    events.push(chunk(id, created, {}, "stop"));
    let i = 0;
    const next = () => {
      if (res.destroyed) return;
      if (i < events.length) {
        res.write("data: " + JSON.stringify(events[i++]) + "\n\n");
        setTimeout(next, 2);
      } else {
        res.end("data: [DONE]\n\n");
      }
    };
    next();
  });
}

function authorized(req, apiKey) {
  if (!apiKey) return true;
  const want = Buffer.from("Bearer " + apiKey, "utf8");
  const got = Buffer.from(String(req.headers.authorization || ""), "utf8");
  return got.length === want.length && timingSafeEqual(got, want);
}

/** Creates the (not yet listening) mock LLM server. `opts.apiKey`: required bearer token (optional). */
export function createMockLlm(opts = {}) {
  const apiKey = typeof opts.apiKey === "string" && opts.apiKey !== "" ? opts.apiKey : null;
  const server = http.createServer((req, res) => {
    const path = (req.url || "/").split("?")[0];
    if (req.method === "GET" && (path === "/health" || path === "/healthz")) return json(res, 200, { status: "ok" });
    if (!authorized(req, apiKey)) {
      req.resume();
      return json(res, 401, { error: { message: "invalid api key", type: "authentication_error" } });
    }
    if (req.method === "GET" && path === "/v1/models") {
      return json(res, 200, { object: "list", data: [{ id: "mock", object: "model", owned_by: "plr" }] });
    }
    if (req.method === "POST" && path === "/v1/chat/completions") return handleChat(req, res);
    req.resume();
    json(res, 404, { error: { message: "not found", type: "invalid_request_error" } });
  });
  server.on("clientError", (_e, socket) => socket.destroy());
  return server;
}

function parsePort(argv) {
  const i = argv.indexOf("--port");
  const raw = i >= 0 ? argv[i + 1] : process.env.PLR_MOCK_LLM_PORT;
  if (raw === undefined || raw === "") return 18081;
  if (!/^[0-9]{1,5}$/.test(raw) || Number(raw) > 65535) {
    process.stderr.write("mock-llm: invalid port\n");
    process.exit(2);
  }
  return Number(raw);
}

function isMain() {
  try {
    return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMain()) {
  const server = createMockLlm({ apiKey: process.env.PLR_LLM_API_KEY });
  server.listen(parsePort(process.argv.slice(2)), "127.0.0.1");
  server.on("error", () => process.exit(1));
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => process.exit(0));
}
