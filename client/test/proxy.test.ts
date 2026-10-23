import { describe, it, expect, afterEach } from "vitest";
import { request } from "node:http";
import { PrivateClient, startProxy, type ProxyHandle } from "../src/index.js";
import { makeFakeRouter, type Behaviour, type FakeRouter } from "./fake-router.js";

const SECRET = "proxy-secret-" + Math.random().toString(36).slice(2);
let handles: ProxyHandle[] = [];
afterEach(async () => {
  for (const h of handles) await h.close();
  handles = [];
});

async function setup(b: Partial<Behaviour> = {}): Promise<{ r: FakeRouter; p: ProxyHandle }> {
  const r = makeFakeRouter();
  Object.assign(r.behaviour, b);
  const client = new PrivateClient({ routerUrl: "http://router.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: r.fetch });
  const p = await startProxy({ port: 0, client });
  handles.push(p);
  return { r, p };
}

const post = (url: string, body: unknown, headers: Record<string, string> = { "content-type": "application/json" }) =>
  fetch(`${url}/v1/chat/completions`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });

const chatBody = (stream: boolean) => ({ model: "plr", stream, messages: [{ role: "user", content: SECRET }], max_tokens: 8 });

/** Parses OpenAI-style SSE into JSON chunks; returns them plus whether [DONE] was seen. */
function parseOpenAiSse(text: string): { chunks: Record<string, any>[]; done: boolean } {
  const chunks: Record<string, any>[] = [];
  let done = false;
  for (const ev of text.split("\n\n")) {
    if (!ev.startsWith("data: ")) continue;
    const d = ev.slice(6);
    if (d === "[DONE]") done = true;
    else chunks.push(JSON.parse(d) as Record<string, any>);
  }
  return { chunks, done };
}

describe("startProxy", () => {
  it("listens on an ephemeral port when port is 0 and reports the real URL", async () => {
    const { p } = await setup();
    expect(p.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(p.url.endsWith(":0")).toBe(false);
  });

  it("GET /v1/models", async () => {
    const { p } = await setup();
    const res = await fetch(`${p.url}/v1/models`);
    expect(res.status).toBe(200);
    const j = (await res.json()) as { object: string; data: { id: string }[] };
    expect(j.object).toBe("list");
    expect(j.data[0]!.id).toBe("plr");
  });

  it("non-streaming chat.completion", async () => {
    const { r, p } = await setup();
    const res = await post(p.url, chatBody(false));
    expect(res.status).toBe(200);
    const j = (await res.json()) as Record<string, any>;
    expect(j.object).toBe("chat.completion");
    expect(j.choices[0].message).toEqual({ role: "assistant", content: "Hello, wörld 🌍" });
    expect(j.choices[0].finish_reason).toBe("stop");
    expect(j.plr.receipt.compose_hash).toBe(r.composeHash);
    expect(JSON.parse(r.stats.plaintexts[0]!).messages[0].content).toBe(SECRET);
  });

  it("streaming chunks end with [DONE]", async () => {
    const { p } = await setup();
    const res = await post(p.url, chatBody(true));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/event-stream/);
    const { chunks, done } = parseOpenAiSse(await res.text());
    expect(done).toBe(true);
    expect(chunks.every((c) => c.object === "chat.completion.chunk")).toBe(true);
    expect(chunks.map((c) => c.choices[0].delta.content ?? "").join("")).toBe("Hello, wörld 🌍");
    expect(chunks.at(-1)!.choices[0].finish_reason).toBe("stop");
  });

  it("accepts text content parts and max_completion_tokens", async () => {
    const { r, p } = await setup();
    const res = await post(p.url, { messages: [{ role: "developer", content: "sys" }, { role: "user", content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] }], max_completion_tokens: 4 });
    expect(res.status).toBe(200);
    const sent = JSON.parse(r.stats.plaintexts[0]!) as Record<string, any>;
    expect(sent.messages[0]).toEqual({ role: "system", content: "sys" });
    expect(sent.messages[1].content).toBe("ab");
    expect(sent.max_tokens).toBe(4);
  });

  for (const stream of [false, true]) {
    it(`verification failure → 403 plr_verification_failed, nothing forwarded (stream=${stream})`, async () => {
      const { r, p } = await setup();
      r.registry.revokeCompose(r.composeHash);
      const res = await post(p.url, chatBody(stream));
      expect(res.status).toBe(403);
      const j = (await res.json()) as { error: { type: string; code: string; message: string } };
      expect(j.error.type).toBe("plr_verification_failed");
      expect(j.error.code).toBe("E_COMPOSE_NOT_ALLOWED");
      expect(JSON.stringify(j)).not.toContain(SECRET);
      expect(r.stats.chats).toBe(0);
    });
  }

  it("unregistered router → 403 E_INSTANCE_NOT_REGISTERED", async () => {
    const { r, p } = await setup();
    r.registry.removeInstance(r.keyHash);
    const res = await post(p.url, chatBody(false));
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).error.code).toBe("E_INSTANCE_NOT_REGISTERED");
    expect(r.stats.chats).toBe(0);
  });

  it("stream failure before any delta → 502 JSON error", async () => {
    const { p } = await setup({ flipFrame: 0 });
    const res = await post(p.url, chatBody(true));
    expect(res.status).toBe(502);
    const j = (await res.json()) as any;
    expect(j.error).toMatchObject({ type: "plr_stream_failed", code: "E_DECRYPT" });
  });

  it("stream failure after deltas → error event and no [DONE]", async () => {
    const { p } = await setup({ dropFinal: true });
    const res = await post(p.url, chatBody(true));
    expect(res.status).toBe(200);
    const { chunks, done } = parseOpenAiSse(await res.text());
    expect(done).toBe(false);
    expect(chunks.at(-1)!.error).toMatchObject({ code: "E_TRUNCATED" });
  });

  it("non-stream receipt failure → 502, no content returned", async () => {
    const { p } = await setup({ wrongSigner: true });
    const res = await post(p.url, chatBody(false));
    expect(res.status).toBe(502);
    const text = await res.text();
    expect(text).toContain("E_RECEIPT_SIG");
    expect(text).not.toContain("Hello");
  });

  it("input validation: content type, JSON, shape, size, method, path", async () => {
    const { r, p } = await setup();
    expect((await post(p.url, chatBody(false), { "content-type": "text/plain" })).status).toBe(415);
    expect((await post(p.url, "{not json")).status).toBe(400);
    expect((await post(p.url, { messages: [] })).status).toBe(400);
    expect((await post(p.url, { messages: [{ role: "user", content: null }] })).status).toBe(400);
    expect((await post(p.url, { messages: [{ role: "user", content: "x" }], stream: "yes" })).status).toBe(400);
    expect((await post(p.url, { messages: [{ role: "user", content: "x".repeat(1100 * 1024) }] })).status).toBe(413);
    expect((await fetch(`${p.url}/v1/chat/completions`)).status).toBe(405);
    expect((await fetch(`${p.url}/nope`)).status).toBe(404);
    expect(r.stats.chats).toBe(0);
  });

  it("rejects foreign Host headers (DNS rebinding)", async () => {
    const { p } = await setup();
    const port = Number(new URL(p.url).port);
    const status = await new Promise<number>((ok, ko) => {
      const req = request({ host: "127.0.0.1", port, path: "/v1/models", headers: { host: `evil.example:${port}` } }, (res) => {
        res.resume();
        ok(res.statusCode ?? 0);
      });
      req.on("error", ko);
      req.end();
    });
    expect(status).toBe(421);
  });
});
