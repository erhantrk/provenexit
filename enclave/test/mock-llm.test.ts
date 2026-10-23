import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type http from "node:http";
import type { AddressInfo } from "node:net";
// @ts-expect-error plain JS module without types
import { createMockLlm } from "../mock-llm/server.mjs";

let s: http.Server;
let base = "";
beforeAll(async () => {
  s = createMockLlm();
  await new Promise<void>((ok) => s.listen(0, "127.0.0.1", () => ok()));
  base = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((ok) => s.close(() => ok())));

const post = (body: unknown) => fetch(`${base}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

describe("mock LLM (SPEC §14)", () => {
  it("streams mock-answer-<16 hex> in >= 3 deltas, finish_reason stop, [DONE]; never echoes the prompt", async () => {
    const res = await post({ messages: [{ role: "user", content: "PROMPT-XYZ" }], stream: true });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/event-stream/);
    const text = await res.text();
    expect(text).not.toContain("PROMPT-XYZ");
    const events = text.split("\n\n").filter(Boolean);
    expect(events.at(-1)).toBe("data: [DONE]");
    const chunks = events.slice(0, -1).map((e) => JSON.parse(e.replace(/^data: /, "")));
    for (const c of chunks) expect(c.object).toBe("chat.completion.chunk");
    const deltas = chunks.map((c) => c.choices[0].delta.content).filter((x: unknown) => typeof x === "string" && x !== "");
    expect(deltas.length).toBeGreaterThanOrEqual(3);
    expect(deltas.join("")).toMatch(/^mock-answer-[0-9a-f]{16}$/);
    expect(chunks.at(-1).choices[0].finish_reason).toBe("stop");
  });
  it("answers differ per request", async () => {
    const a = await (await post({ messages: [{ role: "user", content: "x" }], stream: true })).text();
    const b = await (await post({ messages: [{ role: "user", content: "x" }], stream: true })).text();
    expect(a.match(/"content":"([0-9a-f]{8})"/g)).not.toEqual(b.match(/"content":"([0-9a-f]{8})"/g));
  });
  it("stream:false and bad bodies are rejected; /health works", async () => {
    expect((await post({ messages: [{ role: "user", content: "x" }] })).status).toBe(400);
    expect((await post({})).status).toBe(400);
    expect((await fetch(`${base}/health`)).status).toBe(200);
  });
});
