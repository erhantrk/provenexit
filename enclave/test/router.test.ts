import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes } from "@noble/hashes/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { MockRoot, MockTdxAttester, PlrError, toHex } from "@plr/shared";
import { createRouter } from "../src/router.js";
import { RouterKeys } from "../src/keys.js";
import { ReceiptLog } from "../src/receipts.js";
import { HttpLlmClient, type LlmClient } from "../src/llm.js";
import { Logger } from "../src/log.js";
import { composeBytes, makeCompose } from "../src/compose.js";
// @ts-expect-error plain JS module without types
import { createMockLlm } from "../mock-llm/server.mjs";
import { attest, chat, checkReceipt, postChat, readFrames, seal } from "./helpers.js";

const SECRET = "router-unit-secret-" + toHex(randomBytes(8));
const COMPOSE = composeBytes(makeCompose({ kind: "mock", modelSha256: "11".repeat(32), runtime: "node-mock-llm", bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", runtimeSha256: "33".repeat(32), nodeSha256: "33".repeat(32) }));

const listen = (s: http.Server) => new Promise<number>((ok) => s.listen(0, "127.0.0.1", () => ok((s.address() as AddressInfo).port)));
const closeServer = (s: http.Server) => new Promise<void>((ok) => { s.close(() => ok()); s.closeAllConnections(); });

const logLines: string[] = [];
const captured: string[] = [];
let restoreStdio: () => void;

function captureStdio() {
  const ow = process.stdout.write.bind(process.stdout), ew = process.stderr.write.bind(process.stderr);
  const wrap = (orig: typeof process.stdout.write) => ((chunk: unknown, ...rest: unknown[]) => {
    captured.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
    return (orig as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stdout.write;
  process.stdout.write = wrap(ow);
  process.stderr.write = wrap(ew);
  return () => { process.stdout.write = ow; process.stderr.write = ew; };
}

interface Ctx { url: string; server: http.Server; receipts: ReceiptLog; keys: RouterKeys }
async function startRouter(llm: LlmClient, extra: { maxSeenEpks?: number; maxInflight?: number; attester?: MockTdxAttester } = {}): Promise<Ctx> {
  const keys = RouterKeys.generate();
  const receipts = new ReceiptLog();
  const server = createRouter({
    attester: extra.attester ?? attester, keys, composeBytes: COMPOSE, llm, receipts,
    log: new Logger("plr-router", (l) => logLines.push(l)),
    ...(extra.maxSeenEpks !== undefined ? { maxSeenEpks: extra.maxSeenEpks } : {}),
    ...(extra.maxInflight !== undefined ? { maxInflight: extra.maxInflight } : {}),
  });
  const port = await listen(server);
  return { url: `http://127.0.0.1:${port}`, server, receipts, keys };
}

const root = MockRoot.generate();
const attester = new MockTdxAttester({ root, composeBytes: COMPOSE });
let llmServer: http.Server;
let llmPort: number;
let R: Ctx;
const msg = (s = SECRET) => ({ messages: [{ role: "user", content: `${s} hello` }], max_tokens: 8 });

beforeAll(async () => {
  restoreStdio = captureStdio();
  llmServer = createMockLlm();
  llmPort = await listen(llmServer);
  R = await startRouter(new HttpLlmClient(llmPort));
});
afterAll(async () => {
  restoreStdio();
  await closeServer(R.server);
  await closeServer(llmServer);
});

describe("attestation (SPEC §6.2)", () => {
  it("verifies end to end against the MOCK root and binds the keys + nonce", async () => {
    const v = await attest(R.url, root.publicKey);
    expect(v.rootKind).toBe("MOCK");
    expect(v.bundle.app_compose).toBe(new TextDecoder().decode(COMPOSE));
    expect(toHex(v.keyHash)).toBe(toHex(R.keys.keyHash));
    expect(Object.keys(v.bundle).sort()).toEqual(["app_compose", "ed25519", "event_log", "quote", "root_kind", "v", "x25519"]);
  });

  it.each([
    ["missing", ""],
    ["uppercase", "?nonce=" + "AB".repeat(32)],
    ["short", "?nonce=" + "ab".repeat(31)],
    ["0x prefix", "?nonce=0x" + "ab".repeat(31)],
    ["duplicate", `?nonce=${"ab".repeat(32)}&nonce=${"ab".repeat(32)}`],
    ["extra param", `?nonce=${"ab".repeat(32)}&x=1`],
  ])("bad nonce (%s) → 400 E_BAD_REQUEST", async (_n, q) => {
    const res = await fetch(`${R.url}/v1/attestation${q}`);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "E_BAD_REQUEST" });
  });

  it("wrong method / unknown path", async () => {
    expect((await fetch(`${R.url}/v1/attestation?nonce=${"ab".repeat(32)}`, { method: "POST" })).status).toBe(405);
    expect((await fetch(`${R.url}/nope`)).status).toBe(404);
  });

  it("quote service failure → 503 E_UPSTREAM", async () => {
    const broken = { getQuote: async () => { throw new Error("down"); } } as unknown as MockTdxAttester;
    const r = await startRouter(new HttpLlmClient(llmPort), { attester: broken });
    const res = await fetch(`${r.url}/v1/attestation?nonce=${"ab".repeat(32)}`);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "E_UPSTREAM" });
    await closeServer(r.server);
  });
});

describe("private chat round trip (SPEC §6.3, §8)", () => {
  it("decrypts, streams encrypted deltas and a valid receipt; seq is contiguous from 0", async () => {
    const r = await startRouter(new HttpLlmClient(llmPort));
    const v = await attest(r.url, root.publicKey);
    for (let i = 0; i < 3; i++) {
      const o = await chat(r.url, v, msg());
      expect(o.status).toBe(200);
      expect(o.content).toMatch(/^mock-answer-[0-9a-f]{16}$/);
      expect(o.deltas.length).toBeGreaterThanOrEqual(3);
      expect(o.receipt!.seq).toBe(i);
      expect(checkReceipt(o, v)).toBe(true);
      expect(o.raw).not.toContain("mock-answer");
    }
    expect(r.receipts.size).toBe(3);
    await closeServer(r.server);
  });

  it("forces stream:true and forwards only whitelisted fields", async () => {
    const seen: object[] = [];
    const spy: LlmClient = { chat: async (req) => { seen.push(req); return (async function* () { yield "a"; })(); } };
    const r = await startRouter(spy);
    const v = await attest(r.url, root.publicKey);
    const o = await chat(r.url, v, { ...msg(), stream: false, temperature: 0.5, model: "m" });
    expect(o.status).toBe(200);
    expect(seen[0]).toEqual({ messages: msg().messages, max_tokens: 8, temperature: 0.5, model: "m" });
    await closeServer(r.server);
  });

  it("a replayed request (same epk) is refused: keys are single-use", async () => {
    const v = await attest(R.url, root.publicKey);
    const s = seal(v, new TextEncoder().encode(JSON.stringify(msg())));
    const first = await postChat(R.url, s.body);
    expect(first.status).toBe(200);
    await first.text();
    const again = await postChat(R.url, s.body);
    expect(again.status).toBe(400);
    expect(await again.json()).toEqual({ error: "E_DECRYPT" });
  });

  it("upstream unreachable → 503 E_UPSTREAM (plaintext error, no echo)", async () => {
    const r = await startRouter(new HttpLlmClient(1));
    const v = await attest(r.url, root.publicKey);
    const o = await chat(r.url, v, msg());
    expect(o.status).toBe(503);
    expect(o.error).toBe("E_UPSTREAM");
    await closeServer(r.server);
  });

  it("upstream failing mid-stream → authenticated fin error frame, no receipt", async () => {
    const failing: LlmClient = { chat: async () => (async function* () { yield "partial"; throw new PlrError("E_UPSTREAM"); })() };
    const r = await startRouter(failing);
    const v = await attest(r.url, root.publicKey);
    const o = await chat(r.url, v, msg());
    expect(o.status).toBe(200);
    expect(o.error).toBe("E_UPSTREAM");
    expect(o.receipt).toBeUndefined();
    expect(r.receipts.size).toBe(0);
    await closeServer(r.server);
  });

  it("refuses new chats once the replay cache bound is reached (fail closed)", async () => {
    const r = await startRouter(new HttpLlmClient(llmPort), { maxSeenEpks: 1 });
    const v = await attest(r.url, root.publicKey);
    expect((await chat(r.url, v, msg())).status).toBe(200);
    expect((await chat(r.url, v, msg())).status).toBe(503);
    await closeServer(r.server);
  });
});

describe("bad input (SPEC §6.3 pre-decrypt errors)", () => {
  let v: Awaited<ReturnType<typeof attest>>;
  beforeAll(async () => { v = await attest(R.url, root.publicKey); });
  const good = () => JSON.parse(seal(v, new TextEncoder().encode(JSON.stringify(msg()))).body) as Record<string, unknown>;
  const expectErr = async (res: Response, status: number, code: string) => {
    expect(res.status).toBe(status);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: code });
    expect(text).not.toContain(SECRET);
  };

  it.each([
    ["not JSON", "{nope"],
    ["array", "[]"],
    ["v=2", { v: 2 }],
    ["missing ct", { ct: undefined }],
    ["extra field", { extra: 1 }],
    ["uppercase epk", { epk: "AB".repeat(32) }],
    ["short att_nonce", { att_nonce: "ab".repeat(31) }],
    ["non-canonical base64", { ct: "YWJj ZA==" }],
    ["url-safe base64", { ct: "-_-_" }],
  ])("%s → 400 E_BAD_REQUEST", async (_n, patch) => {
    const body = typeof patch === "string" ? patch : JSON.stringify({ ...good(), ...patch });
    await expectErr(await postChat(R.url, body), 400, "E_BAD_REQUEST");
  });

  it("wrong key / tampered ct / short ct / low-order epk → 400 E_DECRYPT", async () => {
    const g = good();
    const ct = Buffer.from(g.ct as string, "base64"); ct[0]! ^= 1;
    await expectErr(await postChat(R.url, JSON.stringify({ ...g, ct: ct.toString("base64") })), 400, "E_DECRYPT");
    await expectErr(await postChat(R.url, JSON.stringify({ ...good(), ct: Buffer.alloc(8).toString("base64") })), 400, "E_DECRYPT");
    await expectErr(await postChat(R.url, JSON.stringify({ ...good(), epk: "00".repeat(32) })), 400, "E_DECRYPT");
    await expectErr(await postChat(R.url, JSON.stringify({ ...good(), epk: toHex(x25519.getPublicKey(x25519.utils.randomSecretKey())) })), 400, "E_DECRYPT");
    await expectErr(await postChat(R.url, JSON.stringify({ ...good(), att_nonce: "cd".repeat(32) })), 400, "E_DECRYPT");
  });

  it.each([
    ["not JSON", SECRET],
    ["no messages", JSON.stringify({ prompt: SECRET })],
    ["bad role", JSON.stringify({ messages: [{ role: "root", content: SECRET }] })],
    ["unknown field", JSON.stringify({ ...msg(), tools: [SECRET] })],
    ["bad max_tokens", JSON.stringify({ ...msg(), max_tokens: -1 })],
    ["bad temperature", JSON.stringify({ ...msg(), temperature: 9 })],
  ])("decrypted but invalid plaintext (%s) → 400 E_BAD_REQUEST without echo", async (_n, pt) => {
    const s = seal(v, new TextEncoder().encode(pt));
    await expectErr(await postChat(R.url, s.body), 400, "E_BAD_REQUEST");
  });

  it("body > 1 MiB → 413 E_TOO_LARGE (content-length and chunked)", async () => {
    const big = JSON.stringify({ ...good(), ct: Buffer.alloc(800 * 1024).toString("base64") });
    expect(big.length).toBeGreaterThan(1024 * 1024);
    await expectErr(await postChat(R.url, big), 413, "E_TOO_LARGE");
    const chunked = new ReadableStream({
      start(c) { for (let i = 0; i < 20; i++) c.enqueue(new Uint8Array(100 * 1024).fill(0x61)); c.close(); },
    });
    const res = await fetch(`${R.url}/v1/private/chat`, { method: "POST", body: chunked, duplex: "half" } as RequestInit);
    await expectErr(res, 413, "E_TOO_LARGE");
  });

  it("exactly at the limit is accepted for parsing (→ decrypt error, not 413)", async () => {
    const g = good();
    const base = JSON.stringify({ ...g, ct: "" }).length;
    let n = Math.floor(((1024 * 1024 - base) / 4) * 3);
    n -= n % 3;
    const body = JSON.stringify({ ...g, ct: Buffer.alloc(n).toString("base64") });
    expect(body.length).toBeLessThanOrEqual(1024 * 1024);
    await expectErr(await postChat(R.url, body), 400, "E_DECRYPT");
  });

  it("GET on chat → 405", async () => {
    expect((await fetch(`${R.url}/v1/private/chat`)).status).toBe(405);
  });
});

describe("receipts proof endpoint (SPEC §6.4) and healthz", () => {
  it("404 E_NOT_ANCHORED before anchoring; strict seq parsing", async () => {
    const res = await fetch(`${R.url}/v1/receipts/proof?seq=0`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "E_NOT_ANCHORED" });
    for (const q of ["", "?seq=", "?seq=-1", "?seq=01", "?seq=1e3", "?seq=0x1", "?seq=99999999999999999999"]) {
      expect((await fetch(`${R.url}/v1/receipts/proof${q}`)).status, q).toBe(400);
    }
  });
  it("healthz", async () => {
    const res = await fetch(`${R.url}/healthz`);
    expect(await res.json()).toEqual({ ok: true });
  });
});

describe("no retention (SPEC §6)", () => {
  it("no prompt or answer in any output line; logs carry only route/status/duration", async () => {
    const v = await attest(R.url, root.publicKey);
    const o = await chat(R.url, v, msg());
    expect(o.status).toBe(200);
    // a client that disconnects mid-stream must not cause content to be logged either
    const s = seal(v, new TextEncoder().encode(JSON.stringify(msg())));
    const ac = new AbortController();
    const res = await fetch(`${R.url}/v1/private/chat`, { method: "POST", body: s.body, signal: ac.signal });
    expect(res.status).toBe(200);
    ac.abort();
    await new Promise((ok) => setTimeout(ok, 50));
    // and an ordinary completed stream still decrypts
    const s2 = seal(v, new TextEncoder().encode(JSON.stringify(msg())));
    expect((await readFrames(await postChat(R.url, s2.body), s2.kS2c, s2.th)).receipt).toBeDefined();
    const all = captured.join("") + logLines.join("\n");
    expect(all).not.toContain(SECRET);
    expect(all).not.toContain(o.content);
    expect(all).not.toContain("mock-answer");
    for (const l of logLines) expect(l).toMatch(/^plr-router: [a-z_]+( [a-z_]+=[A-Za-z0-9_:/.[\]-]+)*$/);
  });
});
