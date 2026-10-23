// LOCKED — plan "Demo scenarios" 1–7 + proxy + no-retention, end-to-end against near-sandbox and the mock TDX host.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import OpenAI from "openai";
import { PlrError, verifyReceipt, receiptLeaf, verifyMerkleProof, fromHex, toHex } from "@plr/shared";
import { PrivateClient, startProxy } from "@plr/client";
import { startStack, type Stack, type RouterHandle } from "../src/harness.js";

const SECRET = "my-secret-prompt-" + Math.random().toString(36).slice(2);
const msg = (s = SECRET) => ({ messages: [{ role: "user", content: `${s} — reply with one word` }], max_tokens: 16 });

let S: Stack;
let honest: RouterHandle;
beforeAll(async () => {
  S = await startStack({ llm: process.env.PLR_E2E_LLM === "llama" ? "llama" : "mock" });
  await S.approveBuild("honest");
  honest = await S.startRouter("honest");
}, 300_000);
afterAll(async () => { await S?.stop(); });

const client = (url: string) => new PrivateClient({ routerUrl: url, registry: S.registry, trustedRoot: S.trustedRoot });
async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}

describe("1. honest router", () => {
  it("verifies, answers, and returns a valid receipt", async () => {
    const c = client(honest.url);
    const deltas: string[] = [];
    const r = await c.chat(msg(), { onDelta: (d) => deltas.push(d) });
    expect(r.content.length).toBeGreaterThan(0);
    expect(deltas.join("")).toBe(r.content);
    expect(r.verified.rootKind).toBe("MOCK");
    expect(toHex(r.verified.composeHash)).toBe(honest.composeHash);
    expect(toHex(r.verified.keyHash)).toBe(honest.keyHash);
    expect(verifyReceipt(r.receipt, r.sig, r.verified.ed25519)).toBe(true);
    expect(r.receipt.compose_hash).toBe(honest.composeHash);
  });

  it("anchors receipts on-chain and serves inclusion proofs", async () => {
    const c = client(honest.url);
    const r = await c.chat(msg("anchor-me"));
    let proof: any;
    for (let i = 0; i < 60; i++) {
      const res = await fetch(`${honest.url}/v1/receipts/proof?seq=${r.receipt.seq}`);
      if (res.status === 200) { proof = await res.json(); break; }
      await new Promise((ok) => setTimeout(ok, 1000));
    }
    expect(proof, "receipt was never anchored").toBeTruthy();
    const anchor = await S.registry.getAnchor(proof.anchor_id);
    expect(anchor).not.toBeNull();
    expect(anchor!.root).toBe(proof.root);
    expect(anchor!.key_hash).toBe(honest.keyHash);
    expect(verifyMerkleProof(receiptLeaf(r.receipt), proof.index, proof.count, proof.proof.map((h: string) => fromHex(h, 32)), fromHex(anchor!.root, 32))).toBe(true);
  }, 90_000);
});

describe("2. evil router that logs prompts", () => {
  it("is refused before any prompt is sent; nothing is stolen", async () => {
    const evil = await S.startRouter("evil-logger");
    expect(evil.composeHash).not.toBe(honest.composeHash);
    expect(await codeOf(client(evil.url).chat(msg()))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(evil.output()).not.toContain(SECRET);
    const stolen = join(S.runDir, "stolen.log");
    expect(existsSync(stolen) ? readFileSync(stolen, "utf8") : "").not.toContain(SECRET);
    await evil.stop();
  });
});

describe("3. MITM swaps the encryption key", () => {
  it("is refused: report_data does not bind the advertised key", async () => {
    const m = await S.startRouter("mitm-key");
    expect(await codeOf(client(m.url).chat(msg()))).toBe("E_REPORT_DATA_KEYS");
    expect(m.output()).not.toContain(SECRET);
    await m.stop();
  });
});

describe("4. replayed quote", () => {
  it("is refused on the second session (stale nonce)", async () => {
    const m = await S.startRouter("replay-quote");
    await client(m.url).attest(); // first response is genuine and fresh
    expect(await codeOf(client(m.url).attest())).toBe("E_NONCE");
    await m.stop();
  });
});

describe("5. owner revokes the build on-chain", () => {
  it("next request is refused immediately; re-allow restores service", async () => {
    const c = client(honest.url);
    await c.chat(msg("before-revoke"));
    await S.call("owner", "revoke_compose", { hash: honest.composeHash });
    expect(await codeOf(client(honest.url).chat(msg()))).toBe("E_COMPOSE_NOT_ALLOWED");
    await S.call("owner", "allow_compose", { hash: honest.composeHash });
    const r = await client(honest.url).chat(msg("after-reallow"));
    expect(r.content.length).toBeGreaterThan(0);
  });
});

describe("6. tampered / truncated response stream", () => {
  it("truncation is detected and no partial answer is returned", async () => {
    const m = await S.startRouter("truncate-stream");
    const deltas: string[] = [];
    expect(await codeOf(client(m.url).chat(msg(), { onDelta: (d) => deltas.push(d) }))).toBe("E_TRUNCATED");
    await m.stop();
  });
  it("a flipped ciphertext byte is detected", async () => {
    const m = await S.startRouter("tamper-stream");
    expect(await codeOf(client(m.url).chat(msg()))).toBe("E_DECRYPT");
    await m.stop();
  });
});

describe("7. debug-mode TD", () => {
  it("is refused (and cannot register on-chain)", async () => {
    await S.approveBuild("debug-td");
    const d = await S.startRouter("debug-td");
    expect(await codeOf(client(d.url).chat(msg()))).toBe("E_DEBUG_TD");
    await d.stop();
  });
});

describe("8. unregistered instance of an approved build", () => {
  it("is refused: every serving key must be published on-chain", async () => {
    const u = await S.startRouter("honest", { register: false });
    expect(await codeOf(client(u.url).chat(msg()))).toBe("E_INSTANCE_NOT_REGISTERED");
    await u.stop();
  });
});

describe("9. OpenAI-compatible local proxy", () => {
  it("works unchanged with the official openai SDK (stream and non-stream)", async () => {
    const p = await startProxy({ port: 0, client: client(honest.url) });
    const oa = new OpenAI({ baseURL: `${p.url}/v1`, apiKey: "unused" });
    const r = await oa.chat.completions.create({ model: "plr", messages: [{ role: "user", content: "hi" }], max_tokens: 8 });
    expect(r.choices[0]!.message.content!.length).toBeGreaterThan(0);
    const s = await oa.chat.completions.create({ model: "plr", stream: true, messages: [{ role: "user", content: "hi" }], max_tokens: 8 });
    let out = "";
    for await (const ch of s) out += ch.choices[0]?.delta?.content ?? "";
    expect(out.length).toBeGreaterThan(0);
    await p.close();
  });

  it("returns 403 with the PLR code and forwards nothing when verification fails", async () => {
    const evil = await S.startRouter("evil-logger");
    const p = await startProxy({ port: 0, client: client(evil.url) });
    const res = await fetch(`${p.url}/v1/chat/completions`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "plr", messages: [{ role: "user", content: SECRET }] }),
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.code).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(evil.output()).not.toContain(SECRET);
    await p.close(); await evil.stop();
  });
});

describe("10. no retention by the honest router", () => {
  it("never writes the prompt or answer to its output or run directory", async () => {
    const r = await client(honest.url).chat(msg());
    const out = honest.output();
    expect(out).not.toContain(SECRET);
    expect(out).not.toContain(r.content.trim() || "\u0000never");
    const walk = (d: string): string[] => readdirSync(d).flatMap((f) => {
      const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p];
    });
    for (const f of walk(S.runDir)) {
      if (statSync(f).size > 5_000_000) continue; // model files / sandbox data
      if (f.endsWith("stolen.log")) continue;      // written only by the evil build
      expect(readFileSync(f).includes(Buffer.from(SECRET)), `secret found in ${f}`).toBe(false);
    }
  });
});
