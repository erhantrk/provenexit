import { describe, it, expect } from "vitest";
import { PlrError, verifyReceipt, toHex, type RegistryReader } from "@plr/shared";
import { PrivateClient, VERIFIED_TTL_MS } from "../src/index.js";
import { makeFakeRouter, prng, randomChunker, type FakeRouter, type Behaviour } from "./fake-router.js";

const msg = (s = "top-secret prompt") => ({ messages: [{ role: "user", content: s }], max_tokens: 16 });

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PlrError);
    return (e as PlrError).code;
  }
  return "NO_THROW";
}

function setup(b: Partial<Behaviour> = {}, o: { registry?: RegistryReader; clock?: () => number } = {}) {
  const r = makeFakeRouter();
  Object.assign(r.behaviour, b);
  const c = new PrivateClient({
    routerUrl: "http://router.test/",
    registry: o.registry ?? r.registry,
    trustedRoot: r.root.publicKey,
    fetch: r.fetch,
    ...(o.clock ? { clock: o.clock } : {}),
  });
  return { r, c };
}

describe("PrivateClient — honest router", () => {
  it("verifies, decrypts in order, and returns a verified receipt", async () => {
    const { r, c } = setup();
    const deltas: string[] = [];
    const res = await c.chat(msg(), { onDelta: (d) => deltas.push(d) });
    expect(res.content).toBe("Hello, wörld 🌍");
    expect(deltas).toEqual(r.behaviour.deltas);
    expect(res.verified.rootKind).toBe("MOCK");
    expect(toHex(res.verified.composeHash)).toBe(r.composeHash);
    expect(toHex(res.verified.keyHash)).toBe(r.keyHash);
    expect(res.receipt.compose_hash).toBe(r.composeHash);
    expect(verifyReceipt(res.receipt, res.sig, res.verified.ed25519)).toBe(true);
    const sent = JSON.parse(r.stats.plaintexts[0]!) as Record<string, unknown>;
    expect(sent).toEqual({ model: "plr", messages: msg().messages, stream: true, max_tokens: 16 });
  });

  it("works over real HTTP with the global fetch", async () => {
    const r = makeFakeRouter();
    const srv = await r.listen();
    try {
      const c = new PrivateClient({ routerUrl: srv.url, registry: r.registry, trustedRoot: r.root.publicKey });
      const res = await c.chat(msg());
      expect(res.content).toBe("Hello, wörld 🌍");
    } finally {
      await srv.close();
    }
  });

  it("fuzz: any chunking of the SSE response decrypts identically", async () => {
    for (let seed = 1; seed <= 60; seed++) {
      const { c } = setup({ chunker: randomChunker(prng(seed), 80), deltas: ["α", "β".repeat(seed), "", "γ🌍"] });
      const res = await c.chat(msg());
      expect(res.content).toBe("α" + "β".repeat(seed) + "γ🌍");
    }
  });

  it("handles a stream with zero deltas (empty answer) and a valid receipt", async () => {
    const { c } = setup({ deltas: [] });
    const res = await c.chat(msg());
    expect(res.content).toBe("");
  });
});

describe("PrivateClient — attestation freshness and caching", () => {
  it("attest() uses a fresh random nonce every call", async () => {
    const { r, c } = setup();
    await c.attest();
    await c.attest();
    expect(r.stats.attestations).toBe(2);
    expect(r.stats.nonces[0]).not.toBe(r.stats.nonces[1]);
  });

  it("reuses a verification for < 60 s and re-attests after", async () => {
    let now = 1_000;
    const { r, c } = setup({}, { clock: () => now });
    await c.chat(msg());
    await c.chat(msg());
    expect(r.stats.attestations).toBe(1);
    now += VERIFIED_TTL_MS + 1;
    await c.chat(msg());
    expect(r.stats.attestations).toBe(2);
  });

  it("re-attests (and so sees an on-chain revocation) after the cache expires", async () => {
    let now = 0;
    const { r, c } = setup({}, { clock: () => now });
    await c.chat(msg());
    r.registry.revokeCompose(r.composeHash);
    now += VERIFIED_TTL_MS + 1;
    const chatsBefore = r.stats.chats;
    expect(await codeOf(c.chat(msg()))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(r.stats.chats).toBe(chatsBefore);
  });

  it("concurrent chats share one attestation", async () => {
    const { r, c } = setup();
    await Promise.all([c.chat(msg()), c.chat(msg()), c.chat(msg())]);
    expect(r.stats.attestations).toBe(1);
    expect(r.stats.chats).toBe(3);
  });

  it("drops the cached verification after a failed session", async () => {
    const { r, c } = setup();
    await c.chat(msg());
    r.behaviour.dropFinal = true;
    expect(await codeOf(c.chat(msg()))).toBe("E_TRUNCATED");
    r.behaviour.dropFinal = false;
    await c.chat(msg());
    expect(r.stats.attestations).toBe(2);
  });
});

describe("PrivateClient — verification failures send nothing", () => {
  it("revoked compose → E_COMPOSE_NOT_ALLOWED, no chat request", async () => {
    const { r, c } = setup();
    r.registry.revokeCompose(r.composeHash);
    expect(await codeOf(c.chat(msg()))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(r.stats.chats).toBe(0);
  });

  it("unregistered instance → E_INSTANCE_NOT_REGISTERED", async () => {
    const { r, c } = setup();
    r.registry.removeInstance(r.keyHash);
    expect(await codeOf(c.chat(msg()))).toBe("E_INSTANCE_NOT_REGISTERED");
    expect(r.stats.chats).toBe(0);
  });

  it("MITM key → E_REPORT_DATA_KEYS", async () => {
    const { r, c } = setup({ mitmKey: true });
    expect(await codeOf(c.chat(msg()))).toBe("E_REPORT_DATA_KEYS");
    expect(r.stats.chats).toBe(0);
  });

  it("replayed quote → E_NONCE on the next attestation", async () => {
    const { c } = setup({ replayAttestation: true });
    await c.attest();
    expect(await codeOf(c.attest())).toBe("E_NONCE");
  });

  it("debug TD → E_DEBUG_TD", async () => {
    const r = makeFakeRouter({ debug: true });
    const c = new PrivateClient({ routerUrl: "http://x.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: r.fetch });
    expect(await codeOf(c.chat(msg()))).toBe("E_DEBUG_TD");
    expect(r.stats.chats).toBe(0);
  });

  it("registry failure → E_REGISTRY_UNAVAILABLE", async () => {
    const r0 = makeFakeRouter();
    const broken: RegistryReader = {
      chain: "near",
      contractId: "reg.test",
      getRoot: () => r0.registry.getRoot(),
      isComposeAllowed: () => Promise.reject(new Error("rpc down")),
      isOsAllowed: () => r0.registry.isOsAllowed(r0.osHash),
      getInstance: (k) => r0.registry.getInstance(k),
      getAnchor: (i) => r0.registry.getAnchor(i),
    };
    const c = new PrivateClient({ routerUrl: "http://x.test", registry: broken, trustedRoot: r0.root.publicKey, fetch: r0.fetch });
    expect(await codeOf(c.chat(msg()))).toBe("E_REGISTRY_UNAVAILABLE");
    expect(r0.stats.chats).toBe(0);
  });

  it("pinned root differing from the registry root → E_ROOT_UNTRUSTED", async () => {
    const r = makeFakeRouter();
    const other = makeFakeRouter();
    const c = new PrivateClient({ routerUrl: "http://x.test", registry: r.registry, trustedRoot: other.root.publicKey, fetch: r.fetch });
    expect(await codeOf(c.chat(msg()))).toBe("E_ROOT_UNTRUSTED");
  });

  it("unreachable router / non-JSON / non-200 attestation → E_BAD_RESPONSE", async () => {
    const r = makeFakeRouter();
    const mk = (f: typeof fetch) => new PrivateClient({ routerUrl: "http://x.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: f });
    expect(await codeOf(mk(() => Promise.reject(new TypeError("ECONNREFUSED"))).attest())).toBe("E_BAD_RESPONSE");
    expect(await codeOf(mk(async () => new Response("not json")).attest())).toBe("E_BAD_RESPONSE");
    expect(await codeOf(mk(async () => new Response("{}", { status: 500 })).attest())).toBe("E_BAD_RESPONSE");
    expect(await codeOf(mk(async () => new Response("x".repeat(300 * 1024))).attest())).toBe("E_BAD_RESPONSE");
  });

  it("rejects invalid requests before any network traffic", async () => {
    const { r, c } = setup();
    expect(await codeOf(c.chat({ messages: [] }))).toBe("E_BAD_INPUT");
    expect(await codeOf(c.chat({ messages: [{ role: "user", content: "x" }], max_tokens: -1 }))).toBe("E_BAD_INPUT");
    expect(await codeOf(c.chat({ messages: [{ role: "user", content: "\ud800" }] }))).toBe("E_BAD_INPUT");
    expect(await codeOf(c.chat({ messages: [{ role: "tool", content: "x" }] }))).toBe("E_BAD_INPUT");
    expect(await codeOf(c.chat({ messages: [{ role: "user", content: "x" }], model: "has space" }))).toBe("E_BAD_INPUT");
    expect(await codeOf(c.chat({ messages: [{ role: "user", content: "x" }], max_tokens: 40_000 }))).toBe("E_BAD_INPUT");
    expect(await codeOf(c.chat({ messages: [{ role: "user", content: "x" }], temperature: Number.NaN }))).toBe("E_BAD_INPUT");
    expect(r.stats.attestations + r.stats.chats).toBe(0);
  });

  it("refuses an over-size request without sending it", async () => {
    const { r, c } = setup();
    expect(await codeOf(c.chat(msg("x".repeat(900 * 1024))))).toBe("E_TOO_LARGE");
    expect(r.stats.chats).toBe(0);
  });
});

describe("PrivateClient — receipt verification", () => {
  const mismatch: [string, Partial<Behaviour>][] = [
    ["th", { mutateReceipt: (rc) => ({ ...rc, th: "ab".repeat(32) }) }],
    ["req_hash", { mutateReceipt: (rc) => ({ ...rc, req_hash: "ab".repeat(32) }) }],
    ["resp_hash", { mutateReceipt: (rc) => ({ ...rc, resp_hash: "ab".repeat(32) }) }],
    ["compose_hash", { mutateReceipt: (rc) => ({ ...rc, compose_hash: "ab".repeat(32) }) }],
    ["key_hash", { mutateReceipt: (rc) => ({ ...rc, key_hash: "ab".repeat(32) }) }],
  ];
  for (const [field, b] of mismatch) {
    it(`signed receipt with wrong ${field} → E_RECEIPT_MISMATCH`, async () => {
      const { c } = setup(b);
      expect(await codeOf(c.chat(msg()))).toBe("E_RECEIPT_MISMATCH");
    });
  }

  it("flipped signature → E_RECEIPT_SIG", async () => {
    const { c } = setup({ sig: (s) => (s[0] === "0" ? "1" : "0") + s.slice(1) });
    expect(await codeOf(c.chat(msg()))).toBe("E_RECEIPT_SIG");
  });

  it("signature by a non-attested key → E_RECEIPT_SIG", async () => {
    const { c } = setup({ wrongSigner: true });
    expect(await codeOf(c.chat(msg()))).toBe("E_RECEIPT_SIG");
  });

  it("malformed receipt / sig → E_RECEIPT_SIG", async () => {
    for (const fp of [
      (rc: object, s: string) => ({ type: "receipt", receipt: { ...rc, extra: 1 }, sig: s }),
      (rc: object, s: string) => ({ type: "receipt", receipt: rc, sig: s.toUpperCase() }),
      (rc: object) => ({ type: "receipt", receipt: rc }),
      (_rc: object, s: string) => ({ type: "receipt", receipt: null, sig: s }),
    ]) {
      const { c } = setup({ finalPayload: fp });
      expect(await codeOf(c.chat(msg()))).toBe("E_RECEIPT_SIG");
    }
  });

  it("final error frame → E_UPSTREAM", async () => {
    const { c } = setup({ finalError: true });
    expect(await codeOf(c.chat(msg()))).toBe("E_UPSTREAM");
  });

  it("unknown final frame type → E_BAD_RESPONSE", async () => {
    const { c } = setup({ finalPayload: () => ({ type: "delta", content: "x" }) });
    expect(await codeOf(c.chat(msg()))).toBe("E_BAD_RESPONSE");
  });
});

describe("PrivateClient — stream integrity", () => {
  it("missing final frame → E_TRUNCATED (deltas only for decrypted frames)", async () => {
    const { c } = setup({ dropFinal: true });
    const deltas: string[] = [];
    expect(await codeOf(c.chat(msg(), { onDelta: (d) => deltas.push(d) }))).toBe("E_TRUNCATED");
    expect(deltas).toEqual(["Hel", "lo, ", "wörld 🌍", ""]);
  });

  it("flipped ciphertext byte → E_DECRYPT, nothing from that frame or later surfaces", async () => {
    const { c } = setup({ flipFrame: 1 });
    const deltas: string[] = [];
    expect(await codeOf(c.chat(msg(), { onDelta: (d) => deltas.push(d) }))).toBe("E_DECRYPT");
    expect(deltas).toEqual(["Hel"]);
  });

  it("reordered, duplicated, or fin-flagged mid-stream frames are rejected", async () => {
    expect(await codeOf(setup({ swapFrames: true }).c.chat(msg()))).toBe("E_DECRYPT");
    expect(await codeOf(setup({ duplicateFrame: 0 }).c.chat(msg()))).toBe("E_DECRYPT");
    // A delta sealed as fin=1 is authenticated as the final frame but is not a receipt.
    expect(await codeOf(setup({ finOnFrame: 1 }).c.chat(msg()))).toBe("E_BAD_RESPONSE");
  });

  it("malformed frame encodings → E_DECRYPT", async () => {
    for (const ct of ["!!!!", "AAAA AAAA", "AAA", "AAB=" /* non-canonical trailing bits */, ""]) {
      expect(await codeOf(setup({ rawCt: { frame: 0, ct } }).c.chat(msg())), ct).toBe("E_DECRYPT");
    }
  });

  it("invalid UTF-8 in the event stream → E_DECRYPT", async () => {
    const { c } = setup({
      chunker: (b) => [b.slice(0, 10), Uint8Array.of(0xff), b.slice(10)],
    });
    expect(await codeOf(c.chat(msg()))).toBe("E_DECRYPT");
  });

  it("a stalled stream times out as E_TRUNCATED", async () => {
    const r = makeFakeRouter();
    r.behaviour.hangAfterDeltas = true;
    const c = new PrivateClient({
      routerUrl: "http://x.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: r.fetch,
      timeouts: { idleMs: 200 },
    });
    expect(await codeOf(c.chat(msg()))).toBe("E_TRUNCATED");
  });

  it("wrong content type → E_BAD_RESPONSE", async () => {
    expect(await codeOf(setup({ contentType: "application/json" }).c.chat(msg()))).toBe("E_BAD_RESPONSE");
  });

  it("propagates an onDelta exception unchanged", async () => {
    const { c } = setup();
    const boom = new Error("boom");
    await expect(c.chat(msg(), { onDelta: () => { throw boom; } })).rejects.toBe(boom);
  });
});

describe("PrivateClient — pre-decrypt HTTP errors", () => {
  const cases: [number, string, string][] = [
    [400, '{"error":"E_BAD_REQUEST"}', "E_BAD_REQUEST"],
    [400, '{"error":"E_DECRYPT"}', "E_DECRYPT"],
    [413, '{"error":"E_TOO_LARGE"}', "E_TOO_LARGE"],
    [503, '{"error":"E_UPSTREAM"}', "E_UPSTREAM"],
    [500, '{"error":"E_DECRYPT"}', "E_BAD_RESPONSE"], // code/status mismatch: body not trusted
    [400, "garbage", "E_BAD_REQUEST"],
    [404, '{"error":"E_NOT_ANCHORED"}', "E_BAD_RESPONSE"],
  ];
  for (const [status, body, code] of cases) {
    it(`${status} ${body} → ${code}`, async () => {
      const { c } = setup({ httpError: { status, body } });
      expect(await codeOf(c.chat(msg()))).toBe(code);
    });
  }
});

describe("PrivateClient — configuration", () => {
  it("rejects bad router URLs and roots", () => {
    const r = makeFakeRouter();
    const base = { registry: r.registry, trustedRoot: r.root.publicKey };
    expect(() => new PrivateClient({ ...base, routerUrl: "ftp://x" })).toThrow(PlrError);
    expect(() => new PrivateClient({ ...base, routerUrl: "http://u:p@x" })).toThrow(PlrError);
    expect(() => new PrivateClient({ ...base, routerUrl: "not a url" })).toThrow(PlrError);
    expect(() => new PrivateClient({ ...base, routerUrl: "http://x", trustedRoot: new Uint8Array(64) })).toThrow(PlrError);
  });
});
