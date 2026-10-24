// Regression tests for review findings on the client:
//  - registry RPC over plain http to a remote host (forgeable policy answers) is refused;
//  - `plr chat` reads the prompt from stdin;
//  - receipt inclusion proofs are positioned with the CHAIN's anchor (first_seq/count), never the router's;
//  - non-integer JSON number literals (`3.0`, `3e0`) never pass as integers (same as the Rust contract).
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Readable } from "node:stream";
import {
  MemoryRegistry,
  MockRoot,
  PlrError,
  merkleProof,
  merkleRoot,
  parseJsonIntegers,
  parseQuote,
  fromHex,
  receiptLeaf,
  toHex,
  verifyEventLog,
  type AnchorRecord,
  type Receipt,
  type RegistryReader,
} from "@plr/shared";
import {
  ConfigError,
  MAX_STDIN_PROMPT,
  NearRegistry,
  PrivateClient,
  checkRpcUrl,
  isLoopbackHost,
  loadConfig,
  readStdinText,
  runCli,
  verifyReceiptAnchored,
} from "../src/index.js";
import { makeFakeRouter, type FakeRouter } from "./fake-router.js";
import { registryHandler, startFakeRpc } from "./fake-rpc.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    return e instanceof PlrError ? e.code : `non-PlrError: ${String(e)}`;
  }
  return "NO_THROW";
};

// ------------------------------------------------------------------------------------------ registry transport

describe("registry RPC transport (the RPC answers decide checks 3, 8, 9)", () => {
  const root = toHex(MockRoot.generate().publicKey);
  const env = (rpc: string) => ({ PLR_NEAR_RPC: rpc, PLR_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: root });

  it("refuses plain http to any non-loopback host", () => {
    for (const u of [
      "http://rpc.example:3030",
      "http://10.0.0.5:3030",
      "http://192.168.1.2/",
      "http://127.0.0.1.evil.example/",
      "http://localhost.evil.example/",
      "http://[::ffff:7f00:1]/",
      "http://0.0.0.0:3030",
      "ws://127.0.0.1:3030",
      "file:///tmp/rpc",
      "https://user:pw@rpc.example/",
    ]) {
      expect(() => new NearRegistry({ rpcUrl: u, contractId: "registry.test.near" }), u).toThrow(PlrError);
      expect(() => checkRpcUrl(u), u).toThrow(/E_BAD_INPUT/);
    }
  });

  it("accepts https anywhere and http only to loopback", () => {
    for (const u of ["https://rpc.mainnet.near.org", "http://127.0.0.1:3030", "http://127.1.2.3:3030", "http://localhost:3030", "http://[::1]:3030"]) {
      expect(() => new NearRegistry({ rpcUrl: u, contractId: "registry.test.near" }), u).not.toThrow();
    }
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("128.0.0.1")).toBe(false);
    expect(isLoopbackHost("127.0.0.256")).toBe(false);
  });

  it("the CLI rejects PLR_NEAR_RPC=http://<remote> as a config error", async () => {
    expect(() => loadConfig(env("http://rpc.example:3030"))).toThrow(ConfigError);
    expect(loadConfig(env("https://rpc.example")).rpcUrl).toBe("https://rpc.example");
    expect(loadConfig({ PLR_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: root }).rpcUrl).toBe("http://127.0.0.1:3030");
    const err: string[] = [];
    const code = await runCli(["verify"], env("http://rpc.example:3030"), { out: () => undefined, err: (s) => err.push(s) }, () => undefined);
    expect(code).toBe(2);
    expect(err.join("\n")).toContain("PLR_NEAR_RPC");
  });
});

// ------------------------------------------------------------------------------------------ plr chat via stdin

describe("plr chat reads the prompt from stdin", () => {
  async function stack() {
    const r = makeFakeRouter();
    const srv = await r.listen();
    const rpc = await startFakeRpc(registryHandler(r.registry));
    closers.push(srv.close, rpc.close);
    const env = { PLR_ROUTER_URL: srv.url, PLR_NEAR_RPC: rpc.url, PLR_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: toHex(r.root.publicKey) };
    return { r, env };
  }
  const io = () => {
    const err: string[] = [];
    const deltas: string[] = [];
    return { err, deltas, io: { out: () => undefined, err: (s: string) => err.push(s) }, write: (s: string) => deltas.push(s) };
  };

  it("with no argument and with '-'; one trailing newline is dropped", async () => {
    for (const argv of [["chat"], ["chat", "-"]]) {
      const { r, env } = await stack();
      const t = io();
      expect(await runCli(argv, env, t.io, t.write, async () => "secret from stdin\n")).toBe(0);
      expect(JSON.parse(r.stats.plaintexts[0]!).messages).toEqual([{ role: "user", content: "secret from stdin" }]);
      expect(t.deltas.join("")).toBe("Hello, wörld 🌍\n");
    }
  });

  it("empty, unreadable or oversized stdin is a usage error and nothing is sent", async () => {
    const { r, env } = await stack();
    for (const read of [async () => "", async () => "  \n", async () => { throw new Error("EIO"); }]) {
      const t = io();
      expect(await runCli(["chat"], env, t.io, t.write, read)).toBe(2);
    }
    expect(r.stats.chats).toBe(0);
    await expect(readStdinText(Readable.from([Buffer.alloc(MAX_STDIN_PROMPT + 1, 0x61)]))).rejects.toThrow();
    await expect(readStdinText(Readable.from([Buffer.from([0xff, 0xfe])]))).rejects.toThrow(); // not UTF-8
    expect(await readStdinText(Readable.from([Buffer.from("héllo")]))).toBe("héllo");
  });

  it("never reads stdin when the configuration is invalid", async () => {
    let read = false;
    const t = io();
    expect(await runCli(["chat"], {}, t.io, t.write, async () => { read = true; return "x"; })).toBe(2);
    expect(read).toBe(false);
  });

  it("help recommends stdin", async () => {
    const t = io();
    expect(await runCli(["--help"], {}, t.io, t.write)).toBe(2);
    expect(t.err.join("\n")).toMatch(/stdin/);
  });
});

// ------------------------------------------------------------------------------------------ anchored proofs

describe("verifyAnchored: positions come from the chain, never from the router", () => {
  /** A fake router that has served `n` receipts, an on-chain anchor over them, and a proof endpoint. */
  async function anchoredStack(n: number, o: { firstSeq?: number; otherKeyHash?: boolean } = {}) {
    const r: FakeRouter = makeFakeRouter();
    const client0 = new PrivateClient({ routerUrl: "http://router.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: r.fetch });
    const receipts: Receipt[] = [];
    for (let i = 0; i < n; i++) receipts.push((await client0.chat({ messages: [{ role: "user", content: `q${i}` }] })).receipt);
    const firstSeq = o.firstSeq ?? 0;
    const batch = receipts.slice(firstSeq);
    const leaves = batch.map(receiptLeaf);
    const root = toHex(merkleRoot(leaves));
    const anchors: AnchorRecord[] = [
      { id: 0, key_hash: "ee".repeat(32), root: "ab".repeat(32), first_seq: 0, count: 5, at_ms: 1 }, // another instance
      { id: 1, key_hash: o.otherKeyHash ? "ee".repeat(32) : r.keyHash, root, first_seq: firstSeq, count: batch.length, at_ms: 2 },
    ];
    const chain: RegistryReader = {
      chain: "memory",
      contractId: r.registry.contractId,
      verifiesOnChain: true, // tier A fixture (SPEC-CHAINS §2)
      getRegistrationQuote: async () => null,
      getRoot: () => r.registry.getRoot(),
      isComposeAllowed: (h) => r.registry.isComposeAllowed(h),
      isOsAllowed: (h) => r.registry.isOsAllowed(h),
      getInstance: (k) => r.registry.getInstance(k),
      getAnchor: async (id) => anchors[id] ?? null,
    };
    /** What the (untrusted) router answers on /v1/receipts/proof; tests tamper with it. */
    const honestReply = (seq: number): { status: number; body: unknown } => {
      // A self-consistent reply; for a seq outside the batch the router "proves" leaf 0 and claims it is ours.
      const index = Math.max(0, seq - firstSeq);
      return {
        status: 200,
        body: { anchor_id: 1, first_seq: firstSeq, count: batch.length, index, root, proof: merkleProof(leaves, index).map(toHex) },
      };
    };
    let reply = honestReply;
    const fetchFn: typeof fetch = async (input, init) => {
      const url = new URL(String(input instanceof Request ? input.url : input));
      if (url.pathname === "/v1/receipts/proof") {
        const { status, body } = reply(Number(url.searchParams.get("seq")));
        return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      }
      return r.fetch(input, init);
    };
    const client = new PrivateClient({ routerUrl: "http://router.test", registry: chain, trustedRoot: r.root.publicKey, fetch: fetchFn });
    return { r, client, receipts, leaves, root, anchors, setReply: (f: typeof reply) => { reply = f; }, honest: honestReply };
  }

  it("accepts an honest proof and reports the chain's position", async () => {
    const s = await anchoredStack(5);
    for (const rc of s.receipts) {
      const a = await s.client.verifyAnchored(rc);
      expect(a).toMatchObject({ anchorId: 1, root: s.root, firstSeq: 0, count: 5, index: rc.seq });
    }
  });

  it("router-supplied count / index / first_seq / root that disagree with the chain → E_ANCHOR_MISMATCH", async () => {
    const s = await anchoredStack(5);
    const base = s.honest;
    const rc = s.receipts[4]!;
    const tamper = (f: (b: Record<string, unknown>) => void) =>
      s.setReply((seq) => {
        const r0 = base(seq);
        const b = { ...(r0.body as Record<string, unknown>) };
        f(b);
        return { status: 200, body: b };
      });
    // Classic RFC 6962 confusion: a proof for the last leaf of a 4-leaf tree claimed for size 4 / index 3.
    tamper((b) => {
      b.count = 4;
      b.index = 3;
      b.proof = merkleProof(s.leaves.slice(0, 4), 3).map(toHex);
    });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_ANCHOR_MISMATCH");
    tamper((b) => { b.index = 3; });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_ANCHOR_MISMATCH");
    tamper((b) => { b.first_seq = 1; });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_ANCHOR_MISMATCH");
    tamper((b) => { b.root = "cd".repeat(32); });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_ANCHOR_MISMATCH");
    tamper((b) => { b.anchor_id = 0; }); // another instance's anchor
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_ANCHOR_MISMATCH");
    tamper((b) => { b.proof = (b.proof as string[]).map(() => "00".repeat(32)); });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_ANCHOR_MISMATCH");
    tamper((b) => { b.anchor_id = 7; }); // not on chain
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_NOT_ANCHORED");
    tamper((b) => { b.extra = 1; });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_BAD_RESPONSE");
    tamper((b) => { b.index = 4.0000001; });
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_BAD_RESPONSE");
    s.setReply(() => ({ status: 404, body: { error: "E_NOT_ANCHORED" } }));
    expect(await codeOf(s.client.verifyAnchored(rc))).toBe("E_NOT_ANCHORED");
  });

  it("a receipt outside the chain's [first_seq, first_seq+count) is rejected even with a self-consistent router reply", async () => {
    const s = await anchoredStack(4, { firstSeq: 2 }); // anchor covers seq 2..3
    expect(await codeOf(s.client.verifyAnchored(s.receipts[3]!))).toBe("NO_THROW");
    expect(await codeOf(s.client.verifyAnchored(s.receipts[0]!))).toBe("E_ANCHOR_MISMATCH");
    // Even if the router rewrites first_seq/index to make seq 0 look like index 0 of a batch starting at 0.
    s.setReply(() => ({ status: 200, body: { ...(s.honest(2).body as object), first_seq: 0, index: 0 } }));
    expect(await codeOf(s.client.verifyAnchored(s.receipts[0]!))).toBe("E_ANCHOR_MISMATCH");
  });

  it("an anchor of another instance never validates our receipt", async () => {
    const s = await anchoredStack(3, { otherKeyHash: true });
    expect(await codeOf(s.client.verifyAnchored(s.receipts[0]!))).toBe("E_ANCHOR_MISMATCH");
  });

  it("the pure verifier also maps registry failures to E_REGISTRY_UNAVAILABLE", async () => {
    const s = await anchoredStack(1);
    const broken: RegistryReader = { ...s.r.registry, chain: "x", contractId: "x", getAnchor: async () => { throw new Error("down"); } } as unknown as RegistryReader;
    const reply = s.honest(0).body;
    expect(await codeOf(verifyReceiptAnchored({ receipt: s.receipts[0]!, reply, registry: broken }))).toBe("E_REGISTRY_UNAVAILABLE");
  });
});

// ------------------------------------------------------------------------------------------ JSON number literals

describe("non-integer JSON number literals never pass as integers (TS == Rust)", () => {
  it("parseJsonIntegers keeps integer literals and poisons every other number", () => {
    const v = parseJsonIntegers('{"a":3,"b":3.0,"c":3e0,"d":-0,"e":9007199254740993,"f":"3.0","g":[1,2.5],"h":-7}') as Record<string, unknown>;
    expect(v.a).toBe(3);
    expect(v.h).toBe(-7);
    for (const k of ["b", "c", "d", "e"]) expect(Number.isNaN(v[k]), k).toBe(true);
    expect(v.f).toBe("3.0");
    expect(Number.isNaN((v.g as number[])[1])).toBe(true);
    expect(() => parseJsonIntegers("{")).toThrow(SyntaxError);
  });

  it("cross-implementation vectors (contracts/near/fixtures/vectors.json, also run by the Rust tests)", () => {
    const fx = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../contracts/near/fixtures/vectors.json"), "utf8")) as {
      registrations: { name: string; quote: string }[];
      number_literals: { name: string; expect: string; event_log_json: string }[];
    };
    const ok = fx.registrations.find((c) => c.name === "ok_mock_tdx_attester")!;
    const rtmr3 = parseQuote(fromHex(ok.quote)).report.rtmr[3];
    expect(fx.number_literals.length).toBeGreaterThanOrEqual(5);
    for (const c of fx.number_literals) {
      let got = "ok";
      try {
        verifyEventLog(parseJsonIntegers(c.event_log_json) as never, rtmr3);
      } catch (e) {
        got = e instanceof PlrError ? e.code : "throw";
      }
      expect(got, c.name).toBe(c.expect);
    }
  });

  it("an attestation whose event log says imr 3.0 / 3e0 is refused with E_EVENT_LOG", async () => {
    for (const lit of ["3.0", "3e0", "0.3e1"]) {
      const r = makeFakeRouter();
      const f: typeof fetch = async (input, init) => {
        const res = await r.fetch(input, init);
        if (!new URL(String(input)).pathname.startsWith("/v1/attestation")) return res;
        const text = (await res.text()).replace('"imr":3,', `"imr":${lit},`);
        expect(text).toContain(`"imr":${lit},`);
        return new Response(text, { status: res.status, headers: res.headers });
      };
      const c = new PrivateClient({ routerUrl: "http://router.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: f });
      expect(await codeOf(c.attest()), lit).toBe("E_EVENT_LOG");
      expect(r.stats.chats).toBe(0);
    }
  });

  it("MemoryRegistry sanity: honest attestation still verifies", async () => {
    const r = makeFakeRouter();
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: r.registry as MemoryRegistry, trustedRoot: r.root.publicKey, fetch: r.fetch });
    await expect(c.attest()).resolves.toBeTruthy();
  });
});
