// Regression tests for review findings on the client:
//  - registry RPC over plain http to a remote host (forgeable policy answers) is refused;
//  - receipt inclusion proofs are positioned with the CHAIN's anchor (first_seq/count), never the exit's;
//  - non-integer JSON number literals (`3.0`, `3e0`) never pass as integers (same as the Rust contract).
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  MockRoot,
  MockVerifier,
  PlrError,
  merkleProof,
  merkleRoot,
  parseJsonIntegers,
  parseQuote,
  fromHex,
  toHex,
  verifyAttestation,
  verifyEventLog,
  vpnReceiptLeaf,
  type AnchorRecord,
  type RegistryReader,
  type VpnReceipt,
} from "@plr/shared";
import { ConfigError, NearRegistry, VpnClient, checkRpcUrl, isLoopbackHost, loadVpnConfig, runCli, verifyVpnReceiptAnchored } from "../src/index.js";
import { startFakeExit } from "./fake-exit.js";

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
  const env = (rpc: string) => ({ PLR_NEAR_RPC: rpc, PLR_VPN_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: root });

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
    expect(() => loadVpnConfig(env("http://rpc.example:3030"))).toThrow(ConfigError);
    expect(loadVpnConfig(env("https://rpc.example")).rpcUrl).toBe("https://rpc.example");
    expect(loadVpnConfig({ PLR_VPN_REGISTRY: "registry.test.near", PLR_TRUSTED_ROOT: root }).rpcUrl).toBe("http://127.0.0.1:3030");
    const err: string[] = [];
    const code = await runCli(["vpn", "verify"], env("http://rpc.example:3030"), { out: () => undefined, err: (s) => err.push(s) });
    expect(code).toBe(2);
    expect(err.join("\n")).toContain("PLR_NEAR_RPC");
  });
});

// ------------------------------------------------------------------------------------------ anchored proofs

describe("verifyAnchored: positions come from the chain, never from the exit", () => {
  /** `n` session receipts of one instance, an on-chain anchor over them, and the exit's (untrusted) proof reply. */
  function anchoredStack(n: number, o: { firstSeq?: number; otherKeyHash?: boolean } = {}) {
    const keyHash = "a1".repeat(32);
    const receipts: VpnReceipt[] = [];
    for (let seq = 0; seq < n; seq++) {
      receipts.push({ v: 1, th: toHex(new Uint8Array(32).fill(seq + 1)), compose_hash: "c0".repeat(32), key_hash: keyHash, seq, ts_open_ms: 1_000 + seq, ts_close_ms: 2_000 + seq });
    }
    const firstSeq = o.firstSeq ?? 0;
    const batch = receipts.slice(firstSeq);
    const leaves = batch.map(vpnReceiptLeaf);
    const root = toHex(merkleRoot(leaves));
    const anchors: AnchorRecord[] = [
      { id: 0, key_hash: "ee".repeat(32), root: "ab".repeat(32), first_seq: 0, count: 5, at_ms: 1 }, // another instance
      { id: 1, key_hash: o.otherKeyHash ? "ee".repeat(32) : keyHash, root, first_seq: firstSeq, count: batch.length, at_ms: 2 },
    ];
    const chain: RegistryReader = {
      chain: "memory",
      contractId: "registry.test.near",
      getRoot: async () => ({ kind: "MOCK", p256: "11".repeat(64) }),
      isComposeAllowed: async () => true,
      isOsAllowed: async () => true,
      getInstance: async () => null,
      getAnchor: async (id) => anchors[id] ?? null,
    };
    /** A self-consistent reply; for a seq outside the batch the exit "proves" leaf 0 and claims it is ours. */
    const honest = (seq: number): Record<string, unknown> => {
      const index = Math.max(0, seq - firstSeq);
      return { anchor_id: 1, first_seq: firstSeq, count: batch.length, index, root, proof: merkleProof(leaves, index).map(toHex) };
    };
    const check = (rc: VpnReceipt, reply: unknown = honest(rc.seq), registry: RegistryReader = chain) =>
      verifyVpnReceiptAnchored({ receipt: rc, reply, registry });
    return { receipts, leaves, root, check, honest };
  }

  it("accepts an honest proof and reports the chain's position", async () => {
    const s = anchoredStack(5);
    for (const rc of s.receipts) {
      expect(await s.check(rc)).toMatchObject({ anchorId: 1, root: s.root, firstSeq: 0, count: 5, index: rc.seq });
    }
  });

  it("exit-supplied count / index / first_seq / root that disagree with the chain → E_ANCHOR_MISMATCH", async () => {
    const s = anchoredStack(5);
    const rc = s.receipts[4]!;
    const tampered = (f: (b: Record<string, unknown>) => void): Record<string, unknown> => {
      const b = { ...s.honest(rc.seq) };
      f(b);
      return b;
    };
    // Classic RFC 6962 confusion: a proof for the last leaf of a 4-leaf tree claimed for size 4 / index 3.
    expect(await codeOf(s.check(rc, tampered((b) => {
      b.count = 4;
      b.index = 3;
      b.proof = merkleProof(s.leaves.slice(0, 4), 3).map(toHex);
    })))).toBe("E_ANCHOR_MISMATCH");
    expect(await codeOf(s.check(rc, tampered((b) => { b.index = 3; })))).toBe("E_ANCHOR_MISMATCH");
    expect(await codeOf(s.check(rc, tampered((b) => { b.first_seq = 1; })))).toBe("E_ANCHOR_MISMATCH");
    expect(await codeOf(s.check(rc, tampered((b) => { b.root = "cd".repeat(32); })))).toBe("E_ANCHOR_MISMATCH");
    expect(await codeOf(s.check(rc, tampered((b) => { b.anchor_id = 0; })))).toBe("E_ANCHOR_MISMATCH"); // another instance's anchor
    expect(await codeOf(s.check(rc, tampered((b) => { b.proof = (b.proof as string[]).map(() => "00".repeat(32)); })))).toBe("E_ANCHOR_MISMATCH");
    expect(await codeOf(s.check(rc, tampered((b) => { b.anchor_id = 7; })))).toBe("E_NOT_ANCHORED"); // not on chain
    expect(await codeOf(s.check(rc, tampered((b) => { b.extra = 1; })))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(s.check(rc, tampered((b) => { b.index = 4.0000001; })))).toBe("E_BAD_RESPONSE");
  });

  it("a receipt outside the chain's [first_seq, first_seq+count) is rejected even with a self-consistent exit reply", async () => {
    const s = anchoredStack(4, { firstSeq: 2 }); // anchor covers seq 2..3
    expect(await codeOf(s.check(s.receipts[3]!))).toBe("NO_THROW");
    expect(await codeOf(s.check(s.receipts[0]!))).toBe("E_ANCHOR_MISMATCH");
    // Even if the exit rewrites first_seq/index to make seq 0 look like index 0 of a batch starting at 0.
    expect(await codeOf(s.check(s.receipts[0]!, { ...s.honest(2), first_seq: 0, index: 0 }))).toBe("E_ANCHOR_MISMATCH");
  });

  it("an anchor of another instance never validates our receipt", async () => {
    const s = anchoredStack(3, { otherKeyHash: true });
    expect(await codeOf(s.check(s.receipts[0]!))).toBe("E_ANCHOR_MISMATCH");
  });

  it("the pure verifier also maps registry failures to E_REGISTRY_UNAVAILABLE", async () => {
    const s = anchoredStack(1);
    const broken: RegistryReader = {
      chain: "x", contractId: "x", getRoot: async () => ({ kind: "MOCK", p256: "11".repeat(64) }), isComposeAllowed: async () => true,
      isOsAllowed: async () => true, getInstance: async () => null, getAnchor: async () => { throw new Error("down"); },
    };
    expect(await codeOf(s.check(s.receipts[0]!, s.honest(0), broken))).toBe("E_REGISTRY_UNAVAILABLE");
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
    const X = await startFakeExit();
    closers.push(X.close);
    for (const lit of ["3.0", "3e0", "0.3e1"]) {
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const text = (await (await fetch(`${X.url}/v1/attestation?nonce=${toHex(nonce)}`)).text()).replace('"imr":3,', `"imr":${lit},`);
      expect(text).toContain(`"imr":${lit},`);
      const bundle = parseJsonIntegers(text) as never;
      const verdict = verifyAttestation({ bundle, nonce, verifier: new MockVerifier(X.root.publicKey), registry: X.registry, trustedRoot: X.root.publicKey });
      expect(await codeOf(verdict), lit).toBe("E_EVENT_LOG");
    }
  });

  it("MemoryRegistry sanity: honest attestation still verifies", async () => {
    const X = await startFakeExit();
    closers.push(X.close);
    const c = new VpnClient({ exitUrl: X.url, registry: X.registry, trustedRoot: X.root.publicKey });
    await expect(c.attest()).resolves.toBeTruthy();
  });
});
