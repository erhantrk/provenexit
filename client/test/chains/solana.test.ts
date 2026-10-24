// SolanaRegistry (SPEC-CHAINS §11): account decoding against the contracts/solana layouts, PDA seeds, fail-closed reads.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";
import { PlrError, toHex } from "@plr/shared";
import {
  SOLANA_LAYOUT, SolanaRegistry, decodeSolanaInstance, parseSolanaContractId, parseSolanaKey, solanaErrorCode, u64le,
} from "../../src/chains/solana.js";
import { startFakeSolanaRpc, type FakeSolanaRpc } from "./solana-fake-rpc.js";

const PROGRAM = Keypair.generate().publicKey;
const STATE = Keypair.generate().publicKey;
const OWNER = Keypair.generate().publicKey;
const OPERATOR = Keypair.generate().publicKey;
const SYSTEM = "11111111111111111111111111111111";
const h = (b: number) => toHex(new Uint8Array(32).fill(b));
const pda = (seed: string, x: Uint8Array) => PublicKey.findProgramAddressSync([Buffer.from(seed), STATE.toBuffer(), x], PROGRAM)[0].toBase58();
const hx = (s: string) => Buffer.from(s, "hex");

function stateData(o: { kind?: number; anchors?: number; pending?: PublicKey } = {}): Uint8Array {
  const b = Buffer.alloc(SOLANA_LAYOUT.STATE_LEN);
  b[0] = 1;
  OWNER.toBuffer().copy(b, 1);
  if (o.pending) {
    b[33] = 1;
    o.pending.toBuffer().copy(b, 34);
  }
  b[66] = o.kind ?? 1;
  b.fill(0xab, 67, 131);
  b.writeBigUInt64LE(3_600_000n, 131);
  b.writeBigUInt64LE(BigInt(o.anchors ?? 0), 139);
  return b;
}
const item = (tag: number, allowed: boolean) => Uint8Array.of(tag, allowed ? 1 : 0);
function opData(org: string | null): Uint8Array {
  const b = Buffer.alloc(SOLANA_LAYOUT.OPERATOR_LEN);
  b[0] = 4;
  if (org !== null) {
    b[1] = 1;
    b[2] = org.length;
    b.write(org, 3, "utf8");
  }
  return b;
}
function instData(o: { expires: number; nextSeq?: number; operator?: PublicKey }): Uint8Array {
  const b = Buffer.alloc(SOLANA_LAYOUT.INSTANCE_LEN);
  b[0] = 5;
  [h(0x11), h(0x22), h(0xc0), h(0x05)].forEach((x, i) => hx(x).copy(b, 1 + 32 * i));
  (o.operator ?? OPERATOR).toBuffer().copy(b, 129);
  b.writeBigUInt64LE(1000n, 161);
  b.writeBigUInt64LE(BigInt(o.expires), 169);
  b.writeBigUInt64LE(BigInt(o.nextSeq ?? 7), 177);
  b.fill(0x9c, SOLANA_LAYOUT.QUOTE_OFF);
  return b;
}
function anchorData(): Uint8Array {
  const b = Buffer.alloc(SOLANA_LAYOUT.ANCHOR_LEN);
  b[0] = 6;
  hx(h(0x33)).copy(b, 1);
  hx(h(0x44)).copy(b, 33);
  b.writeBigUInt64LE(10n, 65);
  b.writeBigUInt64LE(5n, 73);
  b.writeBigUInt64LE(1234n, 81);
  b.fill(0x5a, 89);
  return b;
}

let rpc: FakeSolanaRpc;
const NOW = 1_700_000_000_000;
let R: SolanaRegistry;
const put = (k: string, data: Uint8Array, owner = PROGRAM.toBase58()) => rpc.accounts.set(k, { owner, data });

beforeAll(async () => {
  rpc = await startFakeSolanaRpc();
});
afterAll(async () => rpc.close());
beforeEach(() => {
  rpc.accounts.clear();
  rpc.raw = undefined;
  rpc.calls.length = 0;
  R = new SolanaRegistry({ rpcUrl: rpc.url, programId: PROGRAM.toBase58(), registry: STATE.toBase58(), now: () => NOW });
  put(STATE.toBase58(), stateData({ anchors: 2 }));
});

describe("SolanaRegistry", () => {
  it("is tier B with the §3 contract id", () => {
    expect(R.chain).toBe("solana");
    expect(R.verifiesOnChain).toBe(false);
    expect(R.contractId).toBe(`solana:${STATE.toBase58()}`);
    expect(parseSolanaContractId(R.contractId)).toBe(STATE.toBase58());
    for (const bad of ["solana:", "solana:0OIl", `evm:${STATE.toBase58()}`, `solana:${STATE.toBase58()}x`, 5]) expect(parseSolanaContractId(bad)).toBeNull();
  });

  it("validates its options", () => {
    const ok = { rpcUrl: rpc.url, programId: PROGRAM.toBase58(), registry: STATE.toBase58() };
    expect(() => new SolanaRegistry({ ...ok, rpcUrl: "http://example.com:8899" })).toThrow(PlrError);
    expect(() => new SolanaRegistry({ ...ok, rpcUrl: "https://u:p@example.com" })).toThrow(PlrError);
    expect(() => new SolanaRegistry({ ...ok, programId: "not-base58!" })).toThrow(PlrError);
    expect(() => new SolanaRegistry({ ...ok, registry: "" })).toThrow(PlrError);
    expect(() => new SolanaRegistry({ ...ok, commitment: "recent" as never })).toThrow(PlrError);
    expect(() => new SolanaRegistry({ ...ok, rpcUrl: "https://rpc.example.com" })).not.toThrow();
  });

  it("derives the §11 PDAs", () => {
    expect(R.pdas.compose(h(1)).toBase58()).toBe(pda("compose", hx(h(1))));
    expect(R.pdas.os(h(1)).toBase58()).toBe(pda("os", hx(h(1))));
    expect(R.pdas.operator(OPERATOR).toBase58()).toBe(pda("op", OPERATOR.toBuffer()));
    expect(R.pdas.instance(h(2)).toBase58()).toBe(pda("inst", hx(h(2))));
    expect(R.pdas.anchor(258).toBase58()).toBe(pda("anchor", Buffer.from([2, 1, 0, 0, 0, 0, 0, 0])));
    expect(toHex(u64le(258))).toBe("0201000000000000");
    expect(() => R.pdas.compose("AB".repeat(32))).toThrow(PlrError);
  });

  it("reads the root, allowlists and anchor count from the state and item accounts", async () => {
    expect(await R.getRoot()).toEqual({ kind: "MOCK", p256: "ab".repeat(64) });
    put(STATE.toBase58(), stateData({ kind: 2, anchors: 2 }));
    expect((await R.getRoot()).kind).toBe("INTEL");
    expect(await R.anchorCount()).toBe(2);
    put(R.pdas.compose(h(1)).toBase58(), item(2, true));
    put(R.pdas.compose(h(2)).toBase58(), item(2, false));
    put(R.pdas.os(h(1)).toBase58(), item(3, true));
    expect(await R.isComposeAllowed(h(1))).toBe(true);
    expect(await R.isComposeAllowed(h(2))).toBe(false);
    expect(await R.isComposeAllowed(h(3))).toBe(false);
    expect(await R.isOsAllowed(h(1))).toBe(true);
    expect(await R.isOsAllowed(h(2))).toBe(false);
    expect(await R.isComposeAllowed("00".repeat(32))).toBe(false);
    expect(await R.isComposeAllowed("zz")).toBe(false);
    // the compose PDA of h(1) never satisfies an OS query (different seed), and tags are checked
    put(R.pdas.os(h(4)).toBase58(), item(2, true));
    await expect(R.isOsAllowed(h(4))).rejects.toThrow(/malformed/);
    // reads use base64 + the configured commitment
    expect(rpc.calls.at(-1)!.params[1]).toEqual({ encoding: "base64", commitment: "confirmed" });
  });

  it("returns the instance with its live org, the stored quote and anchors with sig", async () => {
    const kh = h(0x77);
    expect(await R.getInstance(kh)).toBeNull();
    expect(await R.getRegistrationQuote(kh)).toBeNull();
    put(R.pdas.instance(kh).toBase58(), instData({ expires: NOW + 1 }));
    put(R.pdas.operator(OPERATOR).toBase58(), opData("org-a"));
    expect(await R.getInstance(kh)).toEqual({
      compose_hash: h(0xc0), os_measurement: h(0x05), x25519: h(0x11), ed25519: h(0x22), operator: OPERATOR.toBase58(),
      org_id: "org-a", registered_at_ms: 1000, expires_at_ms: NOW + 1, next_seq: 7,
    });
    expect(await R.getOperator(OPERATOR.toBase58())).toBe("org-a");
    // SPEC-CHAINS §1: a revoked operator's instances are not accepted (the owner cuts a rogue operator off at once)
    put(R.pdas.operator(OPERATOR).toBase58(), opData(null));
    expect(await R.getInstance(kh)).toBeNull();
    rpc.accounts.delete(R.pdas.operator(OPERATOR).toBase58());
    expect(await R.getInstance(kh)).toBeNull();
    const q = (await R.getRegistrationQuote(kh, new Uint8Array([1, 2, 3])))!;
    expect(q.length).toBe(828);
    expect(q.every((b) => b === 0x9c)).toBe(true);
    // expired ⇒ null
    put(R.pdas.instance(kh).toBase58(), instData({ expires: NOW }));
    expect(await R.getInstance(kh)).toBeNull();

    expect(await R.getAnchor(1)).toBeNull();
    put(R.pdas.anchor(1).toBase58(), anchorData());
    expect(await R.getAnchor(1)).toEqual({ id: 1, key_hash: h(0x33), root: h(0x44), first_seq: 10, count: 5, at_ms: 1234, sig: "5a".repeat(64) });
    expect(await R.getAnchor(-1)).toBeNull();
    expect(await R.getAnchor(1.5)).toBeNull();
  });

  it("fails closed on foreign, malformed or unavailable data", async () => {
    const kh = h(0x78);
    put(R.pdas.instance(kh).toBase58(), instData({ expires: NOW + 1 }), Keypair.generate().publicKey.toBase58());
    await expect(R.getInstance(kh)).rejects.toThrow(/not owned/);
    put(R.pdas.instance(kh).toBase58(), instData({ expires: NOW + 1 }).subarray(0, 1000));
    await expect(R.getInstance(kh)).rejects.toThrow(/malformed/);
    // a pre-funded (system-owned, empty) PDA is simply "not set"
    put(R.pdas.instance(kh).toBase58(), new Uint8Array(0), SYSTEM);
    expect(await R.getInstance(kh)).toBeNull();
    // u64 beyond 2^53
    const big = Buffer.from(instData({ expires: NOW + 1 }));
    big.writeBigUInt64LE(2n ** 60n, 177);
    put(R.pdas.instance(kh).toBase58(), big);
    await expect(R.getInstance(kh)).rejects.toThrow(/range/);
    // bad operator record
    const bad = Buffer.from(opData("org-a"));
    bad[2] = 0;
    put(R.pdas.operator(OPERATOR).toBase58(), bad);
    await expect(R.getOperator(OPERATOR.toBase58())).rejects.toThrow(/malformed/);
    expect(await R.getOperator("nope")).toBeNull();
    // missing state
    rpc.accounts.delete(STATE.toBase58());
    await expect(R.getRoot()).rejects.toThrow(/not found/);
    // RPC error / HTTP error / malformed reply
    rpc.raw = () => ({ status: 200, body: { jsonrpc: "2.0", id: 1, error: { code: -1, message: "boom" } } });
    await expect(R.isComposeAllowed(h(1))).rejects.toThrow(/RPC error/);
    rpc.raw = () => ({ status: 500, body: "x" });
    await expect(R.isComposeAllowed(h(1))).rejects.toThrow();
    rpc.raw = () => ({ status: 200, body: { jsonrpc: "2.0", id: 999, result: { value: [] } } });
    await expect(R.isComposeAllowed(h(1))).rejects.toThrow(/malformed/);
  });

  it("decodes the instance layout at the contract's offsets", () => {
    const { record, quote } = decodeSolanaInstance(instData({ expires: 99, nextSeq: 3 }));
    expect(record).toMatchObject({ x25519: h(0x11), ed25519: h(0x22), compose_hash: h(0xc0), os_measurement: h(0x05), expires_at_ms: 99, next_seq: 3 });
    expect(quote.length).toBe(828);
  });

  it("maps the §10 custom error numbering", () => {
    expect(solanaErrorCode(1)).toBe("E_UNAUTHORIZED");
    expect(solanaErrorCode(4)).toBe("E_OPERATOR_UNAPPROVED");
    expect(solanaErrorCode(9)).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(solanaErrorCode(0)).toBeNull();
    expect(solanaErrorCode(10)).toBeNull();
    expect(parseSolanaKey(SYSTEM)).not.toBeNull();
    expect(parseSolanaKey("1".repeat(45))).toBeNull();
  });
});
