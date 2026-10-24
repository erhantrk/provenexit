import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Address, Keypair, StrKey, xdr } from "@stellar/stellar-sdk";
import { PlrError, toHex } from "@plr/shared";
import {
  STELLAR_STANDALONE_PASSPHRASE as PP, StellarRegistry, StellarRegistryError, decodeAnchorView, decodeInstanceView, plrCodeOfStellarError,
  stellarContractAddress, stellarContractErrorOf, stellarErrorName,
} from "../../src/chains/stellar.js";
import { scStructOf, startFakeSoroban, type FakeSoroban, type SimHandler } from "./stellar-fake-rpc.js";

const C = StrKey.encodeContract(Buffer.alloc(32, 7));
const OP = Keypair.random().publicKey();
const h = (n: number) => toHex(new Uint8Array(32).fill(n));
const b = (n: number, len = 32) => xdr.ScVal.scvBytes(new Uint8Array(len).fill(n));
const u64 = (n: number | bigint) => xdr.ScVal.scvU64(BigInt(n));
const NOW = 1_800_000_000_000;

function instanceVal(o: Partial<Record<string, xdr.ScVal>> = {}): xdr.ScVal {
  return scStructOf({
    compose_hash: b(1), os_measurement: b(2), x25519: b(3), ed25519: b(4), operator: new Address(OP).toScVal(),
    registered_at_ms: u64(NOW - 1000), expires_at_ms: u64(NOW + 60_000), next_seq: u64(5), ...o,
  } as Record<string, xdr.ScVal>);
}
function anchorVal(o: Partial<Record<string, xdr.ScVal>> = {}): xdr.ScVal {
  return scStructOf({ key_hash: b(9), root: b(8), first_seq: u64(0), count: u64(3), at_ms: u64(NOW), sig: b(6, 64), ...o } as Record<string, xdr.ScVal>);
}

describe("stellar error mapping", () => {
  it("maps SPEC-CHAINS §10 numbers to names", () => {
    expect(stellarErrorName(1)).toBe("E_UNAUTHORIZED");
    expect(stellarErrorName(7)).toBe("E_SEQ");
    expect(stellarErrorName(9)).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(stellarErrorName(0)).toBeNull();
    expect(stellarErrorName(10)).toBeNull();
    expect(stellarContractErrorOf("HostError: Error(Contract, #8)\n\nEvent log ...")).toBe("E_INSTANCE_NOT_REGISTERED");
    expect(stellarContractErrorOf("HostError: Error(Auth, InvalidAction)")).toBeNull();
    expect(stellarContractErrorOf(undefined)).toBeNull();
    expect(plrCodeOfStellarError("E_SEQ")).toBe("E_SEQ");
    expect(plrCodeOfStellarError("E_UNAUTHORIZED")).toBeNull();
  });
  it("parses registry ids", () => {
    expect(stellarContractAddress(`stellar:${C}`)).toBe(C);
    expect(stellarContractAddress(C)).toBe(C);
    for (const bad of [OP, "stellar:", "", 5, `stellar:${C}x`]) expect(() => stellarContractAddress(bad)).toThrow(PlrError);
  });
});

describe("strict decoding", () => {
  it("decodes an InstanceView", () => {
    expect(decodeInstanceView(instanceVal())).toEqual({
      compose_hash: h(1), os_measurement: h(2), x25519: h(3), ed25519: h(4), operator: OP,
      registered_at_ms: NOW - 1000, expires_at_ms: NOW + 60_000, next_seq: 5,
    });
    expect(decodeInstanceView(xdr.ScVal.scvVoid())).toBeNull();
  });
  it("rejects malformed instance views", () => {
    const bads = [
      instanceVal({ x25519: b(3, 31) }),
      instanceVal({ next_seq: xdr.ScVal.scvU32(5) }),
      instanceVal({ next_seq: u64(2n ** 60n) }),
      instanceVal({ operator: new Address(C).toScVal() }), // contracts never register
      instanceVal({ operator: xdr.ScVal.scvString(OP) }),
      scStructOf({ compose_hash: b(1) }),
      xdr.ScVal.scvBool(true),
    ];
    for (const v of bads) expect(() => decodeInstanceView(v)).toThrow(StellarRegistryError);
    const extra = scStructOf({
      compose_hash: b(1), os_measurement: b(2), x25519: b(3), ed25519: b(4), operator: new Address(OP).toScVal(),
      registered_at_ms: u64(1), expires_at_ms: u64(2), next_seq: u64(0), extra: b(1),
    });
    expect(() => decodeInstanceView(extra)).toThrow(StellarRegistryError);
  });
  it("decodes an AnchorView with its signature", () => {
    expect(decodeAnchorView(4, anchorVal())).toEqual({ id: 4, key_hash: h(9), root: h(8), first_seq: 0, count: 3, at_ms: NOW, sig: toHex(new Uint8Array(64).fill(6)) });
    expect(() => decodeAnchorView(0, anchorVal({ sig: b(6, 63) }))).toThrow(StellarRegistryError);
    expect(decodeAnchorView(0, xdr.ScVal.scvVoid())).toBeNull();
  });
});

describe("StellarRegistry over a fake Soroban RPC", () => {
  let rpc: FakeSoroban;
  let handler: SimHandler = () => xdr.ScVal.scvVoid();
  let reg: StellarRegistry;
  beforeAll(async () => {
    rpc = await startFakeSoroban(PP, (fn, args, c) => handler(fn, args, c));
    reg = new StellarRegistry({ rpcUrl: rpc.url, networkPassphrase: PP, contract: C, timeoutMs: 1500, now: () => NOW });
  });
  afterAll(async () => rpc?.close());

  it("is tier B with the SPEC-CHAINS §3 contractId", () => {
    expect(reg.chain).toBe("stellar");
    expect(reg.verifiesOnChain).toBe(false);
    expect(reg.contractId).toBe(`stellar:${C}`);
  });

  it("validates options", () => {
    expect(() => new StellarRegistry({ rpcUrl: "http://example.com/rpc", networkPassphrase: PP, contract: C })).toThrow(PlrError);
    expect(() => new StellarRegistry({ rpcUrl: rpc.url, networkPassphrase: "", contract: C })).toThrow(PlrError);
    expect(() => new StellarRegistry({ rpcUrl: rpc.url, networkPassphrase: PP, contract: OP })).toThrow(PlrError);
    expect(() => new StellarRegistry({ rpcUrl: "https://rpc.example.com", networkPassphrase: PP, contract: `stellar:${C}` })).not.toThrow();
  });

  it("reads policy, root and instances (org is live from get_operator)", async () => {
    const seen: string[] = [];
    handler = (fn, args) => {
      seen.push(fn);
      switch (fn) {
        case "get_root": return xdr.ScVal.scvVec([xdr.ScVal.scvU32(1), b(5, 64)]);
        case "is_compose_allowed": return xdr.ScVal.scvBool(args[0]!.type === "scvBytes" && toHex(args[0]!.bytes.value) === h(1));
        case "is_os_allowed": return xdr.ScVal.scvBool(false);
        case "get_instance": return instanceVal();
        case "get_operator": return Address.fromScVal(args[0]!).toString() === OP ? xdr.ScVal.scvString("org-a") : xdr.ScVal.scvVoid();
        case "get_registration_quote": return b(0x42, 828);
        case "get_anchor": return args[0]!.type === "scvU64" && args[0]!.u64 === 0n ? anchorVal() : xdr.ScVal.scvVoid();
        case "anchor_count": return u64(1);
        default: return { error: "HostError: Error(WasmVm, MissingValue)" };
      }
    };
    expect(await reg.getRoot()).toEqual({ kind: "MOCK", p256: toHex(new Uint8Array(64).fill(5)) });
    expect(await reg.isComposeAllowed(h(1))).toBe(true);
    expect(await reg.isComposeAllowed(h(2))).toBe(false);
    expect(await reg.isOsAllowed(h(2))).toBe(false);
    expect(await reg.getInstance(h(9))).toMatchObject({ operator: OP, org_id: "org-a", next_seq: 5, compose_hash: h(1) });
    expect(await reg.getRegistrationQuote(h(9), new Uint8Array(3))).toEqual(new Uint8Array(828).fill(0x42));
    expect(await reg.getAnchor(0)).toMatchObject({ id: 0, sig: toHex(new Uint8Array(64).fill(6)) });
    expect(await reg.getAnchor(1)).toBeNull();
    expect(await reg.anchorCount()).toBe(1);
    // simulations come from the never-existing null account (no signing)
    expect(rpc.calls.every((c) => c.source === "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")).toBe(true);
    expect(seen).toContain("get_operator");
  });

  it("never asks about malformed or zero hashes", async () => {
    const before = rpc.calls.length;
    expect(await reg.isComposeAllowed(h(0))).toBe(false);
    expect(await reg.isOsAllowed("zz")).toBe(false);
    expect(await reg.getInstance("00")).toBeNull();
    expect(await reg.getRegistrationQuote(h(0))).toBeNull();
    expect(await reg.getAnchor(-1)).toBeNull();
    expect(rpc.calls.length).toBe(before);
  });

  it("revoked operator ⇒ null (SPEC-CHAINS §1: records only from live-approved operators); expired ⇒ null", async () => {
    handler = (fn) => (fn === "get_instance" ? instanceVal() : xdr.ScVal.scvVoid());
    expect(await reg.getInstance(h(9))).toBeNull();
    handler = (fn) => (fn === "get_instance" ? instanceVal({ expires_at_ms: u64(NOW) }) : xdr.ScVal.scvVoid());
    expect(await reg.getInstance(h(9))).toBeNull();
    handler = () => xdr.ScVal.scvVoid();
    expect(await reg.getInstance(h(9))).toBeNull();
    expect(await reg.getRegistrationQuote(h(9))).toBeNull();
  });

  it("fails closed on malformed replies, simulation errors and timeouts", async () => {
    handler = () => xdr.ScVal.scvU32(1);
    await expect(reg.isComposeAllowed(h(1))).rejects.toThrow(StellarRegistryError);
    await expect(reg.getRoot()).rejects.toThrow(StellarRegistryError);
    handler = (fn) => (fn === "get_instance" ? instanceVal() : xdr.ScVal.scvString("Not An Org"));
    await expect(reg.getInstance(h(9))).rejects.toThrow(StellarRegistryError);
    handler = () => xdr.ScVal.scvVec([xdr.ScVal.scvU32(3), b(5, 64)]);
    await expect(reg.getRoot()).rejects.toThrow(StellarRegistryError);
    handler = () => ({ error: "HostError: Error(Contract, #3)" });
    const e = await reg.isOsAllowed(h(1)).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(StellarRegistryError);
    expect((e as StellarRegistryError).contractError).toBe("E_BAD_INPUT");
    handler = () => ({ raw: { latestLedger: 1 } });
    await expect(reg.isOsAllowed(h(1))).rejects.toThrow(StellarRegistryError);
    handler = () => "hang";
    await expect(reg.isOsAllowed(h(1))).rejects.toThrow(/timeout|RPC failed/);
  });

  it("an unreachable RPC rejects", async () => {
    const r = new StellarRegistry({ rpcUrl: "http://127.0.0.1:1/rpc", networkPassphrase: PP, contract: C, timeoutMs: 1000 });
    await expect(r.getRoot()).rejects.toThrow(StellarRegistryError);
  });
});
