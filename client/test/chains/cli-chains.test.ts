// plr CLI config for the tier-B chains (SPEC-CHAINS §3, §9-§11): PLR_CHAIN=evm|stellar|solana.
import { describe, expect, it } from "vitest";
import { Keypair as SolKeypair } from "@solana/web3.js";
import { StrKey } from "@stellar/stellar-sdk";
import { randomBytes } from "@noble/hashes/utils.js";
import { p256 } from "@noble/curves/nist.js";
import { toHex } from "@plr/shared";
import { loadConfig, loadVpnConfig, makeRegistry, registryTier } from "../../src/cli.js";
import { EvmRegistry } from "../../src/chains/evm.js";
import { StellarRegistry } from "../../src/chains/stellar.js";
import { SolanaRegistry } from "../../src/chains/solana.js";

const root = toHex(p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1));
const A = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const B = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
const C1 = StrKey.encodeContract(Buffer.from(randomBytes(32)));
const C2 = StrKey.encodeContract(Buffer.from(randomBytes(32)));
const S1 = SolKeypair.generate().publicKey.toBase58();
const S2 = SolKeypair.generate().publicKey.toBase58();
const PROG = SolKeypair.generate().publicKey.toBase58();
const PASS = "Standalone Network ; February 2017";
const msg = (f: () => unknown): string => {
  try {
    f();
    return "NO_THROW";
  } catch (e) {
    return (e as Error).message;
  }
};

describe("plr CLI with tier-B chains", () => {
  it("evm: contractId in PLR_REGISTRY, or address + PLR_EVM_CHAIN_ID; the VPN registry separately", () => {
    const c = loadConfig({ PLR_CHAIN: "evm", PLR_EVM_RPC: "http://127.0.0.1:8545", PLR_REGISTRY: `evm:31337:${A}`, PLR_TRUSTED_ROOT: root });
    expect([c.chain, c.contractId, c.rpcUrl]).toEqual(["evm", `evm:31337:${A}`, "http://127.0.0.1:8545"]);
    const r = makeRegistry(c);
    expect(r).toBeInstanceOf(EvmRegistry);
    expect([r.contractId, r.verifiesOnChain, registryTier(r)]).toEqual([`evm:31337:${A}`, false, "B"]);
    const d = loadConfig({ PLR_CHAIN: "evm", PLR_EVM_REGISTRY: A.toUpperCase().replace("0X", "0x"), PLR_EVM_CHAIN_ID: "10143", PLR_TRUSTED_ROOT: root });
    expect(d.contractId).toBe(`evm:10143:${A}`);
    const v = loadVpnConfig({ PLR_CHAIN: "evm", PLR_VPN_REGISTRY: `evm:10143:${B}`, PLR_REGISTRY: `evm:10143:${A}`, PLR_TRUSTED_ROOT: root });
    expect(v.contractId).toBe(`evm:10143:${B}`);
    const base = { PLR_CHAIN: "evm", PLR_TRUSTED_ROOT: root };
    expect(msg(() => loadConfig(base))).toMatch(/PLR_REGISTRY/);
    expect(msg(() => loadConfig({ ...base, PLR_EVM_REGISTRY: A }))).toMatch(/PLR_EVM_CHAIN_ID/);
    expect(msg(() => loadConfig({ ...base, PLR_REGISTRY: `evm:1:${A}`, PLR_EVM_CHAIN_ID: "2" }))).toMatch(/disagrees/);
    expect(msg(() => loadConfig({ ...base, PLR_REGISTRY: `evm:1:${A}`, PLR_EVM_CHAIN_ID: "1", PLR_EVM_REGISTRY: B }))).toMatch(/disagrees/);
    expect(msg(() => loadConfig({ ...base, PLR_REGISTRY: `evm:1:${A}`, PLR_EVM_RPC: "http://rpc.example.com" }))).toMatch(/PLR_EVM_RPC/);
    expect(msg(() => loadConfig({ ...base, PLR_REGISTRY: `stellar:${C1}` }))).toMatch(/evm:/);
  });

  it("stellar: RPC + passphrase required; stellar:C… or PLR_STELLAR_[VPN_]REGISTRY", () => {
    const env = { PLR_CHAIN: "stellar", PLR_STELLAR_RPC: "http://localhost:8000/rpc", PLR_STELLAR_PASSPHRASE: PASS, PLR_TRUSTED_ROOT: root };
    const c = loadConfig({ ...env, PLR_REGISTRY: `stellar:${C1}` });
    const r = makeRegistry(c);
    expect(r).toBeInstanceOf(StellarRegistry);
    expect([r.contractId, registryTier(r)]).toEqual([`stellar:${C1}`, "B"]);
    expect(loadConfig({ ...env, PLR_STELLAR_REGISTRY: C1 }).contractId).toBe(`stellar:${C1}`);
    expect(loadVpnConfig({ ...env, PLR_STELLAR_REGISTRY: C1, PLR_STELLAR_VPN_REGISTRY: C2 }).contractId).toBe(`stellar:${C2}`);
    expect(msg(() => loadConfig({ ...env, PLR_REGISTRY: `stellar:${C1}`, PLR_STELLAR_REGISTRY: C2 }))).toMatch(/disagrees/);
    expect(msg(() => loadConfig({ ...env, PLR_STELLAR_PASSPHRASE: "", PLR_REGISTRY: `stellar:${C1}` }))).toMatch(/PASSPHRASE/);
    expect(msg(() => loadConfig({ ...env, PLR_STELLAR_RPC: "", PLR_REGISTRY: `stellar:${C1}` }))).toMatch(/PLR_STELLAR_RPC/);
    expect(msg(() => loadConfig({ ...env, PLR_REGISTRY: C1 }))).toMatch(/stellar:/);
  });

  it("solana: program id required; solana:<state> or PLR_SOLANA_[VPN_]REGISTRY", () => {
    const env = { PLR_CHAIN: "solana", PLR_SOLANA_PROGRAM: PROG, PLR_TRUSTED_ROOT: root };
    const c = loadConfig({ ...env, PLR_REGISTRY: `solana:${S1}` });
    expect(c.rpcUrl).toBe("http://127.0.0.1:8899");
    const r = makeRegistry(c);
    expect(r).toBeInstanceOf(SolanaRegistry);
    expect([r.contractId, registryTier(r), (r as SolanaRegistry).programId]).toEqual([`solana:${S1}`, "B", PROG]);
    expect(loadVpnConfig({ ...env, PLR_SOLANA_VPN_REGISTRY: S2 }).contractId).toBe(`solana:${S2}`);
    expect(msg(() => loadConfig({ ...env, PLR_SOLANA_PROGRAM: "", PLR_REGISTRY: `solana:${S1}` }))).toMatch(/PLR_SOLANA_PROGRAM/);
    expect(msg(() => loadConfig({ ...env, PLR_REGISTRY: `solana:${S1}`, PLR_SOLANA_REGISTRY: S2 }))).toMatch(/disagrees/);
    expect(msg(() => loadConfig({ ...env, PLR_REGISTRY: "solana:0OIl" }))).toMatch(/solana:/);
  });
});
