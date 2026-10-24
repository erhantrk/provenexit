// PLR_CHAIN dispatch (SPEC-CHAINS §4): config loaders, writer factory and host env allowlists for the tier-B chains.
import { afterEach, describe, expect, it } from "vitest";
import { Keypair as SolKeypair } from "@solana/web3.js";
import { Keypair as StellarKeypair, StrKey } from "@stellar/stellar-sdk";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { randomBytes } from "@noble/hashes/utils.js";
import { PlrError, toHex } from "@plr/shared";
import { LazyEvmRegistryWriter, createRegistryWriter } from "../../src/chains.js";
import { EvmRegistryWriter } from "../../src/chains/evm.js";
import { SolanaRegistryWriter } from "../../src/chains/solana.js";
import { StellarRegistryWriter } from "../../src/chains/stellar.js";
import { loadConfig } from "../../src/config.js";
import { COMBO_EXIT_ENV_ALLOWLIST, COMBO_ROUTER_ENV_ALLOWLIST, EXIT_ENV_ALLOWLIST, ROUTER_ENV_ALLOWLIST, comboProcessEnvs } from "../../src/mock-tdx/host.js";
import { loadExitConfig } from "../../src/vpn/config.js";
import { startFakeNode, type FakeNode } from "./evm-fake-node.js";

const base = { PLR_TDX_SOCKET: "/tmp/q.sock", PLR_APP_COMPOSE_PATH: "/tmp/c.json" };
const evmKey = generatePrivateKey().slice(2);
const evmOp = privateKeyToAccount(`0x${evmKey}`).address.toLowerCase();
const EVM_A = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const EVM_B = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";
const evm = { PLR_CHAIN: "evm", PLR_EVM_RPC: "http://127.0.0.1:8545", PLR_EVM_REGISTRY: EVM_A, PLR_EVM_KEY: evmKey };
const stKp = StellarKeypair.random();
const ST_A = StrKey.encodeContract(Buffer.from(randomBytes(32)));
const ST_B = StrKey.encodeContract(Buffer.from(randomBytes(32)));
const stellar = {
  PLR_CHAIN: "stellar", PLR_STELLAR_RPC: "http://127.0.0.1:8000/rpc", PLR_STELLAR_PASSPHRASE: "Standalone Network ; February 2017",
  PLR_STELLAR_REGISTRY: ST_A, PLR_STELLAR_KEY: stKp.secret(),
};
const solKp = SolKeypair.generate();
const SOL_A = SolKeypair.generate().publicKey.toBase58();
const SOL_B = SolKeypair.generate().publicKey.toBase58();
const SOL_PROGRAM = SolKeypair.generate().publicKey.toBase58();
const solana = {
  PLR_CHAIN: "solana", PLR_SOLANA_RPC: "http://127.0.0.1:8899", PLR_SOLANA_PROGRAM: SOL_PROGRAM,
  PLR_SOLANA_REGISTRY: SOL_A, PLR_SOLANA_KEY: toHex(solKp.secretKey),
};

describe("PLR_CHAIN dispatch for tier B (SPEC-CHAINS §4, §9-§11)", () => {
  it("router: each chain's env selects its writer with the SPEC-CHAINS §3 identifiers", () => {
    const e = loadConfig({ ...base, ...evm, PLR_EVM_CHAIN_ID: "31337" });
    expect(e.registry?.chain).toBe("evm");
    const ew = createRegistryWriter(e.registry!);
    expect(ew).toBeInstanceOf(EvmRegistryWriter);
    expect([ew.contractId, ew.operatorId]).toEqual([`evm:31337:${EVM_A}`, evmOp]);

    const s = loadConfig({ ...base, ...stellar });
    const sw = createRegistryWriter(s.registry!);
    expect(sw).toBeInstanceOf(StellarRegistryWriter);
    expect([sw.contractId, sw.operatorId]).toEqual([`stellar:${ST_A}`, stKp.publicKey()]);

    const o = loadConfig({ ...base, ...solana });
    const ow = createRegistryWriter(o.registry!);
    expect(ow).toBeInstanceOf(SolanaRegistryWriter);
    expect([ow.contractId, ow.operatorId]).toEqual([`solana:${SOL_A}`, solKp.publicKey.toBase58()]);
    for (const c of [e, s, o]) expect([c.near, c.nearConfigError]).toEqual([null, false]);
  });

  it("without PLR_EVM_CHAIN_ID (the exact §9 env) the EVM writer is lazy: contractId comes from the node", () => {
    const w = createRegistryWriter(loadConfig({ ...base, ...evm }).registry!);
    expect(w).toBeInstanceOf(LazyEvmRegistryWriter);
    expect(w.operatorId).toBe(evmOp);
    expect(() => w.contractId).toThrow(PlrError);
  });

  it("the exit uses PLR_<CHAIN>_VPN_REGISTRY, else PLR_<CHAIN>_REGISTRY", () => {
    const pick = (env: Record<string, string>) => createRegistryWriter(loadExitConfig({ ...base, ...env }).registry!).contractId;
    expect(pick({ ...evm, PLR_EVM_CHAIN_ID: "10143" })).toBe(`evm:10143:${EVM_A}`);
    expect(pick({ ...evm, PLR_EVM_CHAIN_ID: "10143", PLR_EVM_VPN_REGISTRY: EVM_B })).toBe(`evm:10143:${EVM_B}`);
    expect(pick(stellar)).toBe(`stellar:${ST_A}`);
    expect(pick({ ...stellar, PLR_STELLAR_VPN_REGISTRY: ST_B })).toBe(`stellar:${ST_B}`);
    expect(pick(solana)).toBe(`solana:${SOL_A}`);
    expect(pick({ ...solana, PLR_SOLANA_VPN_REGISTRY: SOL_B })).toBe(`solana:${SOL_B}`);
  });

  it("no chain variables ⇒ unregistered; partial or invalid ⇒ registration disabled (fail closed)", () => {
    for (const chain of ["evm", "stellar", "solana"]) {
      const c = loadConfig({ ...base, PLR_CHAIN: chain });
      expect([c.registry, c.nearConfigError]).toEqual([null, false]);
    }
    // another chain's variables do not configure this one
    expect(loadConfig({ ...base, ...evm, PLR_CHAIN: "stellar" }).registry).toBeNull();
    for (const bad of [
      { ...evm, PLR_EVM_KEY: "" }, { ...evm, PLR_EVM_KEY: "00".repeat(32) }, { ...evm, PLR_EVM_REGISTRY: "0x12" },
      { ...evm, PLR_EVM_RPC: "file:///etc/passwd" }, { ...evm, PLR_EVM_CHAIN_ID: "0" },
      { ...stellar, PLR_STELLAR_PASSPHRASE: "" }, { ...stellar, PLR_STELLAR_REGISTRY: stKp.publicKey() }, { ...stellar, PLR_STELLAR_KEY: "S123" },
      { ...solana, PLR_SOLANA_PROGRAM: "" }, { ...solana, PLR_SOLANA_REGISTRY: "not-base58!" }, { ...solana, PLR_SOLANA_KEY: "zz" },
    ]) {
      const c = loadConfig({ ...base, ...bad });
      expect([c.registry, c.near, c.nearConfigError], JSON.stringify(bad)).toEqual([null, null, true]);
    }
  });

  it("host allowlists forward PLR_EVM_* / PLR_STELLAR_* / PLR_SOLANA_*; a combo exit never gets the LLM registry", () => {
    const shared = [
      "PLR_EVM_RPC", "PLR_EVM_CHAIN_ID", "PLR_EVM_REGISTRY", "PLR_EVM_KEY",
      "PLR_STELLAR_RPC", "PLR_STELLAR_PASSPHRASE", "PLR_STELLAR_REGISTRY", "PLR_STELLAR_KEY",
      "PLR_SOLANA_RPC", "PLR_SOLANA_PROGRAM", "PLR_SOLANA_REGISTRY", "PLR_SOLANA_KEY",
    ];
    for (const k of shared) {
      expect(ROUTER_ENV_ALLOWLIST).toContain(k);
      expect(EXIT_ENV_ALLOWLIST).toContain(k);
    }
    for (const k of ["PLR_EVM_VPN_REGISTRY", "PLR_STELLAR_VPN_REGISTRY", "PLR_SOLANA_VPN_REGISTRY"]) {
      expect(EXIT_ENV_ALLOWLIST).toContain(k);
      expect(COMBO_EXIT_ENV_ALLOWLIST).toContain(k);
      expect(ROUTER_ENV_ALLOWLIST).not.toContain(k as never);
    }
    for (const k of ["PLR_EVM_REGISTRY", "PLR_STELLAR_REGISTRY", "PLR_SOLANA_REGISTRY"]) {
      expect(COMBO_EXIT_ENV_ALLOWLIST).not.toContain(k as never);
      expect(COMBO_ROUTER_ENV_ALLOWLIST).toContain(k);
    }
    const envs = comboProcessEnvs({
      hostEnv: { ...evm, PLR_EVM_VPN_REGISTRY: EVM_B }, nodeEnv: {}, socketPath: "/s", routerComposePath: "/r", vpnComposePath: "/v",
      routerPort: 1, llmPort: 2, llmApiKey: "k", runDir: "/d",
    });
    expect([envs.router.PLR_EVM_REGISTRY, envs.router.PLR_EVM_VPN_REGISTRY]).toEqual([EVM_A, undefined]);
    expect([envs.exit.PLR_EVM_REGISTRY, envs.exit.PLR_EVM_VPN_REGISTRY, envs.exit.PLR_EVM_KEY]).toEqual([undefined, EVM_B, evmKey]);
  });
});

describe("LazyEvmRegistryWriter", () => {
  let node: FakeNode | undefined;
  afterEach(async () => {
    await node?.close();
    node = undefined;
  });

  it("learns the chain id on prepare() and then behaves like the EVM writer", async () => {
    node = await startFakeNode({ chainId: 10143, address: EVM_A, owner: evmOp, rootP256: `0x${"11".repeat(64)}` });
    const w = new LazyEvmRegistryWriter({ rpcUrl: node.url, registry: EVM_A, key: evmKey, chainId: null });
    await w.prepare();
    expect(w.contractId).toBe(`evm:10143:${EVM_A}`);
    expect(await w.getInstanceNextSeq("ab".repeat(32))).toBeNull();
    w.close();
    await expect(w.prepare()).rejects.toBeInstanceOf(PlrError);
  });

  it("a node that is down fails prepare() with E_REGISTRY_UNAVAILABLE (retried later), never a contractId", async () => {
    const w = new LazyEvmRegistryWriter({ rpcUrl: "http://127.0.0.1:1", registry: EVM_A, key: evmKey, chainId: null });
    await expect(w.prepare()).rejects.toMatchObject({ code: "E_REGISTRY_UNAVAILABLE" });
    expect(() => w.contractId).toThrow(PlrError);
  });
});
