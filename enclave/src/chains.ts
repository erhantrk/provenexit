/** `PLR_CHAIN` → registry writer (SPEC-CHAINS §4). NEAR keeps its existing writer unchanged. */
import { PlrError } from "@plr/shared";
import type { RegistryConfig } from "./config.js";
import { NearRegistryWriter } from "./near.js";
import type { AnchorArgs, AnchorView, RegisterArgs, RegistryWriter } from "./registry-writer.js";
import { ZcashRegistryWriter } from "./zcash.js";
import { EvmRegistryWriter, evmWriterOf, type EvmConfig } from "./chains/evm.js";
import { createStellarWriter } from "./chains/stellar.js";
import { SolanaRegistryWriter } from "./chains/solana.js";

/**
 * EVM writer whose chain id (part of `contractId`, SPEC-CHAINS §3) is asked from the node on first use, so the
 * instance env can be exactly `PLR_EVM_RPC` / `PLR_EVM_REGISTRY` / `PLR_EVM_KEY` (§9). `prepare()` resolves it (a failed
 * probe is retried on the next call); `contractId` is unavailable until then (the anchorer prepares before registering).
 */
export class LazyEvmRegistryWriter implements RegistryWriter {
  readonly operatorId: string;
  #inner: EvmRegistryWriter | null = null;
  #pending: Promise<EvmRegistryWriter> | null = null;
  #closed = false;
  readonly #cfg: EvmConfig;

  constructor(cfg: EvmConfig) {
    this.#cfg = cfg;
    // Validates the settings and derives the operator address now (chain id 1 is a placeholder, never used to write).
    this.operatorId = new EvmRegistryWriter({ rpcUrl: cfg.rpcUrl, registry: cfg.registry, key: cfg.key, chainId: 1 }).operatorId;
  }

  get contractId(): string {
    if (this.#inner === null) throw new PlrError("E_REGISTRY_UNAVAILABLE", "evm chain id not known yet");
    return this.#inner.contractId;
  }

  prepare(): Promise<void> {
    return this.#writer().then(() => undefined);
  }

  #writer(): Promise<EvmRegistryWriter> {
    if (this.#closed) return Promise.reject(new PlrError("E_REGISTRY_UNAVAILABLE", "evm writer closed"));
    if (this.#inner !== null) return Promise.resolve(this.#inner);
    this.#pending ??= EvmRegistryWriter.create({ rpcUrl: this.#cfg.rpcUrl, registry: this.#cfg.registry, key: this.#cfg.key })
      .then((w) => {
        if (this.#closed) w.close();
        else this.#inner = w;
        return w;
      })
      .finally(() => {
        this.#pending = null;
      });
    return this.#pending;
  }

  async registerInstance(args: RegisterArgs): Promise<void> {
    return (await this.#writer()).registerInstance(args);
  }
  async anchorReceipts(args: AnchorArgs): Promise<unknown> {
    return (await this.#writer()).anchorReceipts(args);
  }
  async getInstanceNextSeq(keyHash: string): Promise<number | null> {
    return (await this.#writer()).getInstanceNextSeq(keyHash);
  }
  async getInstanceOperator(keyHash: string): Promise<string | null> {
    return (await this.#writer()).getInstanceOperator(keyHash);
  }
  async anchorCount(): Promise<number> {
    return (await this.#writer()).anchorCount();
  }
  async getAnchor(id: number): Promise<AnchorView | null> {
    return (await this.#writer()).getAnchor(id);
  }
  close(): void {
    this.#closed = true;
    this.#inner?.close();
  }
}

/** @throws PlrError E_BAD_INPUT on invalid settings (already validated by the config loaders) */
export function createRegistryWriter(c: RegistryConfig): RegistryWriter {
  switch (c.chain) {
    case "near":
      return new NearRegistryWriter(c.near);
    case "evm":
      return c.evm.chainId === null ? new LazyEvmRegistryWriter(c.evm) : evmWriterOf(c.evm);
    case "stellar":
      return createStellarWriter(c.stellar);
    case "solana":
      return new SolanaRegistryWriter({ rpcUrl: c.solana.rpcUrl, programId: c.solana.programId, registry: c.solana.registry, key: c.solana.key });
    case "zcash":
      return new ZcashRegistryWriter({ rpc: c.zcash.rpcUrl, network: c.zcash.network, owner: c.zcash.owner, key: c.zcash.key, startHeight: c.zcash.startHeight });
  }
}
