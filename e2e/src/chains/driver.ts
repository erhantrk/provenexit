/**
 * Chain drivers of the e2e harness (SPEC-CHAINS §6): one local node per stack holding the two registries (LLM + VPN),
 * the stack accounts, owner admin APIs, registry readers and the env an instance needs to register on that chain.
 * `startStack({ chain })` picks the driver; everything else in the harness is chain-agnostic.
 */
import type { RegistryReader } from "@plr/shared";

export type Chain = "near" | "evm" | "stellar" | "solana" | "zcash";
export const CHAINS: readonly Chain[] = ["near", "evm", "stellar", "solana", "zcash"];

export type Signer = "owner" | "operator" | "operator2" | "stranger";
/** Accounts that operate (register) instances; the owner maps them to organizations (SPEC §7 rev 1.2). */
export type OperatorAccount = "operator" | "operator2";
export const OPERATORS: readonly OperatorAccount[] = ["operator", "operator2"];

/** Which of the stack's two registries. */
export type RegistryName = "llm" | "vpn";

/** Owner API of one registry (SPEC-CHAINS §6). Resolves once the write is included on chain. */
export interface ChainAdmin {
  allowCompose(h: string): Promise<void>;
  revokeCompose(h: string): Promise<void>;
  allowOs(h: string): Promise<void>;
  revokeOs(h: string): Promise<void>;
  approveOperator(account: OperatorAccount, orgId: string): Promise<void>;
  revokeOperator(account: OperatorAccount): Promise<void>;
}

/** NEAR-style method call on a registry (`call` / `callVpn`); chains without contracts map the owner methods. */
export type CallFn = (signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }) => Promise<unknown>;

/** What a chain driver provides to the harness. */
export interface ChainDriver {
  readonly chain: Chain;
  /** The node's RPC URL. */
  readonly rpcUrl: string;
  readonly contractId: string;
  readonly vpnContractId: string;
  readonly registry: RegistryReader;
  readonly vpnRegistry: RegistryReader;
  readonly accounts: { owner: string; operator: string; operator2: string; stranger: string };
  readonly admin: ChainAdmin;
  readonly vpnAdmin: ChainAdmin;
  /** The same API signed by the stranger account (refused or ignored by readers). */
  asStranger(a: ChainAdmin): ChainAdmin;
  view<T>(method: string, args: object): Promise<T>;
  call: CallFn;
  callVpn: CallFn;
  /**
   * Env of a launch that registers on `registries` as `operator` (the host forwards it per its allowlists). Each
   * call may set up per-instance credentials (NEAR: a fresh full-access key on the operator account).
   */
  instanceEnv(operator: OperatorAccount, registries: readonly RegistryName[]): Promise<Record<string, string>>;
  /** Dev tooling: lines for the stack env file describing where the registries are (client config). */
  clientEnvLines(): string[];
  /** Dev tooling: JSON for the owner key file (0600) used by `stack-cli owner`. */
  ownerFile(): Record<string, unknown>;
  /** Dev tooling: the fresh key of a stack account. */
  exportSigner(signer: Signer): { accountId: string; secretKey: string };
  /** Stops the node (bounded, idempotent). */
  stop(): Promise<void>;
}

export interface DriverOptions {
  /** Directory for the node's state (under the stack's run dir). */
  dir: string;
  /** Pinned MOCK root public key (64 bytes x‖y), set as the registries' root. */
  trustedRoot: Uint8Array;
  /** Fixed RPC port (default: a free one). */
  rpcPort?: number;
  /** Registration lifetime (ms). */
  instanceTtlMs: number;
}
