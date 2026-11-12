/**
 * The chain driver of the e2e harness: one local near-sandbox per stack holding the VPN registry, the stack accounts,
 * the owner admin API, the registry reader and the env an exit needs to register on it.
 */
import type { RegistryReader } from "@plr/shared";

export type Signer = "owner" | "operator" | "operator2" | "stranger";
/** Accounts that operate (register) instances; the owner maps them to organizations (SPEC §7 rev 1.2). */
export type OperatorAccount = "operator" | "operator2";
export const OPERATORS: readonly OperatorAccount[] = ["operator", "operator2"];

/** Owner API of the registry. Resolves once the write is included on chain. */
export interface ChainAdmin {
  allowCompose(h: string): Promise<void>;
  revokeCompose(h: string): Promise<void>;
  allowOs(h: string): Promise<void>;
  revokeOs(h: string): Promise<void>;
  approveOperator(account: OperatorAccount, orgId: string): Promise<void>;
  revokeOperator(account: OperatorAccount): Promise<void>;
}

/** NEAR method call on the registry, signed by a stack account. */
export type CallFn = (signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }) => Promise<unknown>;

/** What the chain driver provides to the harness. */
export interface ChainDriver {
  /** The node's RPC URL. */
  readonly rpcUrl: string;
  readonly vpnContractId: string;
  readonly vpnRegistry: RegistryReader;
  readonly accounts: { owner: string; operator: string; operator2: string; stranger: string };
  readonly vpnAdmin: ChainAdmin;
  /** The same API signed by the stranger account (refused by the contract). */
  asStranger(a: ChainAdmin): ChainAdmin;
  viewVpn<T>(method: string, args: object): Promise<T>;
  callVpn: CallFn;
  /**
   * Env of a launch that registers on the VPN registry as `operator` (the host forwards it per its allowlist). Each
   * call sets up per-instance credentials (a fresh full-access key on the operator account).
   */
  instanceEnv(operator: OperatorAccount): Promise<Record<string, string>>;
  /** Dev tooling: lines for the stack env file describing where the registry is (client config). */
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
  /** Pinned MOCK root public key (64 bytes x‖y), set as the registry's root. */
  trustedRoot: Uint8Array;
  /** Fixed RPC port (default: a free one). */
  rpcPort?: number;
  /** Registration lifetime (ms). */
  instanceTtlMs: number;
}
