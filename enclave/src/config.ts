/** Router configuration from the environment (set by the mock TDX host). Strictly validated; fail closed. */
import { PlrError, isTAddress, isZcashNetwork, parseZcashSecretKey, type ZcashNetwork } from "@plr/shared";
import { NEAR_ACCOUNT_RE, NEAR_KEY_RE } from "./near.js";

export interface NearConfig {
  rpcUrl: string;
  contractId: string;
  operatorId: string;
  operatorKey: string;
  registerDeposit: bigint;
  /**
   * Deposit attached to every `anchor_receipts` (yoctoNEAR) to pay the anchor's storage; the contract refunds
   * the excess, and falls back to the instance's prepaid credit only if this is too small.
   */
  anchorDeposit: bigint;
}

/** SPEC-CHAINS §4 `PLR_CHAIN` values. Only `near` and `zcash` have writers in this build. */
export const CHAIN_NAMES = ["near", "evm", "stellar", "solana", "zcash"] as const;
export type ChainName = (typeof CHAIN_NAMES)[number];

/** Zcash tier-C registry settings (SPEC-CHAINS §5 `PLR_ZCASH_*`). */
export interface ZcashConfig {
  /** Zebra JSON-RPC URL (http/https; optional `user:pass@` for basic auth). */
  rpcUrl: string;
  network: ZcashNetwork;
  /** Owner t-address of the registry (the `contractId` part). */
  owner: string;
  /** Operator secret key (WIF or 64 hex), validated. */
  key: string;
  /** First block height scanned for records (PLR_ZCASH_START_HEIGHT, default 0). */
  startHeight: number;
}

/** The registry an instance registers on, selected by `PLR_CHAIN` (default `near`). */
export type RegistryConfig = { chain: "near"; near: NearConfig } | { chain: "zcash"; zcash: ZcashConfig };

export interface RouterConfig {
  tdxSocket: string;
  composePath: string;
  host: string;
  port: number;
  /** Port of the LLM on 127.0.0.1; null → the SPEC §11 default for the compose's llm kind. */
  llmPort: number | null;
  /** Per-boot LLM API key from the host (PLR_LLM_API_KEY, 64 hex), or null when the LLM is unauthenticated. */
  llmApiKey: string | null;
  anchorIntervalMs: number;
  /** The NEAR settings when `PLR_CHAIN` is `near` (= `registry.near`), else null. */
  near: NearConfig | null;
  /** The selected registry (any chain), or null (unregistered: clients refuse). */
  registry: RegistryConfig | null;
  /**
   * True if the selected chain's variables were present but incomplete/invalid, or `PLR_CHAIN` is invalid or has no
   * writer in this build: registration is disabled (clients refuse).
   */
  nearConfigError: boolean;
}

export type Env = Readonly<Record<string, string | undefined>>;

/** 0.01 NEAR: ~7× the storage of one anchor record; the contract refunds what is not used. */
export const DEFAULT_ANCHOR_DEPOSIT = "10000000000000000000000";

export function bad(what: string): never {
  throw new PlrError("E_BAD_INPUT", `config ${what}`);
}

export function intVar(env: Env, name: string, def: number, min: number, max: number): number {
  const v = env[name];
  if (v === undefined || v === "") return def;
  if (!/^[0-9]{1,10}$/.test(v)) bad(name);
  const n = Number(v);
  if (n < min || n > max) bad(name);
  return n;
}

export const HOST_RE = /^(?:127\.0\.0\.1|0\.0\.0\.0|::1|::|localhost|(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))$/;

export function loadConfig(env: Env = process.env): RouterConfig {
  const tdxSocket = env.PLR_TDX_SOCKET;
  if (!tdxSocket || tdxSocket.length > 1024) bad("PLR_TDX_SOCKET");
  const composePath = env.PLR_APP_COMPOSE_PATH;
  if (!composePath || composePath.length > 4096) bad("PLR_APP_COMPOSE_PATH");
  const host = env.PLR_ROUTER_HOST || "127.0.0.1";
  if (!HOST_RE.test(host)) bad("PLR_ROUTER_HOST");
  const port = intVar(env, "PLR_ROUTER_PORT", 18100, 0, 65535);
  const llmPortRaw = env.PLR_LLM_PORT;
  const llmPort = llmPortRaw === undefined || llmPortRaw === "" ? null : intVar(env, "PLR_LLM_PORT", 0, 1, 65535);
  const anchorIntervalMs = intVar(env, "PLR_ANCHOR_INTERVAL_MS", 3000, 100, 3_600_000);
  const llmApiKeyRaw = env.PLR_LLM_API_KEY;
  const llmApiKey = llmApiKeyRaw === undefined || llmApiKeyRaw === "" ? null : llmApiKeyRaw;
  if (llmApiKey !== null && !/^[0-9a-f]{64}$/.test(llmApiKey)) bad("PLR_LLM_API_KEY");

  const { registry, near, nearConfigError } = loadRegistrySafe(env, { nearRegistryVar: "PLR_REGISTRY", zcashOwnerVar: "PLR_ZCASH_OWNER" });
  return { tdxSocket, composePath, host, port, llmPort, llmApiKey, anchorIntervalMs, near, registry, nearConfigError };
}

/** Which env variables name the registry (they differ between the LLM router and the VPN exit). */
export interface RegistryVars {
  nearRegistryVar: string;
  zcashOwnerVar: string;
}

/**
 * The registry selected by `PLR_CHAIN` (default `near`): null when none of the chain's variables are set.
 * @throws PlrError E_BAD_INPUT on an invalid `PLR_CHAIN`, a chain without a writer in this build, or partial/invalid
 * variables
 */
export function loadRegistry(env: Env, vars: RegistryVars): RegistryConfig | null {
  const chainRaw = env.PLR_CHAIN === undefined || env.PLR_CHAIN === "" ? "near" : env.PLR_CHAIN;
  if (!(CHAIN_NAMES as readonly string[]).includes(chainRaw)) bad("PLR_CHAIN");
  const chain = chainRaw as ChainName;
  if (chain === "near") {
    const near = loadNear(env, vars.nearRegistryVar);
    return near === null ? null : { chain, near };
  }
  if (chain === "zcash") {
    const zcash = loadZcash(env, vars.zcashOwnerVar);
    return zcash === null ? null : { chain, zcash };
  }
  return bad(`PLR_CHAIN ${chain} has no registry writer in this build`);
}

/** {@link loadRegistry} that never throws: a configuration error disables registration (fail closed). */
export function loadRegistrySafe(env: Env, vars: RegistryVars): { registry: RegistryConfig | null; near: NearConfig | null; nearConfigError: boolean } {
  try {
    const registry = loadRegistry(env, vars);
    return { registry, near: registry?.chain === "near" ? registry.near : null, nearConfigError: false };
  } catch {
    return { registry: null, near: null, nearConfigError: true };
  }
}

/**
 * Zcash registration config (SPEC-CHAINS §5): all of PLR_ZCASH_RPC, PLR_ZCASH_NETWORK, the owner (`ownerVar`) and
 * PLR_ZCASH_KEY, or none (→ null); PLR_ZCASH_START_HEIGHT optional. @throws PlrError E_BAD_INPUT if partially set or invalid
 */
export function loadZcash(env: Env, ownerVar: string = "PLR_ZCASH_OWNER"): ZcashConfig | null {
  const vars = ["PLR_ZCASH_RPC", "PLR_ZCASH_NETWORK", ownerVar, "PLR_ZCASH_KEY"] as const;
  const set = vars.filter((k) => (env[k] ?? "") !== "");
  if (set.length === 0) return null;
  if (set.length !== vars.length) bad(`Zcash (PLR_ZCASH_RPC, PLR_ZCASH_NETWORK, ${ownerVar}, PLR_ZCASH_KEY must be set together)`);
  const rpcUrl = env.PLR_ZCASH_RPC!;
  if (rpcUrl.length > 2048) bad("PLR_ZCASH_RPC");
  let u: URL;
  try {
    u = new URL(rpcUrl);
  } catch {
    bad("PLR_ZCASH_RPC");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") bad("PLR_ZCASH_RPC");
  const network = env.PLR_ZCASH_NETWORK!;
  if (!isZcashNetwork(network)) bad("PLR_ZCASH_NETWORK");
  const owner = env[ownerVar]!;
  if (owner.length > 64 || !isTAddress(owner, network)) bad(ownerVar);
  const key = env.PLR_ZCASH_KEY!;
  try {
    parseZcashSecretKey(key);
  } catch {
    bad("PLR_ZCASH_KEY");
  }
  const startHeight = intVar(env, "PLR_ZCASH_START_HEIGHT", 0, 0, 1_000_000_000);
  return { rpcUrl, network, owner, key, startHeight };
}

/**
 * NEAR registration config: all of PLR_NEAR_RPC, the registry (`registryVar`), PLR_OPERATOR_ID and
 * PLR_OPERATOR_KEY, or none (→ null). @throws PlrError E_BAD_INPUT if partially set or invalid
 */
export function loadNear(env: Env, registryVar: string = "PLR_REGISTRY"): NearConfig | null {
  const nearVars = ["PLR_NEAR_RPC", registryVar, "PLR_OPERATOR_ID", "PLR_OPERATOR_KEY"] as const;
  const set = nearVars.filter((k) => (env[k] ?? "") !== "");
  let near: NearConfig | null = null;
  if (set.length === nearVars.length) {
    const rpcUrl = env.PLR_NEAR_RPC!;
    let u: URL;
    try {
      u = new URL(rpcUrl);
    } catch {
      bad("PLR_NEAR_RPC");
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") bad("PLR_NEAR_RPC");
    const contractId = env[registryVar]!;
    const operatorId = env.PLR_OPERATOR_ID!;
    const operatorKey = env.PLR_OPERATOR_KEY!;
    if (!NEAR_ACCOUNT_RE.test(contractId)) bad(registryVar);
    if (!NEAR_ACCOUNT_RE.test(operatorId)) bad("PLR_OPERATOR_ID");
    if (!NEAR_KEY_RE.test(operatorKey)) bad("PLR_OPERATOR_KEY");
    const dep = env.PLR_REGISTER_DEPOSIT || "100000000000000000000000";
    if (!/^[0-9]{1,40}$/.test(dep)) bad("PLR_REGISTER_DEPOSIT");
    const anchorDep = env.PLR_ANCHOR_DEPOSIT || DEFAULT_ANCHOR_DEPOSIT;
    if (!/^[0-9]{1,40}$/.test(anchorDep)) bad("PLR_ANCHOR_DEPOSIT");
    near = { rpcUrl, contractId, operatorId, operatorKey, registerDeposit: BigInt(dep), anchorDeposit: BigInt(anchorDep) };
  } else if (set.length > 0) {
    bad(`NEAR (PLR_NEAR_RPC, ${registryVar}, PLR_OPERATOR_ID, PLR_OPERATOR_KEY must be set together)`);
  }
  return near;
}
