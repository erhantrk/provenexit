/** Shared configuration helpers (registry selection, NEAR settings, bounded integers). Strictly validated; fail closed. */
import { PlrError } from "@plr/shared";
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

/** `PLR_CHAIN` values: the registry is on NEAR (the only writer in this build; `near` is also the default). */
export const CHAIN_NAMES = ["near"] as const;
export type ChainName = (typeof CHAIN_NAMES)[number];

/** The registry an instance registers on, selected by `PLR_CHAIN` (default `near`). */
export type RegistryConfig = { chain: "near"; near: NearConfig };

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

/** Which env variable names the registry (the VPN exit: PLR_VPN_REGISTRY, else PLR_REGISTRY). */
export interface RegistryVars {
  nearRegistryVar: string;
}

/**
 * The registry selected by `PLR_CHAIN` (default and only value `near`): null when none of the NEAR variables are set.
 * @throws PlrError E_BAD_INPUT on any other `PLR_CHAIN`, or partial/invalid variables
 */
export function loadRegistry(env: Env, vars: RegistryVars): RegistryConfig | null {
  const chainRaw = env.PLR_CHAIN === undefined || env.PLR_CHAIN === "" ? "near" : env.PLR_CHAIN;
  if (!(CHAIN_NAMES as readonly string[]).includes(chainRaw)) bad("PLR_CHAIN");
  const near = loadNear(env, vars.nearRegistryVar);
  return near === null ? null : { chain: "near", near };
}

/** {@link loadRegistry} that never throws: a configuration error disables registration (fail closed). */
export function loadRegistrySafe(env: Env, vars: RegistryVars): { registry: RegistryConfig | null; near: NearConfig | null; nearConfigError: boolean } {
  try {
    const registry = loadRegistry(env, vars);
    return { registry, near: registry?.near ?? null, nearConfigError: false };
  } catch {
    return { registry: null, near: null, nearConfigError: true };
  }
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
