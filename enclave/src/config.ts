/** Router configuration from the environment (set by the mock TDX host). Strictly validated; fail closed. */
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
  near: NearConfig | null;
  /** True if NEAR variables were present but incomplete/invalid: registration is disabled (clients refuse). */
  nearConfigError: boolean;
}

type Env = Readonly<Record<string, string | undefined>>;

/** 0.01 NEAR: ~7× the storage of one anchor record; the contract refunds what is not used. */
export const DEFAULT_ANCHOR_DEPOSIT = "10000000000000000000000";

function bad(what: string): never {
  throw new PlrError("E_BAD_INPUT", `config ${what}`);
}

function intVar(env: Env, name: string, def: number, min: number, max: number): number {
  const v = env[name];
  if (v === undefined || v === "") return def;
  if (!/^[0-9]{1,10}$/.test(v)) bad(name);
  const n = Number(v);
  if (n < min || n > max) bad(name);
  return n;
}

const HOST_RE = /^(?:127\.0\.0\.1|0\.0\.0\.0|::1|::|localhost|(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))$/;

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

  let near: NearConfig | null = null;
  let nearConfigError = false;
  try {
    near = loadNear(env);
  } catch {
    nearConfigError = true;
  }
  return { tdxSocket, composePath, host, port, llmPort, llmApiKey, anchorIntervalMs, near, nearConfigError };
}

function loadNear(env: Env): NearConfig | null {
  const nearVars = ["PLR_NEAR_RPC", "PLR_REGISTRY", "PLR_OPERATOR_ID", "PLR_OPERATOR_KEY"] as const;
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
    const contractId = env.PLR_REGISTRY!;
    const operatorId = env.PLR_OPERATOR_ID!;
    const operatorKey = env.PLR_OPERATOR_KEY!;
    if (!NEAR_ACCOUNT_RE.test(contractId)) bad("PLR_REGISTRY");
    if (!NEAR_ACCOUNT_RE.test(operatorId)) bad("PLR_OPERATOR_ID");
    if (!NEAR_KEY_RE.test(operatorKey)) bad("PLR_OPERATOR_KEY");
    const dep = env.PLR_REGISTER_DEPOSIT || "100000000000000000000000";
    if (!/^[0-9]{1,40}$/.test(dep)) bad("PLR_REGISTER_DEPOSIT");
    const anchorDep = env.PLR_ANCHOR_DEPOSIT || DEFAULT_ANCHOR_DEPOSIT;
    if (!/^[0-9]{1,40}$/.test(anchorDep)) bad("PLR_ANCHOR_DEPOSIT");
    near = { rpcUrl, contractId, operatorId, operatorKey, registerDeposit: BigInt(dep), anchorDeposit: BigInt(anchorDep) };
  } else if (set.length > 0) {
    bad("NEAR (PLR_NEAR_RPC, PLR_REGISTRY, PLR_OPERATOR_ID, PLR_OPERATOR_KEY must be set together)");
  }
  return near;
}
