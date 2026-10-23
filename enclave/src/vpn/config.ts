/** VPN exit configuration from the environment (set by the mock TDX host). Strictly validated; fail closed. */
import { HOST_RE, bad, intVar, loadNear, type Env, type NearConfig } from "../config.js";

/** SPEC-VPN §3 default exit port. */
export const DEFAULT_EXIT_PORT = 18200;

export interface ExitConfig {
  tdxSocket: string;
  composePath: string;
  host: string;
  port: number;
  anchorIntervalMs: number;
  /** Registration + anchoring on the VPN registry, or null (unregistered: clients refuse). */
  near: NearConfig | null;
  /** True if NEAR variables were present but incomplete/invalid: registration is disabled (clients refuse). */
  nearConfigError: boolean;
}

/**
 * PLR_TDX_SOCKET, PLR_APP_COMPOSE_PATH (from the host), PLR_VPN_HOST (default 127.0.0.1), PLR_VPN_PORT (default
 * 18200, 0 = ephemeral), PLR_ANCHOR_INTERVAL_MS, and the NEAR variables of the router (PLR_NEAR_RPC,
 * PLR_OPERATOR_ID, PLR_OPERATOR_KEY, PLR_REGISTER_DEPOSIT, PLR_ANCHOR_DEPOSIT) with the VPN registry in
 * PLR_VPN_REGISTRY, or else PLR_REGISTRY.
 */
export function loadExitConfig(env: Env = process.env): ExitConfig {
  const tdxSocket = env.PLR_TDX_SOCKET;
  if (!tdxSocket || tdxSocket.length > 1024) bad("PLR_TDX_SOCKET");
  const composePath = env.PLR_APP_COMPOSE_PATH;
  if (!composePath || composePath.length > 4096) bad("PLR_APP_COMPOSE_PATH");
  const host = env.PLR_VPN_HOST || "127.0.0.1";
  if (!HOST_RE.test(host)) bad("PLR_VPN_HOST");
  const port = intVar(env, "PLR_VPN_PORT", DEFAULT_EXIT_PORT, 0, 65535);
  const anchorIntervalMs = intVar(env, "PLR_ANCHOR_INTERVAL_MS", 3000, 100, 3_600_000);
  const registryVar = (env.PLR_VPN_REGISTRY ?? "") !== "" ? "PLR_VPN_REGISTRY" : "PLR_REGISTRY";
  let near: NearConfig | null = null;
  let nearConfigError = false;
  try {
    near = loadNear(env, registryVar);
  } catch {
    nearConfigError = true;
  }
  return { tdxSocket, composePath, host, port, anchorIntervalMs, near, nearConfigError };
}
