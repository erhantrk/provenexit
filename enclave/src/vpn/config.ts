/** VPN exit configuration from the environment (set by the mock TDX host). Strictly validated; fail closed. */
import { HOST_RE, bad, intVar, loadRegistrySafe, type Env, type NearConfig, type RegistryConfig } from "../config.js";

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
  /** The selected VPN registry (any chain, `PLR_CHAIN`), or null (unregistered: clients refuse). */
  registry: RegistryConfig | null;
  /** True if the selected chain's variables were present but incomplete/invalid: registration is disabled (clients refuse). */
  nearConfigError: boolean;
}

/**
 * PLR_TDX_SOCKET, PLR_APP_COMPOSE_PATH (from the host), PLR_VPN_HOST (default 127.0.0.1), PLR_VPN_PORT (default
 * 18200, 0 = ephemeral), PLR_ANCHOR_INTERVAL_MS, and the NEAR variables of the router (PLR_NEAR_RPC,
 * PLR_OPERATOR_ID, PLR_OPERATOR_KEY, PLR_REGISTER_DEPOSIT, PLR_ANCHOR_DEPOSIT) with the VPN registry in
 * PLR_VPN_REGISTRY, or else PLR_REGISTRY. With `PLR_CHAIN=zcash` (SPEC-CHAINS §5): PLR_ZCASH_RPC, PLR_ZCASH_NETWORK,
 * PLR_ZCASH_KEY, PLR_ZCASH_START_HEIGHT and the VPN registry owner in PLR_ZCASH_VPN_OWNER, or else PLR_ZCASH_OWNER.
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
  const nearRegistryVar = (env.PLR_VPN_REGISTRY ?? "") !== "" ? "PLR_VPN_REGISTRY" : "PLR_REGISTRY";
  const zcashOwnerVar = (env.PLR_ZCASH_VPN_OWNER ?? "") !== "" ? "PLR_ZCASH_VPN_OWNER" : "PLR_ZCASH_OWNER";
  // Each chain: the VPN registry variable if set, else the shared one (a lone exit may use the plain name).
  const vpnVar = (vpn: string, plain: string): string => ((env[vpn] ?? "") !== "" ? vpn : plain);
  const { registry, near, nearConfigError } = loadRegistrySafe(env, {
    nearRegistryVar,
    zcashOwnerVar,
    evmRegistryVar: vpnVar("PLR_EVM_VPN_REGISTRY", "PLR_EVM_REGISTRY"),
    stellarRegistryVar: vpnVar("PLR_STELLAR_VPN_REGISTRY", "PLR_STELLAR_REGISTRY"),
    solanaRegistryVar: vpnVar("PLR_SOLANA_VPN_REGISTRY", "PLR_SOLANA_REGISTRY"),
  });
  return { tdxSocket, composePath, host, port, anchorIntervalMs, near, registry, nearConfigError };
}
