/** VPN exit configuration from the environment (set by the mock TDX host). Strictly validated; fail closed. */
import { HOST_RE, bad, intVar, loadRegistrySafe, type Env, type NearConfig, type RegistryConfig } from "../config.js";

/** SPEC-VPN §3 default exit port. */
export const DEFAULT_EXIT_PORT = 18200;
/** INTERFACES §0 `PCCS_URL`: dcap-qvl's default PCCS. */
export const DEFAULT_PCCS_URL = "https://pccs.phala.network";

export interface ExitConfig {
  /** `PLR_ATTESTER`: `mock` (the mock TDX host, default) or `dstack` (a real TDX CVM). */
  attester: "mock" | "dstack";
  /** MOCK mode: the mock host's quote socket. Null in dstack mode (not required). */
  tdxSocket: string | null;
  /** MOCK mode: the measured compose path given by the host. Null in dstack mode (not required). */
  composePath: string | null;
  /** `PLR_VPN_POLICY_PATH`: the SPEC-VPN §2 compose baked into the image. Required in dstack mode, null otherwise. */
  policyPath: string | null;
  /** `PLR_PCCS_URL`: the PCCS the exit fetches Intel collateral from (dstack mode). */
  pccsUrl: string;
  host: string;
  port: number;
  anchorIntervalMs: number;
  /** Registration + anchoring on the VPN registry, or null (unregistered: clients refuse). */
  near: NearConfig | null;
  /** The selected VPN registry (any chain, `PLR_CHAIN`), or null (unregistered: clients refuse). */
  registry: RegistryConfig | null;
  /** True if the selected chain's variables were present but incomplete/invalid: registration is disabled (clients refuse). */
  nearConfigError: boolean;
  /** `PLR_VPN_ALLOWED_PORTS` (comma list, e.g. `80,443`): destination ports the exit dials; null = any port. */
  allowedPorts: number[] | null;
  /** `PLR_VPN_MAX_TUNNELS`: concurrent tunnels (default 1024). */
  maxTunnels: number;
}

/**
 * PLR_TDX_SOCKET, PLR_APP_COMPOSE_PATH (from the host), PLR_VPN_HOST (default 127.0.0.1), PLR_VPN_PORT (default
 * 18200, 0 = ephemeral), PLR_ANCHOR_INTERVAL_MS, and the NEAR variables of the router (PLR_NEAR_RPC,
 * PLR_OPERATOR_ID, PLR_OPERATOR_KEY, PLR_REGISTER_DEPOSIT, PLR_ANCHOR_DEPOSIT) with the VPN registry in
 * PLR_VPN_REGISTRY, or else PLR_REGISTRY. With `PLR_CHAIN=zcash` (SPEC-CHAINS §5): PLR_ZCASH_RPC, PLR_ZCASH_NETWORK,
 * PLR_ZCASH_KEY, PLR_ZCASH_START_HEIGHT and the VPN registry owner in PLR_ZCASH_VPN_OWNER, or else PLR_ZCASH_OWNER.
 */
export function loadExitConfig(env: Env = process.env): ExitConfig {
  const attesterRaw = env.PLR_ATTESTER === undefined || env.PLR_ATTESTER === "" ? "mock" : env.PLR_ATTESTER;
  if (attesterRaw !== "mock" && attesterRaw !== "dstack") bad("PLR_ATTESTER");
  const attester = attesterRaw;
  const tdxSocket = env.PLR_TDX_SOCKET === undefined || env.PLR_TDX_SOCKET === "" ? null : env.PLR_TDX_SOCKET;
  const composePath = env.PLR_APP_COMPOSE_PATH === undefined || env.PLR_APP_COMPOSE_PATH === "" ? null : env.PLR_APP_COMPOSE_PATH;
  if (attester === "mock") {
    // The mock TDX host names its quote socket and the compose it launches (unchanged MOCK path).
    if (tdxSocket === null || tdxSocket.length > 1024) bad("PLR_TDX_SOCKET");
    if (composePath === null || composePath.length > 4096) bad("PLR_APP_COMPOSE_PATH");
  }
  const policyPathRaw = env.PLR_VPN_POLICY_PATH;
  const policyPath = policyPathRaw === undefined || policyPathRaw === "" ? null : policyPathRaw;
  if (policyPath !== null && policyPath.length > 4096) bad("PLR_VPN_POLICY_PATH");
  // dstack mode measures the dstack app-compose; the enforced VPN policy is the compose baked into the image.
  if (attester === "dstack" && policyPath === null) bad("PLR_VPN_POLICY_PATH");
  const pccsUrl = env.PLR_PCCS_URL === undefined || env.PLR_PCCS_URL === "" ? DEFAULT_PCCS_URL : env.PLR_PCCS_URL;
  if (pccsUrl.length > 2048) bad("PLR_PCCS_URL");
  let pccs: URL;
  try {
    pccs = new URL(pccsUrl);
  } catch {
    bad("PLR_PCCS_URL");
  }
  if (pccs.protocol !== "https:") bad("PLR_PCCS_URL");
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
  const portsRaw = env.PLR_VPN_ALLOWED_PORTS ?? "";
  let allowedPorts: number[] | null = null;
  if (portsRaw !== "") {
    if (portsRaw.length > 256 || !/^\d{1,5}(,\d{1,5})*$/.test(portsRaw)) bad("PLR_VPN_ALLOWED_PORTS");
    allowedPorts = portsRaw.split(",").map(Number);
    if (allowedPorts.some((p) => p < 1 || p > 65535)) bad("PLR_VPN_ALLOWED_PORTS");
  }
  const maxTunnels = intVar(env, "PLR_VPN_MAX_TUNNELS", 1024, 1, 1024);
  return { attester, tdxSocket, composePath, policyPath, pccsUrl, host, port, anchorIntervalMs, near, registry, nearConfigError, allowedPorts, maxTunnels };
}
