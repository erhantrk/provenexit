#!/usr/bin/env node
/**
 * `plr` CLI (SPEC §12): `plr verify` | `plr chat "<prompt>"` | `plr chat` / `plr chat -` (prompt from stdin) | `plr proxy`;
 * VPN (SPEC-VPN §9.2): `plr vpn` (local SOCKS5 on 127.0.0.1:18180) | `plr vpn verify`.
 * Reading the prompt from stdin is recommended: argv is visible to other local users (`ps`) and lands in
 * shell history.
 * Config via env: PLR_ROUTER_URL, PLR_NEAR_RPC, PLR_REGISTRY, PLR_TRUSTED_ROOT (128 hex);
 * optional PLR_PROXY_PORT (default 18787) and PLR_PROXY_HOST (default 127.0.0.1).
 * VPN env: PLR_VPN_URL, PLR_VPN_REGISTRY, PLR_NEAR_RPC, PLR_TRUSTED_ROOT; optional PLR_VPN_SOCKS_PORT (default 18180),
 * PLR_VPN_ATTEST_TTL_MS (default 60000), PLR_VPN_ENTRY_URL (set ⇒ two-hop, SPEC-VPN §10, with PLR_VPN_URL as the exit).
 * Chain (SPEC-CHAINS §4, §5): PLR_CHAIN = near (default) | zcash. Zcash: PLR_ZCASH_RPC, PLR_ZCASH_NETWORK,
 * PLR_ZCASH_OWNER (or PLR_REGISTRY / PLR_VPN_REGISTRY = `zcash:<network>:<owner>`), PLR_ZCASH_START_HEIGHT.
 */
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { PlrError, isHex, isPlrError, isTAddress, isValidP256Pub, isZcashNetwork, fromHex, toHex, type RegistryReader, type ZcashNetwork } from "@plr/shared";
import { NearRegistry, checkRpcUrl } from "./near-registry.js";
import { ZcashRegistry, parseZcashContractId } from "./zcash-registry.js";
import { PrivateClient } from "./client.js";
import { startProxy } from "./proxy.js";
import { TracingRegistry, checkLines, formatCheckLine } from "./verify-report.js";
import { recheckRegistry, type AttestationSession } from "./attestation.js";
import { VpnClient, VPN_ATTEST_TTL_MS } from "./vpn/client.js";
import { TwoHopClient } from "./vpn/twohop.js";
import { startVpn, type VpnConnector } from "./vpn/socks5-server.js";

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
}

/** Registry chains this client can read (SPEC-CHAINS §1); other `PLR_CHAIN` values are refused. */
export type CliChain = "near" | "zcash";

/** Zcash reader settings (SPEC-CHAINS §5). */
export interface ZcashCliConfig {
  network: ZcashNetwork;
  owner: string;
  startHeight: number;
  /** Max wall time of the first catch-up (PLR_ZCASH_SYNC_TIMEOUT_MS; the reader's default otherwise). */
  syncTimeoutMs?: number;
}

export interface CliConfig {
  chain: CliChain;
  routerUrl: string;
  rpcUrl: string;
  contractId: string;
  /** Set iff `chain` is zcash. */
  zcash?: ZcashCliConfig;
  trustedRoot: Uint8Array;
  proxyPort: number;
  proxyHost: string;
}

export interface VpnCliConfig {
  exitUrl: string;
  /** Entry exit URL: set ⇒ two-hop (SPEC-VPN §10) with `exitUrl` as the exit. */
  entryUrl: string | undefined;
  chain: CliChain;
  rpcUrl: string;
  contractId: string;
  /** Set iff `chain` is zcash. */
  zcash?: ZcashCliConfig;
  trustedRoot: Uint8Array;
  socksPort: number;
  attestTtlMs: number;
}

const DEFAULTS = {
  router: "http://127.0.0.1:18100",
  rpc: "http://127.0.0.1:3030",
  /** Zebra's default RPC ports: 8232 (mainnet), 18232 (testnet / regtest). */
  zcashRpc: (n: ZcashNetwork): string => `http://127.0.0.1:${n === "mainnet" ? 8232 : 18232}`,
  proxyPort: 18787,
  proxyHost: "127.0.0.1",
  vpnExit: "http://127.0.0.1:18200",
  vpnSocksPort: 18180,
};

/** Max prompt read from stdin (the router's request limit is 1 MiB of ciphertext). */
export const MAX_STDIN_PROMPT = 512 * 1024;

const CHAT_USAGE = `usage: plr chat              read the prompt from stdin (recommended), e.g.  plr chat < prompt.txt
       plr chat -            same
       plr chat "<prompt>"   prompt as an argument (visible in \`ps\` and shell history)`;

const VPN_USAGE = `usage: plr vpn             verify the VPN exit, then serve a local SOCKS5 proxy (remote DNS) on
                            socks5h://127.0.0.1:${DEFAULTS.vpnSocksPort}, e.g.  curl --proxy socks5h://127.0.0.1:${DEFAULTS.vpnSocksPort} https://example.com
       plr vpn verify      print every attestation + registry check of the VPN exit (✔/✘); in two-hop mode both
                            hops and the operator-organization check
env:   PLR_VPN_URL       VPN exit URL (default ${DEFAULTS.vpnExit})
       PLR_VPN_ENTRY_URL entry exit URL; when set, traffic goes client → entry → exit (two-hop): the exit is
                            reached only through the entry and must belong to a different approved organization
       PLR_VPN_REGISTRY  VPN registry contract account id (required; a separate deployment from PLR_REGISTRY)
       PLR_NEAR_RPC      (default ${DEFAULTS.rpc}; https, or http to a loopback host only)
       PLR_TRUSTED_ROOT  pinned attestation root, 128 hex (required)
       PLR_VPN_SOCKS_PORT (default ${DEFAULTS.vpnSocksPort}), PLR_VPN_ATTEST_TTL_MS (default ${VPN_ATTEST_TTL_MS}; 0 = attest every connection)`;

const USAGE = `usage: plr verify | plr chat [-|"<prompt>"] | plr proxy | plr vpn [verify]
       plr chat reads the prompt from stdin when no argument (or "-") is given — recommended, since argv is
       visible to other local processes and saved in shell history.
env:   PLR_ROUTER_URL (default ${DEFAULTS.router})
       PLR_NEAR_RPC   (default ${DEFAULTS.rpc}; https, or http to a loopback host only)
       PLR_REGISTRY   registry contract account id (required)
       PLR_TRUSTED_ROOT  pinned attestation root, 128 hex (required)
       PLR_PROXY_PORT (default ${DEFAULTS.proxyPort}), PLR_PROXY_HOST (default ${DEFAULTS.proxyHost})
chain: PLR_CHAIN      near (default) | zcash — which chain holds the registry
       zcash:  PLR_ZCASH_RPC (Zebra JSON-RPC; https, or http to a loopback host only; default http://127.0.0.1:18232,
               8232 on mainnet), PLR_ZCASH_NETWORK (regtest | testnet | mainnet), PLR_ZCASH_OWNER (registry owner
               t-address; or PLR_REGISTRY / PLR_VPN_REGISTRY = zcash:<network>:<owner>), PLR_ZCASH_START_HEIGHT (default 0),
               PLR_ZCASH_SYNC_TIMEOUT_MS (first catch-up bound, default 60000)
vpn:   ${VPN_USAGE.replace(/\n/g, "\n       ")}`;

export class ConfigError extends Error {}

function trustedRootFrom(env: Record<string, string | undefined>): Uint8Array {
  const rootHex = env.PLR_TRUSTED_ROOT;
  if (!isHex(rootHex, 64)) throw new ConfigError("PLR_TRUSTED_ROOT must be 128 lowercase hex chars");
  const trustedRoot = fromHex(rootHex, 64);
  if (!isValidP256Pub(trustedRoot)) throw new ConfigError("PLR_TRUSTED_ROOT is not a valid P-256 public key");
  return trustedRoot;
}

function rpcUrlFrom(env: Record<string, string | undefined>): string {
  const rpcUrl = env.PLR_NEAR_RPC || DEFAULTS.rpc;
  try {
    checkRpcUrl(rpcUrl);
  } catch {
    throw new ConfigError("PLR_NEAR_RPC must be an https URL (plain http only to a loopback host: the RPC decides the registry checks)");
  }
  return rpcUrl;
}

function portFrom(env: Record<string, string | undefined>, name: string, dflt: number): number {
  const portStr = env[name] ?? String(dflt);
  if (!/^\d{1,5}$/.test(portStr) || Number(portStr) > 65535) throw new ConfigError(`${name} must be a port number`);
  return Number(portStr);
}

function chainFrom(env: Record<string, string | undefined>): CliChain {
  const c = env.PLR_CHAIN || "near";
  if (c === "near" || c === "zcash") return c;
  if (c === "evm" || c === "stellar" || c === "solana") throw new ConfigError(`PLR_CHAIN=${c} is not supported by this client yet (near | zcash)`);
  throw new ConfigError("PLR_CHAIN must be near or zcash");
}

/**
 * Zcash registry settings: the registry id comes from `registryVar` (`zcash:<network>:<owner>`) or from
 * PLR_ZCASH_OWNER + PLR_ZCASH_NETWORK; when both are given they must agree. Never guesses the network.
 */
function zcashFrom(
  env: Record<string, string | undefined>,
  registryVar: "PLR_REGISTRY" | "PLR_VPN_REGISTRY",
): { rpcUrl: string; contractId: string; zcash: ZcashCliConfig } {
  const netEnv = env.PLR_ZCASH_NETWORK || undefined;
  if (netEnv !== undefined && !isZcashNetwork(netEnv)) throw new ConfigError("PLR_ZCASH_NETWORK must be regtest, testnet or mainnet");
  const ownerEnv = env.PLR_ZCASH_OWNER || undefined;
  const regEnv = env[registryVar] || undefined;
  let network: ZcashNetwork;
  let owner: string;
  if (regEnv !== undefined) {
    const id = parseZcashContractId(regEnv);
    if (id === null) throw new ConfigError(`${registryVar} must be zcash:<regtest|testnet|mainnet>:<owner t-address> when PLR_CHAIN=zcash`);
    if (netEnv !== undefined && netEnv !== id.network) throw new ConfigError(`PLR_ZCASH_NETWORK disagrees with ${registryVar}`);
    // PLR_ZCASH_OWNER names the LLM registry owner; the VPN registry (PLR_VPN_REGISTRY) has its own owner.
    if (registryVar === "PLR_REGISTRY" && ownerEnv !== undefined && ownerEnv !== id.owner) throw new ConfigError("PLR_ZCASH_OWNER disagrees with PLR_REGISTRY");
    ({ network, owner } = id);
  } else {
    if (netEnv === undefined) throw new ConfigError("PLR_ZCASH_NETWORK is required (regtest | testnet | mainnet)");
    if (ownerEnv === undefined) throw new ConfigError(`PLR_ZCASH_OWNER (registry owner t-address) or ${registryVar} is required`);
    if (!isTAddress(ownerEnv, netEnv)) throw new ConfigError(`PLR_ZCASH_OWNER is not a P2PKH t-address on ${netEnv}`);
    network = netEnv;
    owner = ownerEnv;
  }
  const rpcUrl = env.PLR_ZCASH_RPC || DEFAULTS.zcashRpc(network);
  try {
    checkRpcUrl(rpcUrl);
  } catch {
    throw new ConfigError("PLR_ZCASH_RPC must be an https URL (plain http only to a loopback host: the node decides the registry checks)");
  }
  const startStr = env.PLR_ZCASH_START_HEIGHT || "0";
  if (!/^\d{1,10}$/.test(startStr) || Number(startStr) > 2 ** 31 - 1) throw new ConfigError("PLR_ZCASH_START_HEIGHT must be a block height");
  const syncStr = env.PLR_ZCASH_SYNC_TIMEOUT_MS || undefined;
  if (syncStr !== undefined && (!/^\d{1,6}$/.test(syncStr) || Number(syncStr) < 1 || Number(syncStr) > 900_000)) {
    throw new ConfigError("PLR_ZCASH_SYNC_TIMEOUT_MS must be 1..900000");
  }
  const zcash: ZcashCliConfig = { network, owner, startHeight: Number(startStr), ...(syncStr !== undefined ? { syncTimeoutMs: Number(syncStr) } : {}) };
  return { rpcUrl, contractId: `zcash:${network}:${owner}`, zcash };
}

/** Registry location for the selected chain: NEAR (PLR_NEAR_RPC + `registryVar`) or Zcash (SPEC-CHAINS §5 env). */
function registryFrom(
  env: Record<string, string | undefined>,
  registryVar: "PLR_REGISTRY" | "PLR_VPN_REGISTRY",
): { chain: CliChain; rpcUrl: string; contractId: string; zcash?: ZcashCliConfig } {
  const chain = chainFrom(env);
  if (chain === "zcash") return { chain, ...zcashFrom(env, registryVar) };
  const contractId = env[registryVar];
  if (contractId === undefined || contractId === "") throw new ConfigError(`${registryVar} is required`);
  return { chain, rpcUrl: rpcUrlFrom(env), contractId };
}

/** The registry reader for a loaded config. */
export function makeRegistry(cfg: { chain: CliChain; rpcUrl: string; contractId: string; zcash?: ZcashCliConfig }): RegistryReader {
  if (cfg.chain === "zcash") {
    const z = cfg.zcash;
    if (z === undefined) throw new ConfigError("zcash settings missing");
    return new ZcashRegistry({
      rpcUrl: cfg.rpcUrl, network: z.network, owner: z.owner, startHeight: z.startHeight,
      ...(z.syncTimeoutMs !== undefined ? { syncTimeoutMs: z.syncTimeoutMs } : {}),
    });
  }
  return new NearRegistry({ rpcUrl: cfg.rpcUrl, contractId: cfg.contractId });
}

/** SPEC-CHAINS §1 tier of a registry, for display only (safety never depends on it, only on `verifiesOnChain`). */
export function registryTier(r: RegistryReader): "A" | "B" | "C" {
  if (r.verifiesOnChain === true) return "A";
  return r.chain === "zcash" ? "C" : "B";
}

/** `plr verify` header line: the registry's tier and what the client adds (SPEC-CHAINS §1, §2). */
function tierLine(r: RegistryReader): string {
  const t = registryTier(r);
  return r.verifiesOnChain === true
    ? `  tier:     ${t} — the registry contract verified the registration quote on-chain`
    : `  tier:     ${t} — the chain does not verify quotes: this client checks the registration evidence and anchor signatures`;
}

/** Reads and validates the env config. Fails closed: no trusted root ⇒ no default. */
export function loadConfig(env: Record<string, string | undefined>): CliConfig {
  const reg = registryFrom(env, "PLR_REGISTRY");
  const trustedRoot = trustedRootFrom(env);
  const proxyPort = portFrom(env, "PLR_PROXY_PORT", DEFAULTS.proxyPort);
  return {
    ...reg,
    routerUrl: env.PLR_ROUTER_URL || DEFAULTS.router,
    trustedRoot,
    proxyPort,
    proxyHost: env.PLR_PROXY_HOST || DEFAULTS.proxyHost,
  };
}

/** VPN env config (SPEC-VPN §9.2). Fails closed: the VPN registry and the trusted root have no default. */
export function loadVpnConfig(env: Record<string, string | undefined>): VpnCliConfig {
  const reg = registryFrom(env, "PLR_VPN_REGISTRY");
  const trustedRoot = trustedRootFrom(env);
  const socksPort = portFrom(env, "PLR_VPN_SOCKS_PORT", DEFAULTS.vpnSocksPort);
  const ttlStr = env.PLR_VPN_ATTEST_TTL_MS ?? String(VPN_ATTEST_TTL_MS);
  if (!/^\d{1,7}$/.test(ttlStr) || Number(ttlStr) > 3_600_000) throw new ConfigError("PLR_VPN_ATTEST_TTL_MS must be 0..3600000");
  const exitUrl = env.PLR_VPN_URL || DEFAULTS.vpnExit;
  const entryUrl = env.PLR_VPN_ENTRY_URL || undefined;
  if (!isHttpUrl(exitUrl)) throw new ConfigError("PLR_VPN_URL must be an http(s) URL");
  if (entryUrl !== undefined && !isHttpUrl(entryUrl)) throw new ConfigError("PLR_VPN_ENTRY_URL must be an http(s) URL");
  return { exitUrl, entryUrl, ...reg, trustedRoot, socksPort, attestTtlMs: Number(ttlStr) };
}

function isHttpUrl(u: string): boolean {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function errCode(e: unknown): string {
  return isPlrError(e) ? e.code : e instanceof Error ? e.message : "error";
}

async function cmdVerify(cfg: CliConfig, registry: TracingRegistry, client: PrivateClient, io: CliIo): Promise<number> {
  io.out(`PLR verify`);
  io.out(`  router:   ${client.routerUrl}`);
  io.out(`  registry: ${registry.contractId} on ${registry.chain} (${cfg.rpcUrl})`);
  io.out(tierLine(registry));
  io.out(`  pinned root: ${client.rootKind} ROOT ${toHex(cfg.trustedRoot)}`);
  io.out("");
  let verified;
  try {
    verified = await client.attest();
  } catch (e) {
    for (const l of checkLines(e, registry.lastCall, { evidence: !registry.verifiesOnChain })) io.out(formatCheckLine(l));
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. Nothing would be sent to this router.`);
    return 1;
  }
  for (const l of checkLines(undefined, undefined, { evidence: !registry.verifiesOnChain })) io.out(formatCheckLine(l));
  io.out("");
  io.out(`✔ VERIFIED`);
  io.out(`  root:            ${verified.rootKind} ROOT${verified.rootKind === "MOCK" ? " (local test root, NOT Intel)" : ""}`);
  io.out(`  compose hash:    ${toHex(verified.composeHash)}`);
  io.out(`  OS measurement:  ${toHex(verified.osMeasurement)}`);
  io.out(`  key hash:        ${toHex(verified.keyHash)}`);
  io.out(`  router x25519:   ${toHex(verified.x25519)}`);
  io.out(`  router ed25519:  ${toHex(verified.ed25519)}`);
  try {
    const inst = await registry.inner.getInstance(toHex(verified.keyHash));
    if (inst === null) {
      io.out(`  on-chain instance: (none — registration expired since verification)`);
    } else {
      io.out(`  on-chain instance:`);
      io.out(`    operator:      ${inst.operator}`);
      io.out(`    registered at: ${new Date(inst.registered_at_ms).toISOString()}`);
      io.out(`    expires at:    ${new Date(inst.expires_at_ms).toISOString()}`);
      io.out(`    next seq:      ${inst.next_seq}`);
    }
  } catch {
    io.out(`  on-chain instance: (registry unavailable)`);
  }
  return 0;
}

async function cmdChat(prompt: string, client: PrivateClient, io: CliIo, writeDelta: (s: string) => void): Promise<number> {
  try {
    const r = await client.chat({ messages: [{ role: "user", content: prompt }] }, { onDelta: writeDelta });
    writeDelta("\n");
    io.err(`✔ verified ${r.verified.rootKind} ROOT · compose ${r.receipt.compose_hash}`);
    io.err(`✔ receipt seq ${r.receipt.seq} · sig ${r.sig.slice(0, 16)}… (Ed25519, verified)`);
    return 0;
  } catch (e) {
    writeDelta("\n");
    io.err(`✘ ${errCode(e)}`);
    return 1;
  }
}

/** Build name, egress and DNS policy from the verified compose (its bytes were checked against the quote; plr-vpn or plr-combo). */
function composeSummary(appCompose: string): { name: string; egress: string; testBuild: boolean } {
  try {
    type Policy = { egress?: { allow_loopback?: unknown; deny_private?: unknown }; dns?: { doh?: unknown } };
    const j = JSON.parse(appCompose) as { name?: unknown; policy?: Policy; vpn?: { policy?: Policy } };
    const name = typeof j.name === "string" ? j.name : "?";
    // A `plr-combo` (SPEC-COMBO §1) carries the exit's policy under `vpn.policy`.
    const policy = name === "plr-combo" ? j.vpn?.policy : j.policy;
    const eg = policy?.egress;
    if (typeof eg !== "object" || eg === null) return { name, egress: "(no VPN egress policy)", testBuild: false };
    const testBuild = eg.allow_loopback === true;
    const doh = policy?.dns?.doh;
    const dns = Array.isArray(doh) && doh.every((u) => typeof u === "string") ? ` · DNS over HTTPS via ${doh.join(", ")}` : "";
    return { name, egress: `deny_private=${String(eg.deny_private)} allow_loopback=${String(eg.allow_loopback)}${dns}`, testBuild };
  } catch {
    return { name: "?", egress: "(unparseable)", testBuild: false };
  }
}

function printVpnSummary(io: CliIo, s: AttestationSession, ind = "  "): void {
  const v = s.verified;
  const c = composeSummary(s.appCompose);
  io.out(`${ind}root:            ${v.rootKind} ROOT${v.rootKind === "MOCK" ? " (local test root, NOT Intel)" : ""}`);
  io.out(`${ind}build:           ${c.name} · egress ${c.egress}${c.testBuild ? "  ⚠ TEST BUILD (loopback egress allowed)" : ""}`);
  io.out(`${ind}compose hash:    ${toHex(v.composeHash)}`);
  io.out(`${ind}OS measurement:  ${toHex(v.osMeasurement)}`);
  io.out(`${ind}key hash:        ${toHex(v.keyHash)}`);
  io.out(`${ind}exit x25519:     ${toHex(v.x25519)}`);
  io.out(`${ind}exit ed25519:    ${toHex(v.ed25519)}`);
}

async function printInstance(io: CliIo, registry: TracingRegistry, s: AttestationSession, ind = "  "): Promise<void> {
  try {
    const inst = await registry.inner.getInstance(toHex(s.verified.keyHash));
    if (inst === null) {
      io.out(`${ind}on-chain instance: (none — registration expired since verification)`);
    } else {
      io.out(`${ind}on-chain instance:`);
      io.out(`${ind}  operator:      ${inst.operator}`);
      io.out(`${ind}  organization:  ${inst.org_id ?? "(not approved)"}`);
      io.out(`${ind}  registered at: ${new Date(inst.registered_at_ms).toISOString()}`);
      io.out(`${ind}  expires at:    ${new Date(inst.expires_at_ms).toISOString()}`);
      io.out(`${ind}  next seq:      ${inst.next_seq}`);
    }
  } catch {
    io.out(`${ind}on-chain instance: (registry unavailable)`);
  }
}

const RECHECK_LINE = "registry re-check before each connection (compose, OS, instance)";

async function cmdVpnVerify(cfg: VpnCliConfig, registry: TracingRegistry, client: VpnClient, io: CliIo): Promise<number> {
  io.out(`PLR VPN verify`);
  io.out(`  exit:     ${client.exitUrl}`);
  io.out(`  registry: ${registry.contractId} on ${registry.chain} (${cfg.rpcUrl})`);
  io.out(tierLine(registry));
  io.out(`  pinned root: ${client.rootKind} ROOT ${toHex(cfg.trustedRoot)}`);
  io.out("");
  let session: AttestationSession;
  try {
    session = await client.attestSession();
  } catch (e) {
    for (const l of checkLines(e, registry.lastCall, { evidence: !registry.verifiesOnChain })) io.out(formatCheckLine(l));
    io.out(`  · ${RECHECK_LINE}  (not checked)`);
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. No connection would be tunnelled through this exit.`);
    return 1;
  }
  for (const l of checkLines(undefined, undefined, { evidence: !registry.verifiesOnChain })) io.out(formatCheckLine(l));
  try {
    await recheckRegistry(registry, session.verified);
    io.out(`  ✔ ${RECHECK_LINE}`);
  } catch (e) {
    io.out(`  ✘ ${RECHECK_LINE}  [${errCode(e)}]`);
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. No connection would be tunnelled through this exit.`);
    return 1;
  }
  io.out(`  ✔ ${REMOTE_DNS_LINE}`);
  io.out("");
  io.out(`✔ VERIFIED`);
  printVpnSummary(io, session);
  await printInstance(io, registry, session);
  return 0;
}

const REMOTE_DNS_LINE = "destinations resolved by the exit (remote DNS); the client never resolves them";

/** One hop of `plr vpn verify` in two-hop mode: SPEC §9 checks, registry re-check, org lines. Returns the org or the error. */
async function verifyHop(
  io: CliIo,
  registry: TracingRegistry,
  attest: () => Promise<AttestationSession>,
  check: (s: AttestationSession) => Promise<string>,
  orgLines: (code: string | undefined, org: string | undefined) => string[],
): Promise<{ session: AttestationSession; org: string } | { error: unknown }> {
  let session: AttestationSession;
  try {
    session = await attest();
  } catch (e) {
    for (const l of checkLines(e, registry.lastCall, { evidence: !registry.verifiesOnChain })) io.out(formatCheckLine(l));
    io.out(`  · ${RECHECK_LINE}  (not checked)`);
    for (const l of orgLines(undefined, undefined)) io.out(`  · ${l}  (not checked)`);
    return { error: e };
  }
  for (const l of checkLines(undefined, undefined, { evidence: !registry.verifiesOnChain })) io.out(formatCheckLine(l));
  try {
    const org = await check(session);
    io.out(`  ✔ ${RECHECK_LINE}`);
    for (const l of orgLines(undefined, org)) io.out(`  ✔ ${l}`);
    return { session, org };
  } catch (e) {
    const code = errCode(e);
    const orgFailure = code === "E_OPERATOR_UNAPPROVED" || code === "E_SAME_OPERATOR";
    io.out(orgFailure ? `  ✔ ${RECHECK_LINE}` : `  ✘ ${RECHECK_LINE}  [${code}]`);
    const lines = orgLines(code, undefined);
    let failedShown = !orgFailure;
    for (const [i, l] of lines.entries()) {
      // E_SAME_OPERATOR: the exit's operator is approved (first line passes), the second line fails.
      const passes = orgFailure && code === "E_SAME_OPERATOR" && i === 0;
      if (passes) io.out(`  ✔ ${l}`);
      else if (!failedShown) {
        io.out(`  ✘ ${l}  [${code}]`);
        failedShown = true;
      } else io.out(`  · ${l}  (not checked)`);
    }
    return { error: e };
  }
}

async function cmdTwoHopVerify(cfg: VpnCliConfig, registry: TracingRegistry, client: TwoHopClient, io: CliIo): Promise<number> {
  io.out(`PLR VPN verify (two-hop)`);
  io.out(`  entry:    ${client.entryUrl}`);
  io.out(`  exit:     ${client.exitUrl}  (reached only through the entry)`);
  io.out(`  registry: ${registry.contractId} on ${registry.chain} (${cfg.rpcUrl})`);
  io.out(tierLine(registry));
  io.out(`  pinned root: ${client.rootKind} ROOT ${toHex(cfg.trustedRoot)}`);
  io.out("");
  const refused = (e: unknown): number => {
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. No connection would be tunnelled through these hops.`);
    return 1;
  };
  io.out(`entry hop (direct)`);
  const entry = await verifyHop(io, registry, () => client.attestEntrySession(), (s) => client.checkEntry(s), (_c, org) => [
    `entry operator approved by the registry owner${org !== undefined ? ` (organization ${org})` : ""}`,
  ]);
  if ("error" in entry) {
    io.out(`exit hop  (not checked)`);
    return refused(entry.error);
  }
  io.out(`exit hop (attestation fetched through the entry; the exit is never contacted directly)`);
  const exit = await verifyHop(io, registry, () => client.attestExitSession(), (s) => client.checkExit(s, entry.org), (code, org) => [
    `exit operator approved by the registry owner${org !== undefined ? ` (organization ${org})` : code === "E_SAME_OPERATOR" ? ` (organization ${entry.org})` : ""}`,
    `entry and exit run by different organizations${org !== undefined ? ` (${entry.org} ≠ ${org})` : ""}`,
  ]);
  if ("error" in exit) return refused(exit.error);
  io.out(`  ✔ ${REMOTE_DNS_LINE}`);
  io.out(`  ✔ the entry sees only the exit's address; destinations and payload are end-to-end encrypted to the exit`);
  io.out("");
  io.out(`✔ VERIFIED (two-hop: ${entry.org} → ${exit.org})`);
  io.out(`entry:`);
  printVpnSummary(io, entry.session);
  await printInstance(io, registry, entry.session);
  io.out(`exit:`);
  printVpnSummary(io, exit.session);
  await printInstance(io, registry, exit.session);
  return 0;
}

async function serveSocks(cfg: VpnCliConfig, client: VpnConnector, io: CliIo): Promise<Awaited<ReturnType<typeof startVpn>> | undefined> {
  try {
    return await startVpn({ port: cfg.socksPort, host: "127.0.0.1", client });
  } catch {
    io.err(`✘ could not listen on 127.0.0.1:${cfg.socksPort} (PLR_VPN_SOCKS_PORT)`);
    return undefined;
  }
}

async function cmdVpn(cfg: VpnCliConfig, client: VpnClient, io: CliIo, untilStopped: () => Promise<void>): Promise<number> {
  let session: AttestationSession;
  try {
    session = await client.attestSession();
  } catch (e) {
    io.err(`✘ VPN exit verification failed: ${errCode(e)} — SOCKS5 proxy not started (run \`plr vpn verify\` for every check)`);
    return 1;
  }
  const p = await serveSocks(cfg, client, io);
  if (p === undefined) return 1;
  io.out(`✔ VPN exit verified (${session.verified.checks.length} checks against registry ${cfg.contractId}); every new connection re-checks the registry`);
  printVpnSummary(io, session);
  io.out(`✔ SOCKS5 proxy (remote DNS, CONNECT only) on ${p.url}`);
  io.out(`  e.g.  curl --proxy ${p.url} https://example.com`);
  await untilStopped();
  await p.close();
  return 0;
}

async function cmdTwoHop(cfg: VpnCliConfig, client: TwoHopClient, io: CliIo, untilStopped: () => Promise<void>): Promise<number> {
  let a;
  try {
    a = await client.attest();
  } catch (e) {
    io.err(`✘ two-hop VPN verification failed: ${errCode(e)} — SOCKS5 proxy not started (run \`plr vpn verify\` for every check)`);
    return 1;
  }
  const p = await serveSocks(cfg, client, io);
  if (p === undefined) return 1;
  io.out(`✔ two-hop VPN verified against registry ${cfg.contractId}: entry (${a.entryOrg}) → exit (${a.exitOrg}), different organizations`);
  io.out(`  entry: ${client.entryUrl}  compose ${toHex(a.entry.composeHash)}`);
  io.out(`  exit:  ${client.exitUrl}  compose ${toHex(a.exit.composeHash)}  (reached only through the entry)`);
  io.out(`  every new connection re-checks both hops and the operator rules`);
  io.out(`✔ SOCKS5 proxy (remote DNS, CONNECT only) on ${p.url}`);
  io.out(`  e.g.  curl --proxy ${p.url} https://example.com`);
  await untilStopped();
  await p.close();
  return 0;
}

function untilSignal(): Promise<void> {
  return new Promise<void>((resolve) => {
    const stop = (): void => resolve();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

/** `plr vpn [verify]`. */
async function runVpn(rest: string[], env: Record<string, string | undefined>, io: CliIo, untilStopped: () => Promise<void>): Promise<number> {
  const sub = rest[0];
  if (rest.length > 1 || (sub !== undefined && sub !== "verify")) {
    io.err(VPN_USAGE);
    return 2;
  }
  let cfg: VpnCliConfig;
  let registry: TracingRegistry;
  let client: VpnClient | TwoHopClient;
  try {
    cfg = loadVpnConfig(env);
    registry = new TracingRegistry(makeRegistry(cfg));
    const common = { registry, trustedRoot: cfg.trustedRoot, attestTtlMs: cfg.attestTtlMs };
    client =
      cfg.entryUrl !== undefined
        ? new TwoHopClient({ entryUrl: cfg.entryUrl, exitUrl: cfg.exitUrl, ...common })
        : new VpnClient({ exitUrl: cfg.exitUrl, ...common });
  } catch (e) {
    io.err(`config error: ${e instanceof ConfigError ? e.message : errCode(e)}`);
    io.err(VPN_USAGE);
    return 2;
  }
  if (client instanceof TwoHopClient) {
    if (sub === "verify") return cmdTwoHopVerify(cfg, registry, client, io);
    return cmdTwoHop(cfg, client, io, untilStopped);
  }
  if (sub === "verify") return cmdVpnVerify(cfg, registry, client, io);
  return cmdVpn(cfg, client, io, untilStopped);
}

class StdinTooLargeError extends Error {}

/** Reads all of process.stdin as UTF-8 (fatal decoding), refusing more than {@link MAX_STDIN_PROMPT} bytes. */
export async function readStdinText(stream: NodeJS.ReadableStream = process.stdin, max = MAX_STDIN_PROMPT): Promise<string> {
  const parts: Buffer[] = [];
  let n = 0;
  for await (const chunk of stream) {
    const b = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
    n += b.length;
    if (n > max) throw new StdinTooLargeError();
    parts.push(b);
  }
  const all = Buffer.concat(parts);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(all);
  } finally {
    all.fill(0);
    for (const p of parts) p.fill(0);
  }
}

/** Resolves the chat prompt: argv form, or stdin for no argument / "-". `null` ⇒ usage error. */
async function chatPrompt(rest: string[], readStdin: () => Promise<string>, io: CliIo): Promise<string | null> {
  if (rest.length > 1) return null;
  const arg = rest[0];
  if (arg !== undefined && arg !== "-") return arg === "" ? null : arg;
  let text: string;
  try {
    text = await readStdin();
  } catch (e) {
    io.err(e instanceof StdinTooLargeError ? `✘ prompt on stdin exceeds ${MAX_STDIN_PROMPT} bytes` : "✘ could not read the prompt from stdin (must be UTF-8)");
    return null;
  }
  // One trailing newline (from `echo` / heredocs) is not part of the prompt.
  const prompt = text.replace(/\r?\n$/, "");
  return prompt.trim() === "" ? null : prompt;
}

/** Runs the CLI; returns the exit code. `proxy` and `vpn` resolve only when `untilStopped` resolves (default: SIGINT/SIGTERM). */
export async function runCli(
  argv: string[],
  env: Record<string, string | undefined>,
  io: CliIo = { out: (s) => console.log(s), err: (s) => console.error(s) },
  writeDelta: (s: string) => void = (s) => void process.stdout.write(s),
  readStdin: () => Promise<string> = () => readStdinText(),
  untilStopped: () => Promise<void> = untilSignal,
): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === undefined || cmd === "-h" || cmd === "--help" || !["verify", "chat", "proxy", "vpn"].includes(cmd)) {
    io.err(USAGE);
    return 2;
  }
  if (cmd === "vpn") return runVpn(rest, env, io, untilStopped);
  if (cmd === "chat" && (rest.length > 1 || rest[0] === "-h" || rest[0] === "--help" || rest[0] === "")) {
    io.err(CHAT_USAGE);
    return 2;
  }
  let cfg: CliConfig;
  let registry: TracingRegistry;
  let client: PrivateClient;
  try {
    cfg = loadConfig(env);
    registry = new TracingRegistry(makeRegistry(cfg));
    client = new PrivateClient({ routerUrl: cfg.routerUrl, registry, trustedRoot: cfg.trustedRoot });
  } catch (e) {
    io.err(`config error: ${e instanceof ConfigError ? e.message : errCode(e)}`);
    io.err(USAGE);
    return 2;
  }
  if (cmd === "verify") return cmdVerify(cfg, registry, client, io);
  if (cmd === "chat") {
    // Config is valid: only now read the prompt (so a misconfigured CLI never consumes stdin).
    const prompt = await chatPrompt(rest, readStdin, io);
    if (prompt === null) {
      io.err(CHAT_USAGE);
      return 2;
    }
    return cmdChat(prompt, client, io, writeDelta);
  }

  try {
    await client.attest();
  } catch (e) {
    io.err(`✘ router verification failed: ${errCode(e)} — proxy not started`);
    return 1;
  }
  const p = await startProxy({ port: cfg.proxyPort, host: cfg.proxyHost, client });
  io.out(`✔ router verified (${client.rootKind} ROOT); OpenAI-compatible proxy on ${p.url}/v1`);
  await untilStopped();
  await p.close();
  return 0;
}

function isMain(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isMain()) {
  runCli(process.argv.slice(2), process.env).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      console.error(`✘ ${e instanceof PlrError ? e.code : "unexpected error"}`);
      process.exitCode = 1;
    },
  );
}
