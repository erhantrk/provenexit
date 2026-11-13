#!/usr/bin/env node
/**
 * `plr` CLI (SPEC-VPN §9.2): `plr vpn` (local SOCKS5 on 127.0.0.1:18180) | `plr vpn verify` |
 * `plr vpn verify --fixture <dir>` | `plr vpn inspect` (INTEL checks without the registry, for the owner's
 * allow_compose / allow_os).
 * Env: PLR_VPN_URL, PLR_VPN_REGISTRY, PLR_NEAR_RPC, PLR_TRUSTED_ROOT; optional PLR_VPN_REGISTRY_CODE_HASH (pinned
 * code hash of the registry account; shipped for the live registry), PLR_VPN_SOCKS_PORT (default 18180),
 * PLR_VPN_ATTEST_TTL_MS (default 60000), PLR_VPN_ENTRY_URL (set ⇒ two-hop, SPEC-VPN §10, with PLR_VPN_URL as the exit),
 * PLR_PCCS_URL (INTEL mode: the PCCS the client fetches fresh Intel collateral from; default Intel's PCS, `exit` = use the exit's copy).
 */
import { createHash, randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  DcapQvlVerifier,
  INTEL_ROOT_P256,
  MAX_DSTACK_COMPOSE_BYTES,
  PlrError,
  checkDstackComposePolicy,
  equalBytes,
  isCollateralJson,
  isDebug,
  isHex,
  isIntelRoot,
  isPlrError,
  isValidP256Pub,
  fromHex,
  keyHash,
  osMeasurement,
  parseQuote,
  sessionNonceDigest,
  toHex,
  utf8,
  verifyEventLogDstack,
  type AttestationBundle,
  type QuoteVerifier,
  type RegistryReader,
  type RootKind,
  type VerifiedRouter,
} from "@plr/shared";
import { NearRegistry, parseRpcUrls, resolveRegistryCodeHash } from "./near-registry.js";
import { TracingRegistry, checkLines, formatCheckLine, type CollateralMode } from "./verify-report.js";
import { recheckRegistry, type AttestationSession } from "./attestation.js";
import { COLLATERAL_FROM_EXIT, DEFAULT_PCCS_URL, collateralSource, fetchPccsCollateral, isPccsUrl, type CollateralSource } from "./pccs.js";
import { VpnClient, VPN_ATTEST_TTL_MS } from "./vpn/client.js";
import { TwoHopClient } from "./vpn/twohop.js";
import { startVpn, type VpnConnector } from "./vpn/socks5-server.js";
import { fetchAttestationDirect, normalizeExitUrl } from "./vpn/hop.js";
import { RECHECK_LINE, REMOTE_DNS_LINE } from "./vpn-report.js";
import { fixtureReplayLine, readFixture, verifyFixture } from "./fixture.js";

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
}

export interface VpnCliConfig {
  exitUrl: string;
  /** Entry exit URL: set ⇒ two-hop (SPEC-VPN §10) with `exitUrl` as the exit. */
  entryUrl: string | undefined;
  rpcUrl: string;
  /** The NEAR VPN registry contract account id (PLR_VPN_REGISTRY). */
  contractId: string;
  /**
   * Pinned `code_hash` of the registry account (`PLR_VPN_REGISTRY_CODE_HASH`, else the shipped pin of a known
   * registry). Undefined only with a MOCK root and an unknown registry (local demo): then only the id is pinned.
   */
  registryCodeHash: string | undefined;
  trustedRoot: Uint8Array;
  socksPort: number;
  attestTtlMs: number;
  /** `PLR_PCCS_URL` (INTEL mode): the PCCS to fetch fresh collateral from; undefined = `DEFAULT_PCCS_URL`, `"exit"` = use the exit's copy. */
  pccsUrl: string | undefined;
}

const DEFAULTS = {
  rpc: "http://127.0.0.1:3030",
  vpnExit: "http://127.0.0.1:18200",
  vpnSocksPort: 18180,
};

const VPN_USAGE = `usage: plr vpn             verify the VPN exit, then serve a local SOCKS5 proxy (remote DNS) on
                            socks5h://127.0.0.1:${DEFAULTS.vpnSocksPort}, e.g.  curl --proxy socks5h://127.0.0.1:${DEFAULTS.vpnSocksPort} https://example.com
       plr vpn verify      print every attestation + registry check of the VPN exit (✔/✘); in two-hop mode both
                            hops and the operator-organization check
       plr vpn verify --fixture <dir>
                            replay a captured fixture (SPEC-TDX §3.3); needs no network, uses the recorded
                            collateral and runs the DCAP check at the capture time
       plr vpn inspect     INTEL checks 1–7b without the registry: compose hash, OS measurement, key hash, TCB and
                            images — the values the owner approves with allow_compose / allow_os
env:   PLR_VPN_URL       VPN exit URL (default ${DEFAULTS.vpnExit})
       PLR_VPN_ENTRY_URL entry exit URL; when set, traffic goes client → entry → exit (two-hop): the exit is
                            reached only through the entry and must belong to a different approved organization
       PLR_VPN_REGISTRY  NEAR VPN registry contract account id (required)
       PLR_VPN_REGISTRY_CODE_HASH
                         pinned code hash of that account (base58, view_account.code_hash); checked before any
                            registry answer is used. Shipped for the live registry; required for any other
                            registry with the Intel root; optional (warning) with a MOCK root
       PLR_NEAR_RPC      NEAR RPC endpoint (default ${DEFAULTS.rpc}; https, or http to a loopback host only).
                            Several, separated by commas: every registry query goes to all of them and all must
                            give the same answer, else the exit is refused (E_REGISTRY_RPC_DISAGREE; an endpoint
                            that does not answer: E_REGISTRY_UNAVAILABLE)
       PLR_TRUSTED_ROOT  pinned attestation root, 128 hex (required)
       PLR_PCCS_URL      INTEL mode only: the PCCS this client fetches fresh Intel collateral from, instead of
                            trusting the exit's copy (https; default ${DEFAULT_PCCS_URL}, Intel's own
                            service). If it cannot be reached the exit is refused (E_COLLATERAL_FETCH).
                            PLR_PCCS_URL=${COLLATERAL_FROM_EXIT} opts out: use the collateral the exit serves (offline use)
       PLR_VPN_SOCKS_PORT (default ${DEFAULTS.vpnSocksPort}), PLR_VPN_ATTEST_TTL_MS (default ${VPN_ATTEST_TTL_MS}; 0 = attest every connection)`;

const USAGE = VPN_USAGE;

export class ConfigError extends Error {}

function trustedRootFrom(env: Record<string, string | undefined>): Uint8Array {
  const rootHex = env.PLR_TRUSTED_ROOT;
  if (!isHex(rootHex, 64)) throw new ConfigError("PLR_TRUSTED_ROOT must be 128 lowercase hex chars");
  const trustedRoot = fromHex(rootHex, 64);
  if (!isValidP256Pub(trustedRoot)) throw new ConfigError("PLR_TRUSTED_ROOT is not a valid P-256 public key");
  return trustedRoot;
}

/**
 * `PLR_PCCS_URL` (TASKS T24): unset ⇒ undefined (the client fetches from `DEFAULT_PCCS_URL`); `exit` ⇒ the opt-out
 * (use the bundle's collateral); else an https URL (SPEC-TDX §4.1).
 */
function pccsUrlFrom(env: Record<string, string | undefined>): string | undefined {
  const u = env.PLR_PCCS_URL || undefined;
  if (u !== undefined && u !== COLLATERAL_FROM_EXIT && !isPccsUrl(u)) {
    throw new ConfigError(`PLR_PCCS_URL must be an https URL (at most 2048 chars) or "${COLLATERAL_FROM_EXIT}"`);
  }
  return u;
}

/** `plr vpn verify` header line: where the Intel collateral of this run comes from (INTEL mode only). */
function collateralLine(c: CollateralSource | undefined): string | undefined {
  if (c === undefined) return undefined;
  return c.source === "pccs"
    ? `  collateral: fetched fresh by this client from ${c.url}`
    : `  collateral: the exit's own copy (PLR_PCCS_URL=${COLLATERAL_FROM_EXIT}); its freshness is not checked against a PCCS`;
}

function rpcUrlFrom(env: Record<string, string | undefined>): string {
  const rpcUrl = env.PLR_NEAR_RPC || DEFAULTS.rpc;
  try {
    // one URL, or several separated by commas (then all must give the same answers); stored normalised
    return parseRpcUrls(rpcUrl).length === 1 ? rpcUrl : parseRpcUrls(rpcUrl).map((u) => u.href).join(",");
  } catch {
    throw new ConfigError("PLR_NEAR_RPC must be an https URL, or several different ones separated by commas (plain http only to a loopback host: the RPC decides the registry checks)");
  }
}

/** `plr vpn verify` header: the RPC endpoint, or the list of endpoints that must all agree. */
function rpcLabel(rpcUrl: string): string {
  const urls = rpcUrl.split(",");
  return urls.length === 1 ? rpcUrl : `${urls.length} RPC endpoints that must give the same answers: ${urls.join(", ")}`;
}

function portFrom(env: Record<string, string | undefined>, name: string, dflt: number): number {
  const portStr = env[name] ?? String(dflt);
  if (!/^\d{1,5}$/.test(portStr) || Number(portStr) > 65535) throw new ConfigError(`${name} must be a port number`);
  return Number(portStr);
}

/** The NEAR registry reader for a loaded config. */
export function makeRegistry(cfg: { rpcUrl: string; contractId: string; registryCodeHash?: string | undefined }): RegistryReader {
  return new NearRegistry({
    rpcUrl: cfg.rpcUrl,
    contractId: cfg.contractId,
    ...(cfg.registryCodeHash !== undefined ? { codeHash: cfg.registryCodeHash } : {}),
  });
}

/** `plr vpn verify` header line: the registry code-hash pin, or the warning that there is none (MOCK only). */
function codePinLine(cfg: { registryCodeHash: string | undefined }): string {
  return cfg.registryCodeHash !== undefined
    ? `  pinned registry code hash: ${cfg.registryCodeHash}`
    : "  ⚠ registry code hash NOT pinned (MOCK root, local demo): only the account id is checked; set PLR_VPN_REGISTRY_CODE_HASH";
}

/** `plr vpn verify` header line: who verified the registration quote. */
const ONCHAIN_LINE = "  on-chain: the registry contract verified the registration quote itself";

/** VPN env config (SPEC-VPN §9.2). Fails closed: the VPN registry and the trusted root have no default. */
export function loadVpnConfig(env: Record<string, string | undefined>): VpnCliConfig {
  const contractId = env.PLR_VPN_REGISTRY;
  if (contractId === undefined || contractId === "") throw new ConfigError("PLR_VPN_REGISTRY is required");
  const rpcUrl = rpcUrlFrom(env);
  const trustedRoot = trustedRootFrom(env);
  let registryCodeHash: string | undefined;
  try {
    registryCodeHash = resolveRegistryCodeHash(contractId, env.PLR_VPN_REGISTRY_CODE_HASH, isIntelRoot(trustedRoot));
  } catch (e) {
    throw new ConfigError(e instanceof Error ? e.message : "PLR_VPN_REGISTRY_CODE_HASH");
  }
  const socksPort = portFrom(env, "PLR_VPN_SOCKS_PORT", DEFAULTS.vpnSocksPort);
  const ttlStr = env.PLR_VPN_ATTEST_TTL_MS ?? String(VPN_ATTEST_TTL_MS);
  if (!/^\d{1,7}$/.test(ttlStr) || Number(ttlStr) > 3_600_000) throw new ConfigError("PLR_VPN_ATTEST_TTL_MS must be 0..3600000");
  const exitUrl = env.PLR_VPN_URL || DEFAULTS.vpnExit;
  const entryUrl = env.PLR_VPN_ENTRY_URL || undefined;
  if (!isHttpUrl(exitUrl)) throw new ConfigError("PLR_VPN_URL must be an http(s) URL");
  if (entryUrl !== undefined && !isHttpUrl(entryUrl)) throw new ConfigError("PLR_VPN_ENTRY_URL must be an http(s) URL");
  return { exitUrl, entryUrl, rpcUrl, contractId, registryCodeHash, trustedRoot, socksPort, attestTtlMs: Number(ttlStr), pccsUrl: pccsUrlFrom(env) };
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

/** Root line of `plr verify` / `plr vpn verify` (SPEC-TDX §3.2). */
function rootLabel(kind: RootKind): string {
  return kind === "INTEL" ? "INTEL ROOT (Intel SGX Root CA)" : "MOCK ROOT (local test root, NOT Intel)";
}

/** Block-explorer line for a NEAR testnet registry (SPEC-TDX §3.2), else undefined. */
function explorerLine(cfg: { rpcUrl: string; contractId: string }): string | undefined {
  if (!cfg.rpcUrl.includes("testnet")) return undefined;
  return `  explorer: https://testnet.nearblocks.io/address/${cfg.contractId}`;
}

/** Build name, egress and DNS policy from the verified `plr-vpn` compose (its bytes were checked against the quote). */
function composeSummary(appCompose: string): { name: string; egress: string; testBuild: boolean } {
  try {
    type Policy = { egress?: { allow_loopback?: unknown; deny_private?: unknown }; dns?: { doh?: unknown } };
    const j = JSON.parse(appCompose) as { name?: unknown; policy?: Policy };
    const name = typeof j.name === "string" ? j.name : "?";
    const policy = j.policy;
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

function printVpnSummary(io: CliIo, s: Pick<AttestationSession, "verified" | "appCompose">, ind = "  "): void {
  const v = s.verified;
  io.out(`${ind}root:            ${rootLabel(v.rootKind)}`);
  if (v.rootKind === "INTEL") {
    // In INTEL mode the measured document is dstack's app-compose (SPEC-TDX §1.4), not the plr-vpn policy.
    io.out(`${ind}tcb:             ${v.tcbStatus ?? "?"}`);
    for (const image of v.images ?? []) io.out(`${ind}image:           ${image}`);
  } else {
    const c = composeSummary(s.appCompose);
    io.out(`${ind}build:           ${c.name} · egress ${c.egress}${c.testBuild ? "  ⚠ TEST BUILD (loopback egress allowed)" : ""}`);
  }
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

async function cmdVpnVerify(cfg: VpnCliConfig, registry: TracingRegistry, client: VpnClient, io: CliIo): Promise<number> {
  const opts = { intel: client.rootKind === "INTEL", collateral: client.collateral?.source ?? ("pccs" as const) };
  io.out(`PLR VPN verify`);
  io.out(`  exit:     ${client.exitUrl}`);
  io.out(`  registry: ${registry.contractId} on ${registry.chain} (${rpcLabel(cfg.rpcUrl)})`);
  io.out(ONCHAIN_LINE);
  const explorer = explorerLine(cfg);
  if (explorer !== undefined) io.out(explorer);
  io.out(`  pinned root: ${client.rootKind} ROOT ${toHex(cfg.trustedRoot)}`);
  io.out(codePinLine(cfg));
  const collateral = collateralLine(client.collateral);
  if (collateral !== undefined) io.out(collateral);
  io.out("");
  let session: AttestationSession;
  try {
    session = await client.attestSession();
  } catch (e) {
    for (const l of checkLines(e, registry.lastCall, { ...opts, codeHash: registry.codeHashState })) io.out(formatCheckLine(l));
    io.out(`  · ${RECHECK_LINE}  (not checked)`);
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. No connection would be tunnelled through this exit.`);
    return 1;
  }
  for (const l of checkLines(undefined, undefined, { ...opts, codeHash: registry.codeHashState })) io.out(formatCheckLine(l));
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

/** One hop of `plr vpn verify` in two-hop mode: SPEC §9 checks, registry re-check, org lines. Returns the org or the error. */
async function verifyHop(
  io: CliIo,
  registry: TracingRegistry,
  attest: () => Promise<AttestationSession>,
  check: (s: AttestationSession) => Promise<string>,
  orgLines: (code: string | undefined, org: string | undefined) => string[],
  opts: { intel: boolean; collateral: CollateralMode },
): Promise<{ session: AttestationSession; org: string } | { error: unknown }> {
  let session: AttestationSession;
  try {
    session = await attest();
  } catch (e) {
    for (const l of checkLines(e, registry.lastCall, { ...opts, codeHash: registry.codeHashState })) io.out(formatCheckLine(l));
    io.out(`  · ${RECHECK_LINE}  (not checked)`);
    for (const l of orgLines(undefined, undefined)) io.out(`  · ${l}  (not checked)`);
    return { error: e };
  }
  for (const l of checkLines(undefined, undefined, { ...opts, codeHash: registry.codeHashState })) io.out(formatCheckLine(l));
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
  const opts = { intel: client.rootKind === "INTEL", collateral: client.collateral?.source ?? ("pccs" as const) };
  io.out(`PLR VPN verify (two-hop)`);
  io.out(`  entry:    ${client.entryUrl}`);
  io.out(`  exit:     ${client.exitUrl}  (reached only through the entry)`);
  io.out(`  registry: ${registry.contractId} on ${registry.chain} (${rpcLabel(cfg.rpcUrl)})`);
  io.out(ONCHAIN_LINE);
  const explorer = explorerLine(cfg);
  if (explorer !== undefined) io.out(explorer);
  io.out(`  pinned root: ${client.rootKind} ROOT ${toHex(cfg.trustedRoot)}`);
  io.out(codePinLine(cfg));
  const collateral = collateralLine(client.collateral);
  if (collateral !== undefined) io.out(collateral);
  io.out("");
  const refused = (e: unknown): number => {
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. No connection would be tunnelled through these hops.`);
    return 1;
  };
  io.out(`entry hop (direct)`);
  const entry = await verifyHop(io, registry, () => client.attestEntrySession(), (s) => client.checkEntry(s), (_c, org) => [
    `entry operator approved by the registry owner${org !== undefined ? ` (organization ${org})` : ""}`,
  ], opts);
  if ("error" in entry) {
    io.out(`exit hop  (not checked)`);
    return refused(entry.error);
  }
  io.out(`exit hop (attestation fetched through the entry; the exit is never contacted directly)`);
  const exit = await verifyHop(io, registry, () => client.attestExitSession(), (s) => client.checkExit(s, entry.org), (code, org) => [
    `exit operator approved by the registry owner${org !== undefined ? ` (organization ${org})` : code === "E_SAME_OPERATOR" ? ` (organization ${entry.org})` : ""}`,
    `entry and exit run by different organizations${org !== undefined ? ` (${entry.org} ≠ ${org})` : ""}`,
  ], opts);
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

/** Values `plr vpn inspect` prints (the owner approves compose / OS with them, TASKS T15 step 4). */
export interface IntelInspection {
  composeHash: Uint8Array;
  osMeasurement: Uint8Array;
  keyHash: Uint8Array;
  tcbStatus: string;
  images: string[];
}

/**
 * INTEL checks 1–7b of `verifyAttestation` without the registry: response shape, quote structure + DCAP
 * signature (Intel root), DEBUG, report_data keys + nonce, dstack event log, compose hash, dstack compose policy.
 * `verifier` exists for tests only: a synthetic bundle has no Intel signature (same seam as `verifyFixture`).
 * @throws PlrError — the first failing check's code
 */
export function inspectIntelBundle(
  bundle: AttestationBundle,
  nonce: Uint8Array,
  verifier: QuoteVerifier & { lastStatus?: string } = new DcapQvlVerifier(INTEL_ROOT_P256),
): IntelInspection {
  if (bundle.v !== "PLR-v1" || bundle.root_kind !== "INTEL") throw new PlrError("E_ROOT_UNTRUSTED", "inspect needs an INTEL exit");
  if (!isHex(bundle.quote) || bundle.quote.length === 0) throw new PlrError("E_BAD_RESPONSE", "quote");
  if (!isCollateralJson(bundle.collateral)) throw new PlrError("E_BAD_RESPONSE", "collateral");
  if (!isHex(bundle.x25519, 32) || !isHex(bundle.ed25519, 32)) throw new PlrError("E_BAD_RESPONSE", "keys");
  if (!Array.isArray(bundle.event_log)) throw new PlrError("E_BAD_RESPONSE", "event_log");
  if (typeof bundle.app_compose !== "string" || bundle.app_compose.length === 0) throw new PlrError("E_BAD_RESPONSE", "app_compose");
  const composeBytes = utf8(bundle.app_compose);
  if (composeBytes.length > MAX_DSTACK_COMPOSE_BYTES) throw new PlrError("E_BAD_RESPONSE", "app_compose size");

  const quote = fromHex(bundle.quote);
  const parsed = parseQuote(quote, "INTEL");
  verifier.verify(quote, {
    collateral: bundle.collateral,
    nowSecs: Math.floor(Date.now() / 1000),
  });
  const report = parsed.report;
  if (isDebug(report)) throw new PlrError("E_DEBUG_TD");
  const kh = keyHash(fromHex(bundle.x25519, 32), fromHex(bundle.ed25519, 32));
  if (!equalBytes(report.reportData.subarray(0, 32), kh)) throw new PlrError("E_REPORT_DATA_KEYS");
  if (!equalBytes(report.reportData.subarray(32, 64), sessionNonceDigest(nonce))) throw new PlrError("E_NONCE");
  const ids = verifyEventLogDstack(bundle.event_log, report.rtmr[3]);
  if (!equalBytes(new Uint8Array(createHash("sha256").update(composeBytes).digest()), ids.composeHash)) {
    throw new PlrError("E_COMPOSE_MISMATCH");
  }
  const policy = checkDstackComposePolicy(bundle.app_compose);
  if (verifier.lastStatus === undefined) throw new PlrError("E_TCB_STATUS");
  return { composeHash: ids.composeHash, osMeasurement: osMeasurement(report), keyHash: kh, tcbStatus: verifier.lastStatus, images: policy.images };
}

/** `plr vpn inspect`: INTEL checks 1–7b with a fresh nonce, no registry (TASKS T15 step 4). */
async function cmdVpnInspect(env: Record<string, string | undefined>, io: CliIo, verifier?: QuoteVerifier): Promise<number> {
  const exitUrl = env.PLR_VPN_URL || DEFAULTS.vpnExit;
  if (!isHttpUrl(exitUrl)) {
    io.err("config error: PLR_VPN_URL must be an http(s) URL");
    io.err(VPN_USAGE);
    return 2;
  }
  let source: CollateralSource;
  try {
    source = collateralSource(pccsUrlFrom(env));
  } catch (e) {
    io.err(`config error: ${e instanceof ConfigError ? e.message : errCode(e)}`);
    io.err(VPN_USAGE);
    return 2;
  }
  io.out(`PLR VPN inspect`);
  io.out(`  exit:     ${exitUrl}`);
  io.out(`  root:     INTEL ROOT (Intel SGX Root CA)`);
  io.out(collateralLine(source) ?? "");
  io.out("");
  const nonce = new Uint8Array(randomBytes(32));
  let r: IntelInspection;
  try {
    let bundle = await fetchAttestationDirect(normalizeExitUrl(exitUrl), nonce);
    // Same rule as `vpn verify`: the TCB the owner reads here comes from collateral this client fetched itself.
    if (source.source === "pccs" && (bundle as AttestationBundle | null)?.root_kind === "INTEL") {
      if (!isHex(bundle.quote) || bundle.quote.length === 0 || bundle.quote.length > 2 * 8192) throw new PlrError("E_BAD_RESPONSE", "quote");
      bundle = { ...bundle, collateral: await fetchPccsCollateral(source.url, fromHex(bundle.quote)) };
    }
    r = inspectIntelBundle(bundle, nonce, verifier);
  } catch (e) {
    io.out(`✘ ${errCode(e)}`);
    return 1;
  }
  io.out(`compose hash:    ${toHex(r.composeHash)}`);
  io.out(`OS measurement:  ${toHex(r.osMeasurement)}`);
  io.out(`key hash:        ${toHex(r.keyHash)}`);
  io.out(`tcb:             ${r.tcbStatus}`);
  for (const image of r.images) io.out(`image:           ${image}`);
  return 0;
}

/** `plr vpn verify --fixture <dir>`: offline replay of a capture (SPEC-TDX §3.3). */
async function cmdVpnVerifyFixture(dir: string, io: CliIo): Promise<number> {
  io.out(`PLR VPN verify (fixture replay)`);
  io.out(`  fixture:  ${dir}`);
  let fixture: ReturnType<typeof readFixture>;
  try {
    fixture = readFixture(dir);
  } catch (e) {
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. The fixture could not be read.`);
    return 1;
  }
  io.out(`  exit:     ${fixture.meta.exit_url}`);
  io.out(`  registry: ${fixture.meta.registry} (snapshot, no network)`);
  io.out(`  pinned root: INTEL ROOT ${toHex(INTEL_ROOT_P256)}`);
  io.out(`  collateral: the recorded copy from the capture (offline replay; no PCCS is contacted)`);
  io.out("");
  const replay = { intel: true, collateral: "recorded" as const };
  let verified: VerifiedRouter;
  try {
    verified = await verifyFixture(dir);
  } catch (e) {
    for (const l of checkLines(e, undefined, replay)) io.out(formatCheckLine(l));
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. The fixture does not verify.`);
    return 1;
  }
  for (const l of checkLines(undefined, undefined, replay)) io.out(formatCheckLine(l));
  io.out("");
  io.out(fixtureReplayLine(fixture.meta));
  printVpnSummary(io, { verified, appCompose: fixture.bundle.app_compose });
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
  const nChecks = session.verified.checks.length + (cfg.registryCodeHash !== undefined ? 1 : 0);
  io.out(`✔ VPN exit verified (${nChecks} checks against registry ${cfg.contractId}); every new connection re-checks the registry`);
  if (cfg.registryCodeHash === undefined) io.out(codePinLine(cfg));
  printVpnSummary(io, session);
  io.out(`✔ SOCKS5 proxy on ${p.url}`);
  io.out("  remote DNS, CONNECT only");
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
  if (cfg.registryCodeHash === undefined) io.out(codePinLine(cfg));
  io.out(`  entry: ${client.entryUrl}  compose ${toHex(a.entry.composeHash)}`);
  io.out(`  exit:  ${client.exitUrl}  compose ${toHex(a.exit.composeHash)}  (reached only through the entry)`);
  io.out(`  every new connection re-checks both hops and the operator rules`);
  io.out(`✔ SOCKS5 proxy on ${p.url}`);
  io.out("  remote DNS, CONNECT only");
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

/** `plr vpn [verify [--fixture <dir>]] | inspect`. */
async function runVpn(
  rest: string[],
  env: Record<string, string | undefined>,
  io: CliIo,
  untilStopped: () => Promise<void>,
  inspectVerifier?: QuoteVerifier,
): Promise<number> {
  const sub = rest[0];
  if (sub === "inspect") {
    if (rest.length > 1) {
      io.err(VPN_USAGE);
      return 2;
    }
    return cmdVpnInspect(env, io, inspectVerifier);
  }
  if (sub === "verify" && rest[1] === "--fixture") {
    const dir = rest[2];
    if (rest.length !== 3 || dir === undefined || dir === "") {
      io.err(VPN_USAGE);
      return 2;
    }
    return cmdVpnVerifyFixture(dir, io);
  }
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
    const common = { registry, trustedRoot: cfg.trustedRoot, attestTtlMs: cfg.attestTtlMs, pccsUrl: cfg.pccsUrl };
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

/** Runs the CLI; returns the exit code. `vpn` resolves only when `untilStopped` resolves (default: SIGINT/SIGTERM). */
export async function runCli(
  argv: string[],
  env: Record<string, string | undefined>,
  io: CliIo = { out: (s) => console.log(s), err: (s) => console.error(s) },
  untilStopped: () => Promise<void> = untilSignal,
  /** Tests only: replaces the DCAP verifier of `vpn inspect` (a synthetic bundle has no Intel signature). */
  vpnInspectVerifier?: QuoteVerifier,
): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd !== "vpn") {
    io.err(USAGE);
    return 2;
  }
  return runVpn(rest, env, io, untilStopped, vpnInspectVerifier);
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
      // A PCCS fetch that timed out is abandoned, not cancelled: do not let its sockets keep the process alive.
      setTimeout(() => process.exit(code), 1_000).unref();
    },
    (e: unknown) => {
      console.error(`✘ ${e instanceof PlrError ? e.code : "unexpected error"}`);
      process.exitCode = 1;
    },
  );
}
