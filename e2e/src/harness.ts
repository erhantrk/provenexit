/**
 * E2E harness (SPEC §13, SPEC-VPN §9.3): a fresh near-sandbox with the LLM registry and a second, independent VPN
 * registry deployed (same wasm, same MOCK root), the mock TDX host launching honest / evil / debug router builds
 * and VPN exit builds, network attackers in front of an honest router or exit, and a local HTTP destination.
 *
 *   const S = await startStack({ llm: "mock" });
 *   await S.approveBuild("honest");
 *   const r = await S.startRouter("honest");   // measured launch, registered on-chain
 *   await S.approveVpnBuild("vpn-honest-test");
 *   const x = await S.startExit("vpn-honest-test");   // registered on the VPN registry
 *   const d = await S.startDestination();
 *   S.dns.set("dest.plr.test", ["127.0.0.1"]);   // the test builds' DoH resolver (127.0.0.1:18253)
 *   await S.approveOperator("operator", "org-a");   // two-hop (SPEC-VPN §10): operator organizations
 *   await S.approveComboBuild("combo-test");          // SPEC-COMBO: router + exit in one TD, approved per registry
 *   const c = await S.startCombo("combo-test");       // c.routerUrl / c.vpnUrl, registered on both registries
 *   …
 *   await S.stop();
 *
 * Chains (SPEC-CHAINS §6): `startStack({ chain })` — `near` (default: near-sandbox, both registries deployed as
 * contracts), the tier-B chains `evm` (anvil + two PlrRegistry deployments), `stellar` (one Stellar quickstart
 * container, two Soroban registries) and `solana` (solana-test-validator with the program preloaded, two state
 * accounts), or `zcash` (zebrad regtest, the registries are the record logs of two owner t-addresses). Owner policy
 * goes through `S.admin` / `S.vpnAdmin` (`ChainAdmin`) on every chain; `S.call` / `S.view` are the NEAR-native calls.
 *
 * Layout: `<root>/<id>/` is the stack's `runDir` (`<root>` = `runRoot()`: `PLR_RUN_ROOT`, else `<repo>/.run`, else
 * `<repo>/e2e/.run` when the repo root is not writable — e.g. a sandbox that only allows writes under the e2e cwd) (near-sandbox home under `near/`, zebrad state under
 * `zcash/`); the mock host's
 * private socket directories live in the sibling `<root>/<id>-host/` (a Unix socket cannot be read as a
 * file, and macOS limits socket paths to 104 bytes). Both are removed by `stop()` unless `PLR_KEEP_RUN=1`.
 * Registration (SPEC §5 rev 1.3) is operator-bound: every launch gets the operator's credentials for its chain (NEAR:
 * `PLR_OPERATOR_ID` + a fresh key of that account; Zcash: `PLR_ZCASH_KEY` of the operator t-address), and the
 * enclave binds exactly that account into its registration quote. A registering launch resolves only once the
 * stack's reader sees the instance (tier B/C: the operator must be approved on that registry first).
 * Nothing listens on a fixed port unless asked to (`rpcPort`, `routerPort`), except the local DoH resolver: the
 * test builds measure `http://127.0.0.1:18253/dns-query` (SPEC-VPN §2), so every stack runs it on exactly that port
 * (one stack at a time on a machine; a busy port fails `startStack`).
 */
import { accessSync, constants as fsConstants, existsSync, mkdirSync, readFileSync, rmdirSync } from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { parseIpv4, parseIpv6, type RegistryReader, type TdxEvent } from "@plr/shared";
import { generateRootSecret, measureBoot, measureComboBoot, measureVpnBoot } from "@plr/enclave/mock-tdx";
import { isAttack, startAttackProxy, type AttackProxy } from "./attacks.js";
import { isVpnAttack, startVpnAttackProxy } from "./vpn-attacks.js";
import { startManaged, waitFor, type ManagedProcess } from "./procs.js";
import { CHAINS, OPERATORS, type Chain, type ChainAdmin, type ChainDriver, type DriverOptions, type OperatorAccount, type RegistryName, type Signer } from "./chains/driver.js";
import { startNearDriver } from "./chains/near.js";
import { startZcashDriver } from "./chains/zcash.js";
import { startEvmDriver } from "./chains/evm.js";
import { startStellarDriver } from "./chains/stellar.js";
import { startSolanaDriver } from "./chains/solana.js";
import { EvmRegistry, SolanaRegistry, StellarRegistry } from "@plr/client";

export { CHAINS, type Chain, type ChainAdmin, type OperatorAccount, type Signer };
export { REGISTRY_WASM } from "./chains/near.js";
export { zebradBinary } from "./chains/zcash.js";
export { anvilBinary } from "./chains/evm.js";
export { stellarBinary } from "./chains/stellar.js";
export { solanaBinDir } from "./chains/solana.js";

// ------------------------------------------------------------------------------------------------ public types

export const VARIANTS = ["honest", "evil-logger", "mitm-key", "replay-quote", "debug-td", "truncate-stream", "tamper-stream"] as const;
export type Variant = (typeof VARIANTS)[number];
export type LlmChoice = "mock" | "llama";
/** VPN exits (SPEC-VPN §9.3): three measured builds, and network attackers in front of `vpn-honest-test`. */
export const VPN_BUILDS = ["vpn-honest", "vpn-honest-test", "vpn-evil-logger"] as const;
export type VpnBuild = (typeof VPN_BUILDS)[number];
export const VPN_VARIANTS = [...VPN_BUILDS, "vpn-mitm-key", "vpn-replay-quote", "vpn-tamper-stream", "vpn-truncate-stream"] as const;
export type VpnVariant = (typeof VPN_VARIANTS)[number];
/** SPEC-COMBO §1: the LLM router + VPN exit in one TD; `combo` = production VPN policy, `combo-test` = test policy. */
export const COMBO_VARIANTS = ["combo", "combo-test"] as const;
export type ComboVariant = (typeof COMBO_VARIANTS)[number];

export interface StackOptions {
  llm: LlmChoice;
  /** Registry chain (SPEC-CHAINS §6, default "near"). */
  chain?: Chain;
  /** The chain node's RPC port (default: a free port). */
  rpcPort?: number;
  /** Run id (default: random); the run directory is `<runRoot()>/<id>/`. */
  id?: string;
  /** Router anchoring interval (default 1000 ms). */
  anchorIntervalMs?: number;
  /**
   * Receives every router/host/attacker output chunk as it arrives (e.g. to tee into a log file), labelled by the
   * variant, or by `ExitOptions.label` when given.
   */
  onRouterOutput?: (label: string, chunk: string) => void;
}

export interface RouterOptions {
  /** Register the instance on-chain at boot (default true). Failure ⇒ the router still serves, unregistered. */
  register?: boolean;
  /** Router listen port (default 0 = ephemeral). For attack variants: the proxy's port is always ephemeral. */
  port?: number;
}

export interface RouterHandle {
  url: string;
  composeHash: string;
  keyHash: string;
  /** router + host stdout+stderr (and the attacker proxy's log for network variants). */
  output(): string;
  stop(): Promise<void>;
}

export interface ExitOptions {
  /** Register the instance on the VPN registry at boot (default true). Failure ⇒ the exit still serves, unregistered. */
  register?: boolean;
  /** Exit listen port (default 0 = ephemeral). For attack variants: the proxy's port is always ephemeral. */
  port?: number;
  /** The operator account that registers the instance (default "operator"); its org is the instance's org. */
  operator?: OperatorAccount;
  /** Output label for `onRouterOutput` (dev tooling: several instances of one variant), `[a-z0-9-]{1,40}`. */
  label?: string;
}

export interface ExitHandle {
  /** For network-attack variants: the attacker proxy's URL. */
  url: string;
  composeHash: string;
  keyHash: string;
  /** exit + host stdout+stderr (and the attacker proxy's log for network variants). */
  output(): string;
  stop(): Promise<void>;
}

export interface ComboOptions {
  /** Register both roles at boot (router → LLM registry, exit → VPN registry; default true). Failure ⇒ still serving. */
  register?: boolean;
  /** The operator account that registers both roles (default "operator"). */
  operator?: OperatorAccount;
  /** Router / exit listen ports (default 0 = ephemeral). */
  routerPort?: number;
  exitPort?: number;
  /** Output label for `onRouterOutput` (default: the variant), `[a-z0-9-]{1,40}`. */
  label?: string;
}

/** A combo TD (SPEC-COMBO §4): one measurement, two services with their own keys. */
export interface ComboHandle {
  routerUrl: string;
  vpnUrl: string;
  composeHash: string;
  routerKeyHash: string;
  vpnKeyHash: string;
  /** The router's listen port (to show that the exit cannot reach it). */
  routerPort: number;
  /** host + LLM + router + exit stdout+stderr. */
  output(): string;
  stop(): Promise<void>;
}

/**
 * The local RFC 8484 resolver of the test builds (SPEC-VPN §9.3), on `127.0.0.1:18253` (POST `/dns-query`).
 * Answers A / AAAA from `set()` records by address family; unknown names ⇒ NXDOMAIN; `setDown(true)` ⇒ HTTP 503.
 */
export interface StackDns {
  /** Sets (replaces) the addresses of `name` (case-insensitive, optional trailing dot). */
  set(name: string, addrs: string[]): void;
  /** Number of queries received so far (every POST, answered or not). */
  hits(): number;
  setDown(down: boolean): void;
}

/** Local HTTP/1.1 destination (SPEC-VPN §9.3). */
export interface Destination {
  host: "127.0.0.1";
  port: number;
  /** Number of requests received so far. */
  hits(): number;
  /** All raw request bytes received so far (latin1). */
  received(): string;
  close(): Promise<void>;
}

export interface Stack {
  /** The registry chain (SPEC-CHAINS §6). */
  chain: Chain;
  /** Owner of the LLM registry (resolves once the write is on chain). */
  admin: ChainAdmin;
  /** Owner of the VPN registry. */
  vpnAdmin: ChainAdmin;
  /** The same API signed by the stranger account (must be refused / ignored). */
  asStranger(a: ChainAdmin): ChainAdmin;
  /** The chain node's RPC URL (near-sandbox / zebrad). */
  rpcUrl: string;
  contractId: string;
  trustedRoot: Uint8Array;
  registry: RegistryReader;
  runDir: string;
  /** NEAR: account ids; Zcash: t-addresses (the LLM registry's owner; the VPN owner is a separate address). */
  accounts: { owner: string; operator: string; operator2: string; stranger: string };
  /** NEAR-native contract view on the LLM registry (rejects on chains without contracts). */
  view<T>(method: string, args: object): Promise<T>;
  /**
   * Rejects with an Error whose message includes the contract panic code. On Zcash only the owner methods exist
   * (`allow_compose`, …, `approve_operator {account_id: t-address, org_id}`): they post the owner record.
   */
  call(signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }): Promise<unknown>;
  approveBuild(variant: Variant): Promise<{ composeHash: string; osMeasurement: string }>;
  startRouter(variant: Variant, o?: RouterOptions): Promise<RouterHandle>;
  attestFor(variant: Variant, reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[]; appCompose: string }>;
  /** The VPN registry: a second deployment of the same wasm with the same MOCK root (SPEC-VPN §9.3). */
  vpnContractId: string;
  vpnRegistry: RegistryReader;
  /** As `call`, on the VPN registry. */
  callVpn(signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }): Promise<unknown>;
  approveVpnBuild(build: VpnBuild): Promise<{ composeHash: string; osMeasurement: string }>;
  startExit(variant: VpnVariant, o?: ExitOptions): Promise<ExitHandle>;
  startDestination(): Promise<Destination>;
  /** Owner → `approve_operator` on the VPN registry (re-approving changes the org). Same as `vpnAdmin.approveOperator`. */
  approveOperator(account: OperatorAccount, orgId: string): Promise<void>;
  /** Owner → `revoke_operator` on the VPN registry. */
  revokeOperator(account: OperatorAccount): Promise<void>;
  /** The test builds' DoH resolver (always running while the stack is up). */
  dns: StackDns;
  /**
   * SPEC-COMBO §3/§4: the owner allows the combo compose hash + OS measurement (stack's LLM choice) on the LLM registry
   * (`llm`, router role) and/or the VPN registry (`vpn`, exit role); default both.
   */
  approveComboBuild(v: ComboVariant, o?: { llm?: boolean; vpn?: boolean }): Promise<{ composeHash: string; osMeasurement: string }>;
  /** Launches a combo TD through the mock TDX host; resolves once both services listen and (if registering) both registrations ended. */
  startCombo(v: ComboVariant, o?: ComboOptions): Promise<ComboHandle>;
  /** Stops every router, exit, combo, attacker proxy, destination, the DoH resolver and the chain. */
  stop(): Promise<void>;
}

/** Extras for the dev tooling (stack-cli): not used by the tests. */
export interface DevStack extends Stack {
  /** The fresh dev-chain key of a stack account (for out-of-process owner actions in the demo). */
  exportSigner(signer: Signer): { accountId: string; secretKey: string };
  /** JSON of the owner key file for `stack-cli owner` (both registries' owners). */
  ownerFile(): Record<string, unknown>;
  /** Client env lines locating the registries (PLR_CHAIN / PLR_NEAR_RPC / PLR_ZCASH_* / PLR_REGISTRY / PLR_VPN_REGISTRY). */
  clientEnvLines(): string[];
}

// ------------------------------------------------------------------------------------------------ paths & builds

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ENCLAVE_DIST = join(REPO_ROOT, "enclave", "dist");
const HOST_CLI = join(ENCLAVE_DIST, "mock-tdx", "cli.js");
const BUILD_INFO = join(ENCLAVE_DIST, "build-info.json");
const E2E_ROOT = join(REPO_ROOT, "e2e");

/** Longest run root accepted: the host's socket paths (`<root>/<id>-host/<dir>/q.sock`) must stay under 104 bytes. */
const MAX_RUN_ROOT_LEN = 56;
let runRootCache: string | undefined;

/**
 * The directory holding every stack's run/host/log directories: `PLR_RUN_ROOT` if set (must be absolute), else the
 * first writable of `<repo>/.run` and `<repo>/e2e/.run` (both git-ignored). Created 0700 on first use; throws when
 * none is usable (fail closed, never silently elsewhere).
 */
export function runRoot(): string {
  if (runRootCache !== undefined) return runRootCache;
  const env = process.env.PLR_RUN_ROOT;
  const candidates = env ? [env] : [join(REPO_ROOT, ".run"), join(E2E_ROOT, ".run")];
  const errors: string[] = [];
  for (const dir of candidates) {
    if (!dir.startsWith("/")) { errors.push(`${dir}: not absolute`); continue; }
    if (dir.length > MAX_RUN_ROOT_LEN) { errors.push(`${dir}: longer than ${MAX_RUN_ROOT_LEN} bytes (socket paths)`); continue; }
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      accessSync(dir, fsConstants.W_OK);
      // Directory creation is what the stack needs; a sandbox may allow access(W_OK) yet deny mkdir.
      const probe = join(dir, `.probe-${process.pid}-${nodeRandomBytes(4).toString("hex")}`);
      mkdirSync(probe, { mode: 0o700 });
      rmdirSyncQuiet(probe);
      return (runRootCache = dir);
    } catch (e) {
      errors.push(`${dir}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`);
    }
  }
  throw new Error(`no writable run root (${errors.join("; ")})`);
}

function rmdirSyncQuiet(dir: string): void {
  try { rmdirSync(dir); } catch { /* best effort: an empty probe dir */ }
}

const DEFAULT_LLAMA_MODEL = join(homedir(), "models", "qwen2.5-0.5b-instruct-q4_k_m.gguf");

const INSTANCE_TTL_MS = 86_400_000;

interface BuildInfo {
  variants: Record<"honest" | "evil-logger", { compose: Record<LlmChoice, { file: string; compose_hash: string }> }>;
  vpn: Record<VpnBuild, { compose: { file: string; compose_hash: string } }>;
  combo: Record<ComboVariant, { compose: Record<LlmChoice, { file: string; compose_hash: string }> }>;
}

function loadBuildInfo(): BuildInfo {
  if (!existsSync(BUILD_INFO) || !existsSync(HOST_CLI)) {
    throw new Error(`enclave build missing (${BUILD_INFO}); run: npx tsc -b && npm run build -w @plr/enclave`);
  }
  const o = JSON.parse(readFileSync(BUILD_INFO, "utf8")) as BuildInfo;
  for (const v of ["honest", "evil-logger"] as const) {
    for (const k of ["mock", "llama"] as const) {
      if (typeof o.variants?.[v]?.compose?.[k]?.file !== "string") throw new Error(`build-info.json: missing ${v}/${k}`);
    }
  }
  for (const v of VPN_BUILDS) {
    if (typeof o.vpn?.[v]?.compose?.file !== "string") throw new Error(`build-info.json: missing vpn/${v} (rebuild: npm run build -w @plr/enclave)`);
  }
  for (const v of COMBO_VARIANTS) {
    for (const k of ["mock", "llama"] as const) {
      if (typeof o.combo?.[v]?.compose?.[k]?.file !== "string") throw new Error(`build-info.json: missing combo/${v}/${k} (rebuild: npm run build -w @plr/enclave)`);
    }
  }
  return o;
}

/** Which measured build (and TD attributes) a variant launches. */
interface BuildSpec {
  build: "honest" | "evil-logger";
  debug: boolean;
}

function buildOf(variant: Variant): BuildSpec {
  if (!(VARIANTS as readonly string[]).includes(variant)) throw new Error(`unknown variant: ${String(variant)}`);
  if (variant === "evil-logger") return { build: "evil-logger", debug: false };
  if (variant === "debug-td") return { build: "honest", debug: true };
  return { build: "honest", debug: false }; // honest + every network attack: the approved build
}

/** The measured build a VPN variant launches: network attacks run the approved test build behind a proxy. */
function vpnBuildOf(variant: VpnVariant): VpnBuild {
  if (!(VPN_VARIANTS as readonly string[]).includes(variant)) throw new Error(`unknown VPN variant: ${String(variant)}`);
  return (VPN_BUILDS as readonly string[]).includes(variant) ? (variant as VpnBuild) : "vpn-honest-test";
}

const RUN_ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const LABEL_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

// ------------------------------------------------------------------------------------------------ startStack

/** Boot lines of the router (`plr-router`) and of a VPN exit (`plr-vpn`): same shape, different tag. */
const LISTEN_RE = {
  router: /plr-router: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/,
  vpn: /plr-vpn: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/,
} as const;
const REG_RE = {
  router: /plr-router: (registered key_hash=[0-9a-f]{64}|registration_failed code=(\S+)|registration_disabled)/,
  vpn: /plr-vpn: (registered key_hash=[0-9a-f]{64}|registration_failed code=(\S+)|registration_disabled)/,
} as const;
const HOST_FAIL_RE = /plr-(?:host|router|vpn): (?:launch_refused|launch_failed|boot_failed|error|fatal) code=(\S+)/;

/** Destination server bounds: request heads up to 1 MiB (long test paths), bodies up to 16 MiB, ≤ 64 MiB recorded. */
const DEST_MAX_HEAD = 1024 * 1024;
const DEST_MAX_BODY = 16 * 1024 * 1024;
const DEST_MAX_RECORDED = 64 * 1024 * 1024;
const DEST_IDLE_MS = 60_000;

/** The test builds' measured resolver URL is `http://127.0.0.1:18253/dns-query` (SPEC-VPN §2). */
export const TEST_DOH_PORT = 18253;
/** Bound on a registered instance becoming visible to the stack's reader (tier C: blocks + reader catch-up). */
const REGISTERED_VISIBLE_TIMEOUT_MS = 120_000;

/** The chain-driver registry (SPEC-CHAINS §6): one local node per stack for every chain in {@link CHAINS}. */
function startChainDriver(chain: Chain, o: DriverOptions): Promise<ChainDriver> {
  switch (chain) {
    case "near":
      return startNearDriver(o);
    case "evm":
      return startEvmDriver(o, { createReader: (r) => new EvmRegistry(r) });
    case "stellar":
      return startStellarDriver(o, { reader: (r) => new StellarRegistry(r) });
    case "solana":
      return startSolanaDriver(o, (p) => new SolanaRegistry(p));
    case "zcash":
      return startZcashDriver(o);
  }
}

export async function startStack(o: StackOptions): Promise<DevStack> {
  if (o.llm !== "mock" && o.llm !== "llama") throw new Error(`startStack: llm must be "mock" or "llama"`);
  const chain: Chain = o.chain ?? "near";
  if (!CHAINS.includes(chain)) throw new Error(`startStack: unknown chain: ${String(chain)}`);
  const info = loadBuildInfo();
  const llmFile = o.llm === "llama" ? (process.env.PLR_MODEL_PATH || DEFAULT_LLAMA_MODEL) : undefined;
  if (llmFile && !existsSync(llmFile)) throw new Error(`model not found: ${llmFile}`);

  const id = o.id ?? `e2e-${Date.now().toString(36)}-${nodeRandomBytes(3).toString("hex")}`;
  if (!RUN_ID_RE.test(id)) throw new Error("startStack: bad run id");
  const root = runRoot();
  const runDir = join(root, id);
  const hostDir = join(root, `${id}-host`);
  if (existsSync(runDir) || existsSync(hostDir)) throw new Error(`run directory already exists: ${runDir}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  await mkdir(hostDir, { recursive: true, mode: 0o700 });

  /** Teardown of everything started so far, registered the moment it starts (incl. launches in progress). */
  const teardowns = new Set<() => Promise<void>>();
  let node: ChainDriver | null = null;
  let stopping: Promise<void> | null = null;
  /**
   * Idempotent, bounded teardown: every router subtree, attack proxy and the chain are stopped in parallel,
   * each with group SIGTERM → ≤ 10 s → group SIGKILL, so this resolves in ≈ 13 s at worst.
   */
  const stop = (): Promise<void> =>
    (stopping ??= (async () => {
      await Promise.allSettled([...[...teardowns].map((t) => t()), node?.stop() ?? Promise.resolve()]);
      if (process.env.PLR_KEEP_RUN !== "1") {
        await rm(hostDir, { recursive: true, force: true }).catch(() => undefined);
        await rm(runDir, { recursive: true, force: true }).catch(() => undefined);
      }
    })());

  try {
    // MOCK ROOT: secret in a 0600 file next to the host sockets (never inside runDir), public half pinned.
    const rootSecretFile = join(hostDir, "mock-root.hex");
    const root = await generateRootSecret(rootSecretFile);
    const trustedRoot = root.publicKey;

    // The test builds' DoH resolver on its measured, fixed port (fails fast if another stack holds it).
    const doh = await startDohResolver(TEST_DOH_PORT);
    teardowns.add(doh.close);
    const dns: StackDns = { set: doh.set, hits: doh.hits, setDown: doh.setDown };

    const driverOpts = { dir: runDir, trustedRoot, instanceTtlMs: INSTANCE_TTL_MS, ...(o.rpcPort !== undefined ? { rpcPort: o.rpcPort } : {}) };
    node = await startChainDriver(chain, driverOpts);
    const d: ChainDriver = node;
    const { rpcUrl, contractId, vpnContractId, registry, vpnRegistry, admin, vpnAdmin, view, call, callVpn } = d;

    const composePathOf = (build: "honest" | "evil-logger") => join(ENCLAVE_DIST, info.variants[build].compose[o.llm].file);

    /** Runtime closure hashes, reused while the files are unchanged (the host itself always re-hashes). */
    const runtimeCache = new Map<string, string>();
    /** Measures exactly like the host's launch path does (same `measureBoot`), fresh instance-id each call. */
    const measure = (variant: Variant) => {
      const b = buildOf(variant);
      return measureBoot({
        composePath: composePathOf(b.build),
        root,
        debug: b.debug,
        runtimeCache,
        ...(llmFile ? { llmFile } : {}),
        ...(process.env.PLR_LLAMA_SERVER ? { llamaServer: process.env.PLR_LLAMA_SERVER } : {}),
      });
    };

    const approveBuild = async (variant: Variant) => {
      const m = await measure(variant);
      await admin.allowCompose(m.composeHash);
      await admin.allowOs(m.osMeasurement);
      return { composeHash: m.composeHash, osMeasurement: m.osMeasurement };
    };

    const attestFor = async (variant: Variant, rd: Uint8Array) => {
      if (!(rd instanceof Uint8Array) || rd.length !== 64) throw new Error("attestFor: reportData must be 64 bytes");
      const m = await measure(variant);
      const { quote, eventLog } = await m.attester.getQuote(rd);
      return { quote, eventLog, appCompose: new TextDecoder("utf-8", { fatal: true }).decode(m.composeBytes) };
    };

    type Service = "router" | "vpn";
    /** One measured launch through the mock TDX host CLI (a router, a VPN exit, or both in a combo TD). */
    interface HostLaunch {
      /** The services this TD runs (each prints its own listening + registration lines). */
      services: readonly Service[];
      /** Output label (log file name in the dev stack). */
      label: string;
      /** Diagnostics, e.g. "router honest" / "exit vpn-honest-test" / "combo combo-test". */
      what: string;
      /** Host CLI arguments after `launch`. */
      hostArgs: string[];
      register: boolean;
      /** The account that registers the instance(s) (default "operator"). */
      operator?: OperatorAccount;
      /** The registries the TD's services register on (router → llm, exit → vpn). */
      registries: readonly RegistryName[];
      listenTimeoutMs: number;
    }
    interface ServiceInfo {
      url: string;
      keyHash: string;
      composeHash: string;
    }
    interface HostTd {
      services: Partial<Record<Service, ServiceInfo>>;
      output(): string;
      stop(): Promise<void>;
    }

    /** Launches a measured build through the mock TDX host CLI (separate process, lifeline-bound). */
    const launchHost = async (l: HostLaunch): Promise<HostTd> => {
      const env: Record<string, string> = {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? homedir(),
        PLR_MOCK_ROOT_SECRET_FILE: rootSecretFile,
        PLR_ANCHOR_INTERVAL_MS: String(o.anchorIntervalMs ?? 1000),
      };
      // The operator's credentials for the stack's chain (NEAR: a fresh full-access key per TD, see chains/near.ts).
      if (l.register) Object.assign(env, await d.instanceEnv(l.operator ?? "operator", l.registries));
      const proc: ManagedProcess = startManaged({
        name: `${l.services.join("+")}:${l.label}`,
        cmd: process.execPath,
        args: [HOST_CLI, "launch", ...l.hostArgs],
        env,
        cwd: hostDir,
        ...(o.onRouterOutput ? { onOutput: (s: string) => o.onRouterOutput!(l.label, s) } : {}),
      });
      // Bounded and idempotent (group SIGTERM → ≤ 10 s → group SIGKILL). Per-instance credentials are left on
      // the throw-away chain: deleting them would put an RPC round-trip on every shutdown path.
      let stopped: Promise<void> | null = null;
      const stopProc = (): Promise<void> =>
        (stopped ??= proc.stop().then(() => {
          teardowns.delete(stopProc);
        }));
      teardowns.add(stopProc);
      if (stopping) await stopProc(); // raced with stack.stop(): the waits below fail fast
      try {
        const waitService = async (service: Service): Promise<ServiceInfo> => {
          const what = l.services.length > 1 ? `${l.what} (${service})` : l.what;
          const m = await waitFor(
            `${what} to listen`,
            () => {
              const out = proc.output();
              const ok = LISTEN_RE[service].exec(out);
              if (ok) return ok;
              const bad = HOST_FAIL_RE.exec(out);
              if (bad) throw new Error(`${l.what} failed to start: ${bad[1]}`);
              if (proc.exited) throw new Error(`${l.what} exited before listening:\n${out.slice(-4000)}`);
              return undefined;
            },
            l.listenTimeoutMs,
          );
          const url = m[1]!;
          await waitFor(`${what} /healthz`, async () => {
            if (proc.exited) throw new Error(`${l.what} exited`);
            try {
              const r = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(2000) });
              const j = r.ok ? ((await r.json()) as { ok?: unknown }) : null;
              return j?.ok === true ? true : undefined;
            } catch {
              return undefined;
            }
          }, 30_000, 200);
          const keyHash = m[2]!;
          if (l.register) {
            // Registration may legitimately fail (unapproved or debug builds): the instance keeps serving.
            const outcome = await waitFor(`${what} registration outcome`, () => {
              if (proc.exited) throw new Error(`${l.what} exited`);
              return REG_RE[service].exec(proc.output()) ?? undefined;
            }, 120_000, 100);
            if (outcome[1]!.startsWith("registered")) {
              // SPEC-CHAINS §6: resolve only once the stack's reader of that registry sees the instance.
              const reader = service === "router" ? registry : vpnRegistry;
              await waitFor(`${what} registration visible to the reader (operator approved on that registry?)`, async () => {
                if (proc.exited) throw new Error(`${l.what} exited`);
                return (await reader.getInstance(keyHash).catch(() => null)) !== null ? true : undefined;
              }, REGISTERED_VISIBLE_TIMEOUT_MS, 250);
            }
          }
          return { url, keyHash, composeHash: m[3]! };
        };
        const infos = await Promise.all(l.services.map(waitService));
        const services: Partial<Record<Service, ServiceInfo>> = {};
        l.services.forEach((sv, i) => (services[sv] = infos[i]!));
        return { services, output: () => proc.output(), stop: stopProc };
      } catch (e) {
        await stopProc();
        throw e;
      }
    };

    /** A single-service TD as a router / exit handle. */
    const single = (td: HostTd, service: Service): RouterHandle => {
      const i = td.services[service]!;
      return { url: i.url, keyHash: i.keyHash, composeHash: i.composeHash, output: td.output, stop: td.stop };
    };

    const launchBuild = async (variant: Variant, ro: RouterOptions, label: Variant = variant): Promise<RouterHandle> => {
      const b = buildOf(variant);
      const td = await launchHost({
        services: ["router"],
        label,
        what: `router ${variant}`,
        hostArgs: [
          "--compose", composePathOf(b.build),
          "--run-dir", hostDir,
          "--state-dir", runDir,
          "--router-port", String(ro.port ?? 0),
          ...(b.debug ? ["--debug"] : []),
          ...(llmFile ? ["--llm-file", llmFile] : []),
          ...(process.env.PLR_LLAMA_SERVER ? ["--llama-server", process.env.PLR_LLAMA_SERVER] : []),
        ],
        register: ro.register !== false,
        registries: ["llm"],
        listenTimeoutMs: o.llm === "llama" ? 300_000 : 60_000,
      });
      return single(td, "router");
    };

    /** Wraps a launched instance behind an attacker proxy; stopping the handle stops both. */
    const behindProxy = (inner: RouterHandle, proxy: AttackProxy, proxyLog: () => string): RouterHandle => {
      let closed: Promise<void> | null = null;
      const close = (): Promise<void> =>
        (closed ??= Promise.allSettled([proxy.close(), inner.stop()]).then(() => {
          teardowns.delete(close);
        }));
      teardowns.add(close);
      return { url: proxy.url, composeHash: inner.composeHash, keyHash: inner.keyHash, output: () => inner.output() + proxyLog(), stop: close };
    };

    const startRouter = async (variant: Variant, ro: RouterOptions = {}): Promise<RouterHandle> => {
      if (stopping) throw new Error("stack is stopped");
      buildOf(variant);
      if (!isAttack(variant)) return launchBuild(variant, ro);
      // Network attack: an honest, approved, registered router behind a malicious proxy.
      const inner = await launchBuild("honest", { ...ro, port: 0 }, variant);
      let proxyLog = "";
      let proxy: AttackProxy;
      try {
        proxy = await startAttackProxy(variant, inner.url, (line) => {
          proxyLog += line;
          o.onRouterOutput?.(variant, line);
        });
      } catch (e) {
        await inner.stop();
        throw e;
      }
      return behindProxy(inner, proxy, () => proxyLog);
    };

    // ---------------------------------------------------------------------------------------------- VPN (SPEC-VPN)

    const vpnComposePathOf = (b: VpnBuild) => join(ENCLAVE_DIST, info.vpn[b].compose.file);

    const approveVpnBuild = async (build: VpnBuild) => {
      if (!(VPN_BUILDS as readonly string[]).includes(build)) throw new Error(`unknown VPN build: ${String(build)}`);
      // Measured exactly like the host's VPN launch path (same `measureVpnBoot`).
      const m = await measureVpnBoot({ composePath: vpnComposePathOf(build), root, debug: false, runtimeCache });
      await vpnAdmin.allowCompose(m.composeHash);
      await vpnAdmin.allowOs(m.osMeasurement);
      return { composeHash: m.composeHash, osMeasurement: m.osMeasurement };
    };

    const launchExit = async (build: VpnBuild, xo: ExitOptions, label: string): Promise<ExitHandle> =>
      single(await launchHost({
        services: ["vpn"],
        label,
        what: `exit ${label}`,
        hostArgs: ["--compose", vpnComposePathOf(build), "--run-dir", hostDir, "--exit-port", String(xo.port ?? 0)],
        register: xo.register !== false,
        operator: xo.operator ?? "operator",
        registries: ["vpn"],
        listenTimeoutMs: 60_000,
      }), "vpn");

    const startExit = async (variant: VpnVariant, xo: ExitOptions = {}): Promise<ExitHandle> => {
      if (stopping) throw new Error("stack is stopped");
      const build = vpnBuildOf(variant);
      if (xo.operator !== undefined && !OPERATORS.includes(xo.operator)) throw new Error(`startExit: unknown operator: ${String(xo.operator)}`);
      if (xo.label !== undefined && !LABEL_RE.test(xo.label)) throw new Error("startExit: bad label");
      const label = xo.label ?? variant;
      if (!isVpnAttack(variant)) return launchExit(build, xo, label);
      // Network attack: the approved, registered test build behind a malicious TCP/HTTP proxy.
      const inner = await launchExit(build, { ...xo, port: 0 }, label);
      let proxyLog = "";
      let proxy: AttackProxy;
      try {
        proxy = await startVpnAttackProxy(variant, inner.url, (line) => {
          proxyLog += line;
          o.onRouterOutput?.(label, line);
        });
      } catch (e) {
        await inner.stop();
        throw e;
      }
      return behindProxy(inner, proxy, () => proxyLog);
    };

    // -------------------------------------------------------------------------------------------- combo (SPEC-COMBO)

    const comboComposePathOf = (v: ComboVariant) => {
      if (!(COMBO_VARIANTS as readonly string[]).includes(v)) throw new Error(`unknown combo variant: ${String(v)}`);
      return join(ENCLAVE_DIST, info.combo[v].compose[o.llm].file);
    };

    const approveComboBuild = async (v: ComboVariant, ao: { llm?: boolean; vpn?: boolean } = {}) => {
      const onLlm = ao.llm !== false;
      const onVpn = ao.vpn !== false;
      // Measured exactly like the host's combo launch path (same `measureComboBoot`, same LLM choice).
      const m = await measureComboBoot({
        composePath: comboComposePathOf(v),
        root,
        debug: false,
        runtimeCache,
        ...(llmFile ? { llmFile } : {}),
        ...(process.env.PLR_LLAMA_SERVER ? { llamaServer: process.env.PLR_LLAMA_SERVER } : {}),
      });
      // Approval is per registry (SPEC-COMBO §3): the LLM registry approves the router role, the VPN one the exit.
      if (onLlm) {
        await admin.allowCompose(m.composeHash);
        await admin.allowOs(m.osMeasurement);
      }
      if (onVpn) {
        await vpnAdmin.allowCompose(m.composeHash);
        await vpnAdmin.allowOs(m.osMeasurement);
      }
      return { composeHash: m.composeHash, osMeasurement: m.osMeasurement };
    };

    const startCombo = async (v: ComboVariant, co: ComboOptions = {}): Promise<ComboHandle> => {
      if (stopping) throw new Error("stack is stopped");
      const composePath = comboComposePathOf(v);
      if (co.operator !== undefined && !OPERATORS.includes(co.operator)) throw new Error(`startCombo: unknown operator: ${String(co.operator)}`);
      if (co.label !== undefined && !LABEL_RE.test(co.label)) throw new Error("startCombo: bad label");
      const label = co.label ?? v;
      const td = await launchHost({
        services: ["router", "vpn"],
        label,
        what: `combo ${label}`,
        hostArgs: [
          "--compose", composePath,
          "--run-dir", hostDir,
          "--state-dir", runDir,
          "--router-port", String(co.routerPort ?? 0),
          "--exit-port", String(co.exitPort ?? 0),
          ...(llmFile ? ["--llm-file", llmFile] : []),
          ...(process.env.PLR_LLAMA_SERVER ? ["--llama-server", process.env.PLR_LLAMA_SERVER] : []),
        ],
        register: co.register !== false,
        operator: co.operator ?? "operator",
        // Each role on its own registry; the host hands each process only its own (SPEC-COMBO §2).
        registries: ["llm", "vpn"],
        listenTimeoutMs: o.llm === "llama" ? 300_000 : 60_000,
      });
      const r = td.services.router!;
      const x = td.services.vpn!;
      try {
        // One measurement for the whole TD: both services must announce the same compose.
        if (r.composeHash !== x.composeHash) throw new Error(`combo ${label}: router and exit announce different compose hashes`);
        if (r.keyHash === x.keyHash) throw new Error(`combo ${label}: router and exit share a key`);
        const routerPort = Number(new URL(r.url).port);
        if (!Number.isInteger(routerPort) || routerPort <= 0 || routerPort > 65535) throw new Error(`combo ${label}: bad router url`);
        return {
          routerUrl: r.url,
          vpnUrl: x.url,
          composeHash: r.composeHash,
          routerKeyHash: r.keyHash,
          vpnKeyHash: x.keyHash,
          routerPort,
          output: td.output,
          stop: td.stop,
        };
      } catch (e) {
        await td.stop();
        throw e;
      }
    };

    const startDestination = async (): Promise<Destination> => {
      if (stopping) throw new Error("stack is stopped");
      const d = await startDestinationServer();
      let closed: Promise<void> | null = null;
      const close = (): Promise<void> =>
        (closed ??= d.close().then(() => {
          teardowns.delete(close);
        }));
      teardowns.add(close);
      return { ...d, close };
    };

    const approveOperator = (account: OperatorAccount, orgId: string): Promise<void> => vpnAdmin.approveOperator(account, orgId);
    const revokeOperator = (account: OperatorAccount): Promise<void> => vpnAdmin.revokeOperator(account);

    return {
      chain,
      admin,
      vpnAdmin,
      asStranger: (a: ChainAdmin) => d.asStranger(a),
      rpcUrl,
      contractId,
      trustedRoot,
      registry,
      runDir,
      accounts: d.accounts,
      view,
      call,
      approveBuild,
      startRouter,
      attestFor,
      vpnContractId,
      vpnRegistry,
      callVpn,
      approveVpnBuild,
      startExit,
      startDestination,
      approveOperator,
      revokeOperator,
      dns,
      approveComboBuild,
      startCombo,
      stop,
      exportSigner: (signer: Signer) => d.exportSigner(signer),
      ownerFile: () => d.ownerFile(),
      clientEnvLines: () => d.clientEnvLines(),
    };
  } catch (e) {
    await stop();
    throw e;
  }
}

// ------------------------------------------------------------------------------------------------ destination

/**
 * The SPEC-VPN §9.3 destination: a minimal HTTP/1.1 server on 127.0.0.1 (ephemeral port) built on node:net so it
 * can record the exact raw request bytes. Every request (complete head) counts as a hit; the response is
 * `200 dest-ok:<path>` (+ the request body for POST) with `Connection: close`. Bounded: head ≤ 1 MiB, body
 * ≤ 16 MiB (`Content-Length` only; anything else ⇒ 400), ≤ 64 MiB recorded, 60 s idle timeout per connection.
 */
async function startDestinationServer(): Promise<Omit<Destination, "close"> & { close(): Promise<void> }> {
  let hits = 0;
  const recorded: Buffer[] = [];
  let recordedLen = 0;
  const sockets = new Set<net.Socket>();

  const server = net.createServer({ allowHalfOpen: true }, (sock) => {
    sockets.add(sock);
    sock.once("close", () => sockets.delete(sock));
    sock.on("error", () => sock.destroy());
    sock.setTimeout(DEST_IDLE_MS, () => sock.destroy());
    let buf: Buffer = Buffer.alloc(0);
    let head: { method: string; path: string; bodyLen: number; headLen: number } | null = null;
    let answered = false;
    const reply = (status: number, body: Buffer) => {
      answered = true;
      sock.end(
        Buffer.concat([
          Buffer.from(`HTTP/1.1 ${status} ${status === 200 ? "OK" : "Bad Request"}\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n`, "latin1"),
          body,
        ]),
      );
    };
    sock.on("data", (c: Buffer) => {
      if (recordedLen + c.length <= DEST_MAX_RECORDED) {
        recorded.push(Buffer.from(c));
        recordedLen += c.length;
      }
      if (answered) return;
      buf = buf.length === 0 ? c : Buffer.concat([buf, c]);
      if (head === null) {
        const end = buf.indexOf("\r\n\r\n");
        if (end < 0) {
          if (buf.length > DEST_MAX_HEAD) reply(400, Buffer.from("dest-bad-request"));
          return;
        }
        const lines = buf.subarray(0, end).toString("latin1").split("\r\n");
        const rl = /^([A-Z]{1,16}) (\S{1,1048576}) HTTP\/1\.[01]$/.exec(lines[0] ?? "");
        let bodyLen = 0;
        let ok = rl !== null;
        for (const line of lines.slice(1)) {
          const m = /^([^:]+):\s*(.*)$/.exec(line);
          if (!m) continue;
          const k = m[1]!.trim().toLowerCase();
          if (k === "content-length") {
            if (!/^[0-9]{1,9}$/.test(m[2]!.trim()) || Number(m[2]!.trim()) > DEST_MAX_BODY) ok = false;
            else bodyLen = Number(m[2]!.trim());
          } else if (k === "transfer-encoding") ok = false;
        }
        hits++;
        if (!ok) return reply(400, Buffer.from("dest-bad-request"));
        head = { method: rl![1]!, path: rl![2]!, bodyLen, headLen: end + 4 };
      }
      if (buf.length - head.headLen < head.bodyLen) return;
      const body = buf.subarray(head.headLen, head.headLen + head.bodyLen);
      reply(200, Buffer.concat([Buffer.from(`dest-ok:${head.path}`, "latin1"), head.method === "POST" ? body : Buffer.alloc(0)]));
    });
    sock.on("end", () => {
      if (!answered) sock.end();
    });
  });
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", fail);
      ok();
    });
  });
  const port = (server.address() as AddressInfo).port;
  let closing: Promise<void> | null = null;
  return {
    host: "127.0.0.1",
    port,
    hits: () => hits,
    received: () => Buffer.concat(recorded).toString("latin1"),
    close: () =>
      (closing ??= new Promise<void>((ok) => {
        server.close(() => ok());
        for (const s of sockets) s.destroy();
      })),
  };
}

// ------------------------------------------------------------------------------------------------ DoH resolver

/** Resolver bounds: queries are ≤ 512 bytes (padded to 128, names ≤ 253); ≤ 32 addresses per name; 10 s per request. */
const DOH_MAX_QUERY = 4096;
const DOH_MAX_ADDRS = 32;
const DOH_REQUEST_TIMEOUT_MS = 10_000;
const DNS_TYPE_A = 1;
const DNS_TYPE_AAAA = 28;

/** Lowercase, no trailing dot: the resolver's record key. */
const dnsKey = (name: string): string => name.toLowerCase().replace(/\.$/, "");

/** The question of a standard query: QDCOUNT = 1, uncompressed qname, class IN. `null` = malformed. */
function parseDnsQuestion(q: Buffer): { id: number; name: string; qtype: number; end: number } | null {
  if (q.length < 12 || q.readUInt16BE(4) !== 1 || (q[2]! & 0x80) !== 0) return null;
  const labels: string[] = [];
  let i = 12;
  let total = 0;
  for (;;) {
    if (i >= q.length) return null;
    const len = q[i]!;
    if (len === 0) break;
    if (len > 63 || i + 1 + len > q.length) return null; // (also rejects compression pointers in a query)
    total += len + 1;
    if (total > 255) return null;
    labels.push(q.subarray(i + 1, i + 1 + len).toString("latin1"));
    i += 1 + len;
  }
  if (i + 5 > q.length || q.readUInt16BE(i + 3) !== 1) return null;
  return { id: q.readUInt16BE(0), name: dnsKey(labels.join(".")), qtype: q.readUInt16BE(i + 1), end: i + 5 };
}

/** A response: the query's id and question, RD/RA set, `rcode`, one answer RR (TTL 60) per rdata, no additional RRs. */
function dnsAnswer(q: Buffer, question: { id: number; qtype: number; end: number }, rcode: number, rdatas: Uint8Array[]): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(question.id, 0);
  header.writeUInt16BE(0x8180 | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(rdatas.length, 6);
  const answers = rdatas.map((rd) => {
    const rr = Buffer.alloc(12 + rd.length);
    rr.writeUInt16BE(0xc00c, 0); // name: pointer to the question name
    rr.writeUInt16BE(question.qtype, 2);
    rr.writeUInt16BE(1, 4); // IN
    rr.writeUInt32BE(60, 6);
    rr.writeUInt16BE(rd.length, 10);
    rr.set(rd, 12);
    return rr;
  });
  return Buffer.concat([header, q.subarray(12, question.end), ...answers]);
}

/**
 * The SPEC-VPN §9.3 resolver: RFC 8484 POST `/dns-query` (`application/dns-message`) on 127.0.0.1:`port`.
 * A/AAAA answers from `set()` records by address family, NXDOMAIN for unknown names, HTTP 503 while down,
 * 400 / 413 / 415 for malformed requests. Every request counts as a hit. It logs nothing.
 */
async function startDohResolver(port: number): Promise<StackDns & { close(): Promise<void> }> {
  const records = new Map<string, Uint8Array[]>();
  const sockets = new Set<net.Socket>();
  let hits = 0;
  let down = false;
  const server = http.createServer((req, res) => {
    hits++;
    const reply = (status: number, type: string, body: Uint8Array | string) => {
      res.writeHead(status, { "content-type": type, "content-length": String(Buffer.byteLength(body)), "cache-control": "no-store" });
      res.end(body);
    };
    if (down) {
      req.resume();
      return reply(503, "text/plain", "resolver down");
    }
    const ctype = (req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
    if (req.method !== "POST" || (req.url ?? "").split("?")[0] !== "/dns-query") {
      req.resume();
      return reply(400, "text/plain", "bad request");
    }
    if (ctype !== "application/dns-message") {
      req.resume();
      return reply(415, "text/plain", "unsupported media type");
    }
    const chunks: Buffer[] = [];
    let n = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > DOH_MAX_QUERY) tooBig = true;
      else chunks.push(c);
    });
    req.on("error", () => res.destroy());
    req.on("end", () => {
      if (tooBig) return reply(413, "text/plain", "too large");
      const q = Buffer.concat(chunks);
      const question = parseDnsQuestion(q);
      if (!question) return reply(400, "text/plain", "bad query");
      const addrs = records.get(question.name);
      const rdatas = (addrs ?? []).filter((a) => a.length === (question.qtype === DNS_TYPE_A ? 4 : question.qtype === DNS_TYPE_AAAA ? 16 : -1));
      reply(200, "application/dns-message", dnsAnswer(q, question, addrs ? 0 : 3, rdatas));
    });
  });
  server.requestTimeout = DOH_REQUEST_TIMEOUT_MS;
  server.headersTimeout = DOH_REQUEST_TIMEOUT_MS;
  server.on("connection", (s: net.Socket) => {
    sockets.add(s);
    s.once("close", () => sockets.delete(s));
  });
  await new Promise<void>((ok, fail) => {
    server.once("error", (e: NodeJS.ErrnoException) =>
      fail(new Error(e.code === "EADDRINUSE" ? `DoH resolver port 127.0.0.1:${port} is in use (another stack running? scripts/dev-down.sh)` : `DoH resolver: ${e.message}`)),
    );
    server.listen(port, "127.0.0.1", () => ok());
  });
  let closing: Promise<void> | null = null;
  return {
    set(name: string, addrs: string[]): void {
      if (typeof name !== "string" || name.length === 0 || name.length > 254) throw new Error("dns.set: bad name");
      if (!Array.isArray(addrs) || addrs.length > DOH_MAX_ADDRS) throw new Error("dns.set: addrs must be an array of ≤ 32 IP literals");
      const raw = addrs.map((a) => {
        const b = parseIpv4(a) ?? parseIpv6(a);
        if (!b) throw new Error(`dns.set: not an IP literal: ${String(a)}`);
        return b;
      });
      records.set(dnsKey(name), raw);
    },
    hits: () => hits,
    setDown(d: boolean): void {
      down = d === true;
    },
    close: () =>
      (closing ??= new Promise<void>((ok) => {
        server.close(() => ok());
        for (const s of sockets) s.destroy();
      })),
  };
}
