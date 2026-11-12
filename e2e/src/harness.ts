/**
 * E2E harness (SPEC-VPN §9.3): a fresh near-sandbox with the VPN registry deployed (MOCK root), the mock TDX host
 * launching the VPN exit builds, network attackers in front of an honest exit, the test builds' DoH resolver and a
 * local HTTP destination.
 *
 *   const S = await startStack();
 *   await S.approveVpnBuild("vpn-honest-test");
 *   const x = await S.startExit("vpn-honest-test");   // measured launch, registered on the VPN registry
 *   const d = await S.startDestination();
 *   S.dns.set("dest.plr.test", ["127.0.0.1"]);        // the test builds' DoH resolver (127.0.0.1:18253)
 *   await S.approveOperator("operator", "org-a");      // two-hop (SPEC-VPN §10): operator organizations
 *   …
 *   await S.stop();
 *
 * Layout: `<root>/<id>/` is the stack's `runDir` (`<root>` = `runRoot()`: `PLR_RUN_ROOT`, else `<repo>/.run`, else
 * `<repo>/e2e/.run` when the repo root is not writable — e.g. a sandbox that only allows writes under the e2e cwd) (near-sandbox home under `near/`); the mock host's
 * private socket directories live in the sibling `<root>/<id>-host/` (a Unix socket cannot be read as a
 * file) — or, when that would push a socket path over the 104-byte macOS `sun_path` limit (a long clone path), in a
 * short `<root>/plr-<hash>/` or `<tmpdir>/plr-<hash>/` (see `hostDirCandidates`). Both are removed by `stop()` unless `PLR_KEEP_RUN=1`.
 * Registration (SPEC §5 rev 1.3) is operator-bound: every launch gets the operator's credentials (`PLR_OPERATOR_ID`
 * + a fresh key of that account), and the exit binds exactly that account into its registration quote. A registering
 * launch resolves only once the stack's reader sees the instance.
 * Nothing listens on a fixed port unless asked to (`rpcPort`, exit `port`), except the local DoH resolver: the
 * test builds measure `http://127.0.0.1:18253/dns-query` (SPEC-VPN §2), so every stack runs it on exactly that port
 * (one stack at a time on a machine; a busy port fails `startStack`).
 */
import { accessSync, constants as fsConstants, existsSync, mkdirSync, readFileSync, rmdirSync } from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { mkdir, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { parseIpv4, parseIpv6, type RegistryReader, type TdxEvent } from "@plr/shared";
import { generateRootSecret, measureVpnBoot } from "@plr/enclave/mock-tdx";
import type { AttackProxy } from "./attacks.js";
import { isVpnAttack, startVpnAttackProxy } from "./vpn-attacks.js";
import { startManaged, waitFor, type ManagedProcess } from "./procs.js";
import { OPERATORS, type ChainAdmin, type ChainDriver, type OperatorAccount, type Signer } from "./chains/driver.js";
import { startNearDriver } from "./chains/near.js";

export { type ChainAdmin, type OperatorAccount, type Signer };
export { REGISTRY_WASM } from "./chains/near.js";

// ------------------------------------------------------------------------------------------------ public types

/** VPN exits (SPEC-VPN §9.3): three measured builds, and network attackers in front of `vpn-honest-test`. */
export const VPN_BUILDS = ["vpn-honest", "vpn-honest-test", "vpn-evil-logger"] as const;
export type VpnBuild = (typeof VPN_BUILDS)[number];
export const VPN_VARIANTS = [...VPN_BUILDS, "vpn-mitm-key", "vpn-replay-quote", "vpn-tamper-stream", "vpn-truncate-stream"] as const;
export type VpnVariant = (typeof VPN_VARIANTS)[number];

export interface StackOptions {
  /** The near-sandbox RPC port (default: a free port). */
  rpcPort?: number;
  /** Run id (default: random); the run directory is `<runRoot()>/<id>/`. */
  id?: string;
  /** Exit anchoring interval (default 1000 ms). */
  anchorIntervalMs?: number;
  /**
   * Receives every exit/host/attacker output chunk as it arrives (e.g. to tee into a log file), labelled by the
   * variant, or by `ExitOptions.label` when given.
   */
  onOutput?: (label: string, chunk: string) => void;
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
  /** The near-sandbox RPC URL. */
  rpcUrl: string;
  trustedRoot: Uint8Array;
  runDir: string;
  /** Account ids of the stack. */
  accounts: { owner: string; operator: string; operator2: string; stranger: string };
  /** The VPN registry (the contracts/near wasm, MOCK root). */
  vpnContractId: string;
  vpnRegistry: RegistryReader;
  /** Owner of the VPN registry (resolves once the write is on chain). */
  vpnAdmin: ChainAdmin;
  /** The same API signed by the stranger account (must be refused). */
  asStranger(a: ChainAdmin): ChainAdmin;
  /** Contract view on the VPN registry. */
  viewVpn<T>(method: string, args: object): Promise<T>;
  /** Contract call on the VPN registry; rejects with an Error whose message includes the contract panic code. */
  callVpn(signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }): Promise<unknown>;
  approveVpnBuild(build: VpnBuild): Promise<{ composeHash: string; osMeasurement: string }>;
  /** A measured quote of a build (fresh instance-id) for `reportData`, exactly as the host's launch path measures. */
  attestFor(build: VpnBuild, reportData: Uint8Array, o?: { debug?: boolean }): Promise<{ quote: Uint8Array; eventLog: TdxEvent[]; appCompose: string }>;
  startExit(variant: VpnVariant, o?: ExitOptions): Promise<ExitHandle>;
  startDestination(): Promise<Destination>;
  /** Owner → `approve_operator` on the VPN registry (re-approving changes the org). Same as `vpnAdmin.approveOperator`. */
  approveOperator(account: OperatorAccount, orgId: string): Promise<void>;
  /** Owner → `revoke_operator` on the VPN registry. */
  revokeOperator(account: OperatorAccount): Promise<void>;
  /** The test builds' DoH resolver (always running while the stack is up). */
  dns: StackDns;
  /** Stops every exit, attacker proxy, destination, the DoH resolver and the chain. */
  stop(): Promise<void>;
}

/** Extras for the dev tooling (stack-cli): not used by the tests. */
export interface DevStack extends Stack {
  /** The fresh dev-chain key of a stack account (for out-of-process owner actions in the demo). */
  exportSigner(signer: Signer): { accountId: string; secretKey: string };
  /** JSON of the owner key file for `stack-cli owner`. */
  ownerFile(): Record<string, unknown>;
  /** Client env lines locating the registry (PLR_NEAR_RPC / PLR_VPN_REGISTRY). */
  clientEnvLines(): string[];
}

// ------------------------------------------------------------------------------------------------ paths & builds

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ENCLAVE_DIST = join(REPO_ROOT, "enclave", "dist");
const HOST_CLI = join(ENCLAVE_DIST, "mock-tdx", "cli.js");
const BUILD_INFO = join(ENCLAVE_DIST, "build-info.json");
const E2E_ROOT = join(REPO_ROOT, "e2e");

/** macOS `sun_path` is 104 bytes including the terminator (the mock host enforces the same bound). */
const MAX_SOCKET_PATH = 103;
/** What the mock host appends to its run dir for the quote socket: `/tdx-XXXXXX/q.sock`. */
const SOCKET_SUFFIX_LEN = "/tdx-XXXXXX/q.sock".length;

/**
 * Directories the mock host may use as `--run-dir` (it creates `tdx-XXXXXX/q.sock` inside), best first, keeping only
 * those whose socket path fits `sun_path`: `<root>/<id>-host`, then a short `<root>/plr-<hash of root+id>`, then
 * `plr-<hash>` under each of `bases` (default `os.tmpdir()`, `/tmp`). The root and id may therefore be arbitrarily
 * long. Pure: nothing is created.
 */
export function hostDirCandidates(root: string, id: string, bases: readonly string[] = [tmpdir(), "/tmp"]): string[] {
  const name = `plr-${createHash("sha256").update(`${root}\0${id}`).digest("hex").slice(0, 12)}`;
  const all = [join(root, `${id}-host`), join(root, name), ...bases.filter((b) => b.startsWith("/")).map((b) => join(b, name))];
  return [...new Set(all)].filter((dir) => Buffer.byteLength(dir) + SOCKET_SUFFIX_LEN <= MAX_SOCKET_PATH);
}

/** The preferred host directory (`hostDirCandidates()[0]`); throws if none is short enough. */
export function hostDirFor(root: string, id: string, bases?: readonly string[]): string {
  const dir = hostDirCandidates(root, id, bases)[0];
  if (dir === undefined) throw new Error(`no short directory for host sockets (${join(root, `${id}-host`)} is too long for a Unix socket)`);
  return dir;
}

/**
 * Creates the first usable candidate (0700, non-recursive: an existing directory — e.g. a planted one under a shared
 * tmp base — fails closed) and returns it. Throws the collected errors if none can be created.
 */
async function makeHostDir(root: string, id: string): Promise<string> {
  const candidates = hostDirCandidates(root, id);
  const errors: string[] = [];
  for (const dir of candidates) {
    if (existsSync(dir)) throw new Error(`run directory already exists: ${dir}`);
    try {
      await mkdir(dir, { mode: 0o700 });
      return dir;
    } catch (e) {
      errors.push(`${dir}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`);
    }
  }
  throw new Error(`no usable directory for host sockets (${errors.join("; ") || "none short enough"})`);
}

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

const INSTANCE_TTL_MS = 86_400_000;

interface BuildInfo {
  vpn: Record<VpnBuild, { compose: { file: string; compose_hash: string } }>;
}

function loadBuildInfo(): BuildInfo {
  if (!existsSync(BUILD_INFO) || !existsSync(HOST_CLI)) {
    throw new Error(`enclave build missing (${BUILD_INFO}); run: npx tsc -b && npm run build -w @plr/enclave`);
  }
  const o = JSON.parse(readFileSync(BUILD_INFO, "utf8")) as BuildInfo;
  for (const v of VPN_BUILDS) {
    if (typeof o.vpn?.[v]?.compose?.file !== "string") throw new Error(`build-info.json: missing vpn/${v} (rebuild: npm run build -w @plr/enclave)`);
  }
  return o;
}

/** The measured build a VPN variant launches: network attacks run the approved test build behind a proxy. */
function vpnBuildOf(variant: VpnVariant): VpnBuild {
  if (!(VPN_VARIANTS as readonly string[]).includes(variant)) throw new Error(`unknown VPN variant: ${String(variant)}`);
  return (VPN_BUILDS as readonly string[]).includes(variant) ? (variant as VpnBuild) : "vpn-honest-test";
}

const RUN_ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const LABEL_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

// ------------------------------------------------------------------------------------------------ startStack

/** Boot line and registration outcome of a VPN exit (`plr-vpn`). */
const LISTEN_RE = /plr-vpn: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/;
const REG_RE = /plr-vpn: (registered key_hash=[0-9a-f]{64}|registration_failed code=(\S+)|registration_disabled)/;
const HOST_FAIL_RE = /plr-(?:host|vpn): (?:launch_refused|launch_failed|boot_failed|error|fatal) code=(\S+)/;

/** Destination server bounds: request heads up to 1 MiB (long test paths), bodies up to 16 MiB, ≤ 64 MiB recorded. */
const DEST_MAX_HEAD = 1024 * 1024;
const DEST_MAX_BODY = 16 * 1024 * 1024;
const DEST_MAX_RECORDED = 64 * 1024 * 1024;
const DEST_IDLE_MS = 60_000;

/** The test builds' measured resolver URL is `http://127.0.0.1:18253/dns-query` (SPEC-VPN §2). */
export const TEST_DOH_PORT = 18253;
/** Bound on a registered instance becoming visible to the stack's reader. */
const REGISTERED_VISIBLE_TIMEOUT_MS = 120_000;

export async function startStack(o: StackOptions = {}): Promise<DevStack> {
  const info = loadBuildInfo();

  const id = o.id ?? `e2e-${Date.now().toString(36)}-${nodeRandomBytes(3).toString("hex")}`;
  if (!RUN_ID_RE.test(id)) throw new Error("startStack: bad run id");
  const root = runRoot();
  const runDir = join(root, id);
  if (existsSync(runDir)) throw new Error(`run directory already exists: ${runDir}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const hostDir = await makeHostDir(root, id).catch(async (e: unknown) => {
    await rm(runDir, { recursive: true, force: true }).catch(() => undefined);
    throw e;
  });

  /** Teardown of everything started so far, registered the moment it starts (incl. launches in progress). */
  const teardowns = new Set<() => Promise<void>>();
  let node: ChainDriver | null = null;
  let stopping: Promise<void> | null = null;
  /**
   * Idempotent, bounded teardown: every exit subtree, attack proxy and the chain are stopped in parallel,
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

    node = await startNearDriver({ dir: runDir, trustedRoot, instanceTtlMs: INSTANCE_TTL_MS, ...(o.rpcPort !== undefined ? { rpcPort: o.rpcPort } : {}) });
    const d: ChainDriver = node;
    const { rpcUrl, vpnContractId, vpnRegistry, vpnAdmin, viewVpn, callVpn } = d;

    /** Runtime closure hashes, reused while the files are unchanged (the host itself always re-hashes). */
    const runtimeCache = new Map<string, string>();
    const vpnComposePathOf = (b: VpnBuild) => {
      if (!(VPN_BUILDS as readonly string[]).includes(b)) throw new Error(`unknown VPN build: ${String(b)}`);
      return join(ENCLAVE_DIST, info.vpn[b].compose.file);
    };
    /** Measures exactly like the host's VPN launch path does (same `measureVpnBoot`), fresh instance-id each call. */
    const measure = (build: VpnBuild, debug = false) => measureVpnBoot({ composePath: vpnComposePathOf(build), root, debug, runtimeCache });

    const approveVpnBuild = async (build: VpnBuild) => {
      const m = await measure(build);
      await vpnAdmin.allowCompose(m.composeHash);
      await vpnAdmin.allowOs(m.osMeasurement);
      return { composeHash: m.composeHash, osMeasurement: m.osMeasurement };
    };

    const attestFor = async (build: VpnBuild, rd: Uint8Array, ao: { debug?: boolean } = {}) => {
      if (!(rd instanceof Uint8Array) || rd.length !== 64) throw new Error("attestFor: reportData must be 64 bytes");
      const m = await measure(build, ao.debug === true);
      const { quote, eventLog } = await m.attester.getQuote(rd);
      return { quote, eventLog, appCompose: new TextDecoder("utf-8", { fatal: true }).decode(m.composeBytes) };
    };

    /** One measured exit launch through the mock TDX host CLI. */
    interface HostLaunch {
      /** Output label (log file name in the dev stack). */
      label: string;
      /** Diagnostics, e.g. "exit vpn-honest-test". */
      what: string;
      /** Host CLI arguments after `launch`. */
      hostArgs: string[];
      register: boolean;
      /** The account that registers the instance (default "operator"). */
      operator?: OperatorAccount;
      listenTimeoutMs: number;
    }

    /** Launches a measured build through the mock TDX host CLI (separate process, lifeline-bound). */
    const launchHost = async (l: HostLaunch): Promise<ExitHandle> => {
      const env: Record<string, string> = {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? homedir(),
        PLR_MOCK_ROOT_SECRET_FILE: rootSecretFile,
        PLR_ANCHOR_INTERVAL_MS: String(o.anchorIntervalMs ?? 1000),
      };
      // The operator's credentials (a fresh full-access key per TD, see chains/near.ts).
      if (l.register) Object.assign(env, await d.instanceEnv(l.operator ?? "operator"));
      const proc: ManagedProcess = startManaged({
        name: `vpn:${l.label}`,
        cmd: process.execPath,
        args: [HOST_CLI, "launch", ...l.hostArgs],
        env,
        cwd: hostDir,
        ...(o.onOutput ? { onOutput: (s: string) => o.onOutput!(l.label, s) } : {}),
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
        const m = await waitFor(
          `${l.what} to listen`,
          () => {
            const out = proc.output();
            const ok = LISTEN_RE.exec(out);
            if (ok) return ok;
            const bad = HOST_FAIL_RE.exec(out);
            if (bad) throw new Error(`${l.what} failed to start: ${bad[1]}`);
            if (proc.exited) throw new Error(`${l.what} exited before listening:\n${out.slice(-4000)}`);
            return undefined;
          },
          l.listenTimeoutMs,
        );
        const url = m[1]!;
        await waitFor(`${l.what} /healthz`, async () => {
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
          const outcome = await waitFor(`${l.what} registration outcome`, () => {
            if (proc.exited) throw new Error(`${l.what} exited`);
            return REG_RE.exec(proc.output()) ?? undefined;
          }, 120_000, 100);
          if (outcome[1]!.startsWith("registered")) {
            // Resolve only once the stack's reader sees the instance.
            await waitFor(`${l.what} registration visible to the reader`, async () => {
              if (proc.exited) throw new Error(`${l.what} exited`);
              return (await vpnRegistry.getInstance(keyHash).catch(() => null)) !== null ? true : undefined;
            }, REGISTERED_VISIBLE_TIMEOUT_MS, 250);
          }
        }
        return { url, keyHash, composeHash: m[3]!, output: () => proc.output(), stop: stopProc };
      } catch (e) {
        await stopProc();
        throw e;
      }
    };

    /** Wraps a launched instance behind an attacker proxy; stopping the handle stops both. */
    const behindProxy = (inner: ExitHandle, proxy: AttackProxy, proxyLog: () => string): ExitHandle => {
      let closed: Promise<void> | null = null;
      const close = (): Promise<void> =>
        (closed ??= Promise.allSettled([proxy.close(), inner.stop()]).then(() => {
          teardowns.delete(close);
        }));
      teardowns.add(close);
      return { url: proxy.url, composeHash: inner.composeHash, keyHash: inner.keyHash, output: () => inner.output() + proxyLog(), stop: close };
    };

    const launchExit = (build: VpnBuild, xo: ExitOptions, label: string): Promise<ExitHandle> =>
      launchHost({
        label,
        what: `exit ${label}`,
        hostArgs: ["--compose", vpnComposePathOf(build), "--run-dir", hostDir, "--exit-port", String(xo.port ?? 0)],
        register: xo.register !== false,
        operator: xo.operator ?? "operator",
        listenTimeoutMs: 60_000,
      });

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
          o.onOutput?.(label, line);
        });
      } catch (e) {
        await inner.stop();
        throw e;
      }
      return behindProxy(inner, proxy, () => proxyLog);
    };

    const startDestination = async (): Promise<Destination> => {
      if (stopping) throw new Error("stack is stopped");
      const dd = await startDestinationServer();
      let closed: Promise<void> | null = null;
      const close = (): Promise<void> =>
        (closed ??= dd.close().then(() => {
          teardowns.delete(close);
        }));
      teardowns.add(close);
      return { ...dd, close };
    };

    const approveOperator = (account: OperatorAccount, orgId: string): Promise<void> => vpnAdmin.approveOperator(account, orgId);
    const revokeOperator = (account: OperatorAccount): Promise<void> => vpnAdmin.revokeOperator(account);

    return {
      rpcUrl,
      trustedRoot,
      runDir,
      accounts: d.accounts,
      vpnContractId,
      vpnRegistry,
      vpnAdmin,
      asStranger: (a: ChainAdmin) => d.asStranger(a),
      viewVpn,
      callVpn,
      approveVpnBuild,
      attestFor,
      startExit,
      startDestination,
      approveOperator,
      revokeOperator,
      dns,
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
