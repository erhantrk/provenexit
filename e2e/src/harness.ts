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
 *   …
 *   await S.stop();
 *
 * Layout: `<repo>/.run/<id>/` is the stack's `runDir` (near-sandbox home under `near/`); the mock host's
 * private socket directories live in the sibling `<repo>/.run/<id>-host/` (a Unix socket cannot be read as a
 * file, and macOS limits socket paths to 104 bytes). Both are removed by `stop()` unless `PLR_KEEP_RUN=1`.
 * Nothing listens on a fixed port unless asked to (`rpcPort`, `routerPort`), except the local DoH resolver: the
 * test builds measure `http://127.0.0.1:18253/dns-query` (SPEC-VPN §2), so every stack runs it on exactly that port
 * (one stack at a time on a machine; a busy port fails `startStack`).
 */
import { existsSync, readFileSync } from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, type KeyPairString } from "near-api-js";
import { parseIpv4, parseIpv6, toHex, type RegistryReader, type TdxEvent } from "@plr/shared";
import { NearRegistry } from "@plr/client";
import { generateRootSecret, measureBoot, measureVpnBoot } from "@plr/enclave/mock-tdx";
import { isAttack, startAttackProxy, type AttackProxy } from "./attacks.js";
import { isVpnAttack, startVpnAttackProxy } from "./vpn-attacks.js";
import { startManaged, waitFor, type ManagedProcess } from "./procs.js";
import { startSandbox, type SandboxNode } from "./sandbox.js";

// ------------------------------------------------------------------------------------------------ public types

export const VARIANTS = ["honest", "evil-logger", "mitm-key", "replay-quote", "debug-td", "truncate-stream", "tamper-stream"] as const;
export type Variant = (typeof VARIANTS)[number];
export type LlmChoice = "mock" | "llama";
export type Signer = "owner" | "operator" | "operator2" | "stranger";
/** Accounts that operate (register) VPN exits; the owner maps them to organizations (SPEC §7 rev 1.2). */
export type OperatorAccount = "operator" | "operator2";
/** VPN exits (SPEC-VPN §9.3): three measured builds, and network attackers in front of `vpn-honest-test`. */
export const VPN_BUILDS = ["vpn-honest", "vpn-honest-test", "vpn-evil-logger"] as const;
export type VpnBuild = (typeof VPN_BUILDS)[number];
export const VPN_VARIANTS = [...VPN_BUILDS, "vpn-mitm-key", "vpn-replay-quote", "vpn-tamper-stream", "vpn-truncate-stream"] as const;
export type VpnVariant = (typeof VPN_VARIANTS)[number];

export interface StackOptions {
  llm: LlmChoice;
  /** near-sandbox RPC port (default: a free port). */
  rpcPort?: number;
  /** Run id (default: random); the run directory is `<repo>/.run/<id>/`. */
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
  rpcUrl: string;
  contractId: string;
  trustedRoot: Uint8Array;
  registry: RegistryReader;
  runDir: string;
  accounts: { owner: string; operator: string; operator2: string; stranger: string };
  view<T>(method: string, args: object): Promise<T>;
  /** Rejects with an Error whose message includes the contract panic code. */
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
  /** Owner → `approve_operator` on the VPN registry (re-approving changes the org). */
  approveOperator(account: OperatorAccount, orgId: string): Promise<void>;
  /** Owner → `revoke_operator` on the VPN registry. */
  revokeOperator(account: OperatorAccount): Promise<void>;
  /** The test builds' DoH resolver (always running while the stack is up). */
  dns: StackDns;
  /** Stops every router, exit, attacker proxy, destination, the DoH resolver and the chain. */
  stop(): Promise<void>;
}

/** Extras for the dev tooling (stack-cli): not used by the tests. */
export interface DevStack extends Stack {
  /** The fresh dev-chain key of a stack account (for out-of-process owner actions in the demo). */
  exportSigner(signer: Signer): { accountId: string; secretKey: KeyPairString };
}

// ------------------------------------------------------------------------------------------------ paths & builds

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ENCLAVE_DIST = join(REPO_ROOT, "enclave", "dist");
const HOST_CLI = join(ENCLAVE_DIST, "mock-tdx", "cli.js");
const BUILD_INFO = join(ENCLAVE_DIST, "build-info.json");
export const REGISTRY_WASM = join(REPO_ROOT, "contracts", "near", "target", "near", "plr_registry.wasm");
const DEFAULT_LLAMA_MODEL = join(homedir(), "models", "qwen2.5-0.5b-instruct-q4_k_m.gguf");

const NEAR = 10n ** 24n;
const DEFAULT_GAS = 300_000_000_000_000n;
const INSTANCE_TTL_MS = 86_400_000;

interface BuildInfo {
  variants: Record<"honest" | "evil-logger", { compose: Record<LlmChoice, { file: string; compose_hash: string }> }>;
  vpn: Record<VpnBuild, { compose: { file: string; compose_hash: string } }>;
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
const OPERATORS: readonly OperatorAccount[] = ["operator", "operator2"];

export async function startStack(o: StackOptions): Promise<DevStack> {
  if (o.llm !== "mock" && o.llm !== "llama") throw new Error(`startStack: llm must be "mock" or "llama"`);
  const info = loadBuildInfo();
  if (!existsSync(REGISTRY_WASM)) throw new Error(`registry wasm missing (${REGISTRY_WASM}); run: cd contracts/near && cargo near build non-reproducible-wasm --no-abi`);
  const llmFile = o.llm === "llama" ? (process.env.PLR_MODEL_PATH || DEFAULT_LLAMA_MODEL) : undefined;
  if (llmFile && !existsSync(llmFile)) throw new Error(`model not found: ${llmFile}`);

  const id = o.id ?? `e2e-${Date.now().toString(36)}-${nodeRandomBytes(3).toString("hex")}`;
  if (!RUN_ID_RE.test(id)) throw new Error("startStack: bad run id");
  const runDir = join(REPO_ROOT, ".run", id);
  const hostDir = join(REPO_ROOT, ".run", `${id}-host`);
  if (existsSync(runDir) || existsSync(hostDir)) throw new Error(`run directory already exists: ${runDir}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  await mkdir(hostDir, { recursive: true, mode: 0o700 });

  /** Teardown of everything started so far, registered the moment it starts (incl. launches in progress). */
  const teardowns = new Set<() => Promise<void>>();
  let node: SandboxNode | null = null;
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

    node = await startSandbox({ homeDir: join(runDir, "near"), ...(o.rpcPort !== undefined ? { rpcPort: o.rpcPort } : {}) });
    const rpcUrl = node.rpcUrl;
    const provider = new JsonRpcProvider({ url: rpcUrl });
    const rootAcct = new Account(node.rootAccountId, provider, KeyPairSigner.fromSecretKey(node.rootKey));

    // Accounts: registry + vpnregistry (contracts), owner, operator, operator2, stranger — each with its own fresh key.
    const names = {
      registry: `registry.${node.rootAccountId}`,
      vpnregistry: `vpnregistry.${node.rootAccountId}`,
      owner: `owner.${node.rootAccountId}`,
      operator: `operator.${node.rootAccountId}`,
      operator2: `operator2.${node.rootAccountId}`,
      stranger: `stranger.${node.rootAccountId}`,
    };
    type Role = keyof typeof names;
    const keys = new Map<string, KeyPair>();
    for (const [role, accountId] of Object.entries(names)) {
      const kp = KeyPair.fromRandom("ed25519");
      keys.set(role, kp);
      const isContract = role === "registry" || role === "vpnregistry";
      await rootAcct.createAccount({ newAccountId: accountId, publicKey: kp.getPublicKey().toString(), nearToTransfer: (isContract ? 50n : 100n) * NEAR });
    }
    const acct = (role: Role) => new Account(names[role], provider, KeyPairSigner.fromSecretKey(keys.get(role)!.toString() as KeyPairString));
    const signers: Record<Signer, Account> = { owner: acct("owner"), operator: acct("operator"), operator2: acct("operator2"), stranger: acct("stranger") };
    const contractId = names.registry;
    const vpnContractId = names.vpnregistry;

    // Both registries: the same wasm, owner and MOCK root; independent allowlists, instances and anchors.
    const wasm = new Uint8Array(readFileSync(REGISTRY_WASM));
    for (const role of ["registry", "vpnregistry"] as const) {
      const a = acct(role);
      await a.deployContract(wasm);
      await a.callFunction({
        contractId: names[role],
        methodName: "new",
        args: { owner_id: names.owner, root_kind: "MOCK", root_p256: toHex(trustedRoot), instance_ttl_ms: INSTANCE_TTL_MS },
        gas: DEFAULT_GAS,
      });
    }

    const registry = new NearRegistry({ rpcUrl, contractId });
    const vpnRegistry = new NearRegistry({ rpcUrl, contractId: vpnContractId });

    const view = async <T>(method: string, args: object): Promise<T> => {
      const raw = await provider.callFunctionRaw({ contractId, method, args: args as Record<string, unknown>, blockQuery: { finality: "optimistic" } });
      const bytes = new Uint8Array(raw.result);
      if (bytes.length === 0) return undefined as T;
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as T;
    };

    const callOn = (target: string) => async (signer: Signer, method: string, args: object, co: { deposit?: string; gas?: string } = {}): Promise<unknown> => {
      const a = signers[signer];
      if (!a) throw new Error(`unknown signer: ${String(signer)}`);
      const amount = (v: string | undefined, def: bigint, what: string): bigint => {
        if (v === undefined) return def;
        if (!/^[0-9]{1,40}$/.test(v)) throw new Error(`call: bad ${what}`);
        return BigInt(v);
      };
      try {
        return await a.callFunction({ contractId: target, methodName: method, args: args as Record<string, unknown>, gas: amount(co.gas, DEFAULT_GAS, "gas"), deposit: amount(co.deposit, 0n, "deposit") });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const err = new Error(`${method} failed: ${msg}`);
        (err as Error & { cause?: unknown }).cause = e;
        throw err;
      }
    };
    const call = callOn(contractId);
    const callVpn = callOn(vpnContractId);

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
      await call("owner", "allow_compose", { hash: m.composeHash });
      await call("owner", "allow_os", { hash: m.osMeasurement });
      return { composeHash: m.composeHash, osMeasurement: m.osMeasurement };
    };

    const attestFor = async (variant: Variant, rd: Uint8Array) => {
      if (!(rd instanceof Uint8Array) || rd.length !== 64) throw new Error("attestFor: reportData must be 64 bytes");
      const m = await measure(variant);
      const { quote, eventLog } = await m.attester.getQuote(rd);
      return { quote, eventLog, appCompose: new TextDecoder("utf-8", { fatal: true }).decode(m.composeBytes) };
    };

    /** One measured launch through the mock TDX host CLI (router or VPN exit). */
    interface HostLaunch {
      service: "router" | "vpn";
      /** Output label (log file name in the dev stack). */
      label: string;
      /** Diagnostics, e.g. "router honest" / "exit vpn-honest-test". */
      what: string;
      /** Host CLI arguments after `launch`. */
      hostArgs: string[];
      register: boolean;
      /** The account that registers the instance (default "operator"). */
      operator?: OperatorAccount;
      /** The registry variable for this service (`PLR_REGISTRY` / `PLR_VPN_REGISTRY`) → contract id. */
      registryEnv: Record<string, string>;
      listenTimeoutMs: number;
    }

    /** Launches a measured build through the mock TDX host CLI (separate process, lifeline-bound). */
    const launchHost = async (l: HostLaunch): Promise<RouterHandle> => {
      const env: Record<string, string> = {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? homedir(),
        PLR_MOCK_ROOT_SECRET_FILE: rootSecretFile,
        PLR_ANCHOR_INTERVAL_MS: String(o.anchorIntervalMs ?? 1000),
      };
      if (l.register) {
        // A dedicated full-access key per instance on the operator account: no nonce races between instances or
        // with the harness's own operator calls. (Function-call keys cannot attach the storage deposit.)
        const op = l.operator ?? "operator";
        const instanceKey = KeyPair.fromRandom("ed25519");
        await signers[op].addFullAccessKey(instanceKey.getPublicKey().toString());
        Object.assign(env, { PLR_NEAR_RPC: rpcUrl, ...l.registryEnv, PLR_OPERATOR_ID: names[op], PLR_OPERATOR_KEY: instanceKey.toString() });
      }
      const proc: ManagedProcess = startManaged({
        name: `${l.service}:${l.label}`,
        cmd: process.execPath,
        args: [HOST_CLI, "launch", ...l.hostArgs],
        env,
        cwd: hostDir,
        ...(o.onRouterOutput ? { onOutput: (s: string) => o.onRouterOutput!(l.label, s) } : {}),
      });
      // Bounded and idempotent (group SIGTERM → ≤ 10 s → group SIGKILL). The per-instance access key is left on
      // the throw-away chain: deleting it would put an RPC round-trip on every shutdown path.
      let stopped: Promise<void> | null = null;
      const stopProc = (): Promise<void> =>
        (stopped ??= proc.stop().then(() => {
          teardowns.delete(stopProc);
        }));
      teardowns.add(stopProc);
      if (stopping) await stopProc(); // raced with stack.stop(): the wait below fails fast
      try {
        const m = await waitFor(
          `${l.what} to listen`,
          () => {
            const out = proc.output();
            const ok = LISTEN_RE[l.service].exec(out);
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
        if (l.register) {
          // Registration may legitimately fail (unapproved or debug builds): the instance keeps serving.
          await waitFor(`${l.what} registration outcome`, () => {
            if (proc.exited) throw new Error(`${l.what} exited`);
            return REG_RE[l.service].exec(proc.output()) ? true : undefined;
          }, 120_000, 100);
        }
        return { url, keyHash: m[2]!, composeHash: m[3]!, output: () => proc.output(), stop: stopProc };
      } catch (e) {
        await stopProc();
        throw e;
      }
    };

    const launchBuild = (variant: Variant, ro: RouterOptions, label: Variant = variant): Promise<RouterHandle> => {
      const b = buildOf(variant);
      return launchHost({
        service: "router",
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
        registryEnv: { PLR_REGISTRY: contractId },
        listenTimeoutMs: o.llm === "llama" ? 300_000 : 60_000,
      });
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
      await callVpn("owner", "allow_compose", { hash: m.composeHash });
      await callVpn("owner", "allow_os", { hash: m.osMeasurement });
      return { composeHash: m.composeHash, osMeasurement: m.osMeasurement };
    };

    const launchExit = (build: VpnBuild, xo: ExitOptions, label: string): Promise<ExitHandle> =>
      launchHost({
        service: "vpn",
        label,
        what: `exit ${label}`,
        hostArgs: ["--compose", vpnComposePathOf(build), "--run-dir", hostDir, "--exit-port", String(xo.port ?? 0)],
        register: xo.register !== false,
        operator: xo.operator ?? "operator",
        registryEnv: { PLR_VPN_REGISTRY: vpnContractId },
        listenTimeoutMs: 60_000,
      });

    const startExit = async (variant: VpnVariant, xo: ExitOptions = {}): Promise<ExitHandle> => {
      if (stopping) throw new Error("stack is stopped");
      const build = vpnBuildOf(variant);
      if (xo.operator !== undefined && !OPERATORS.includes(xo.operator)) throw new Error(`startExit: unknown operator: ${String(xo.operator)}`);
      if (xo.label !== undefined && !/^[a-z0-9][a-z0-9-]{0,39}$/.test(xo.label)) throw new Error("startExit: bad label");
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

    const operatorId = (account: OperatorAccount): string => {
      if (!OPERATORS.includes(account)) throw new Error(`unknown operator account: ${String(account)}`);
      return names[account];
    };
    const approveOperator = async (account: OperatorAccount, orgId: string): Promise<void> => {
      await callVpn("owner", "approve_operator", { account_id: operatorId(account), org_id: orgId });
    };
    const revokeOperator = async (account: OperatorAccount): Promise<void> => {
      await callVpn("owner", "revoke_operator", { account_id: operatorId(account) });
    };

    return {
      rpcUrl,
      contractId,
      trustedRoot,
      registry,
      runDir,
      accounts: { owner: names.owner, operator: names.operator, operator2: names.operator2, stranger: names.stranger },
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
      stop,
      exportSigner: (signer: Signer) => {
        const kp = keys.get(signer);
        if (!kp || !(signer in signers)) throw new Error(`unknown signer: ${String(signer)}`);
        return { accountId: names[signer], secretKey: kp.toString() as KeyPairString };
      },
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
