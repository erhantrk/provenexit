/**
 * E2E harness (SPEC §13): a fresh near-sandbox with the registry deployed, the mock TDX host launching
 * honest / evil / debug router builds, and network attackers in front of an honest router.
 *
 *   const S = await startStack({ llm: "mock" });
 *   await S.approveBuild("honest");
 *   const r = await S.startRouter("honest");   // measured launch, registered on-chain
 *   …
 *   await S.stop();
 *
 * Layout: `<repo>/.run/<id>/` is the stack's `runDir` (near-sandbox home under `near/`); the mock host's
 * private socket directories live in the sibling `<repo>/.run/<id>-host/` (a Unix socket cannot be read as a
 * file, and macOS limits socket paths to 104 bytes). Both are removed by `stop()` unless `PLR_KEEP_RUN=1`.
 * Nothing listens on a fixed port unless asked to (`rpcPort`, `routerPort`).
 */
import { existsSync, readFileSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, type KeyPairString } from "near-api-js";
import { toHex, type RegistryReader, type TdxEvent } from "@plr/shared";
import { NearRegistry } from "@plr/client";
import { generateRootSecret, measureBoot } from "@plr/enclave/mock-tdx";
import { isAttack, startAttackProxy, type AttackProxy } from "./attacks.js";
import { startManaged, waitFor, type ManagedProcess } from "./procs.js";
import { startSandbox, type SandboxNode } from "./sandbox.js";

// ------------------------------------------------------------------------------------------------ public types

export const VARIANTS = ["honest", "evil-logger", "mitm-key", "replay-quote", "debug-td", "truncate-stream", "tamper-stream"] as const;
export type Variant = (typeof VARIANTS)[number];
export type LlmChoice = "mock" | "llama";
export type Signer = "owner" | "operator" | "stranger";

export interface StackOptions {
  llm: LlmChoice;
  /** near-sandbox RPC port (default: a free port). */
  rpcPort?: number;
  /** Run id (default: random); the run directory is `<repo>/.run/<id>/`. */
  id?: string;
  /** Router anchoring interval (default 1000 ms). */
  anchorIntervalMs?: number;
  /** Receives every router/host/attacker output chunk as it arrives (e.g. to tee into a log file). */
  onRouterOutput?: (variant: Variant, chunk: string) => void;
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

export interface Stack {
  rpcUrl: string;
  contractId: string;
  trustedRoot: Uint8Array;
  registry: RegistryReader;
  runDir: string;
  accounts: { owner: string; operator: string; stranger: string };
  view<T>(method: string, args: object): Promise<T>;
  /** Rejects with an Error whose message includes the contract panic code. */
  call(signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }): Promise<unknown>;
  approveBuild(variant: Variant): Promise<{ composeHash: string; osMeasurement: string }>;
  startRouter(variant: Variant, o?: RouterOptions): Promise<RouterHandle>;
  attestFor(variant: Variant, reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[]; appCompose: string }>;
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

const RUN_ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;

// ------------------------------------------------------------------------------------------------ startStack

const LISTEN_RE = /plr-router: listening url=(\S+) key_hash=([0-9a-f]{64}) compose_hash=([0-9a-f]{64})/;
const REG_RE = /plr-router: (registered key_hash=[0-9a-f]{64}|registration_failed code=(\S+)|registration_disabled)/;
const HOST_FAIL_RE = /plr-(?:host|router): (?:launch_refused|launch_failed|boot_failed|error|fatal) code=(\S+)/;

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

    node = await startSandbox({ homeDir: join(runDir, "near"), ...(o.rpcPort !== undefined ? { rpcPort: o.rpcPort } : {}) });
    const rpcUrl = node.rpcUrl;
    const provider = new JsonRpcProvider({ url: rpcUrl });
    const rootAcct = new Account(node.rootAccountId, provider, KeyPairSigner.fromSecretKey(node.rootKey));

    // Accounts: registry (contract), owner, operator, stranger — each with its own fresh key.
    const names = { registry: `registry.${node.rootAccountId}`, owner: `owner.${node.rootAccountId}`, operator: `operator.${node.rootAccountId}`, stranger: `stranger.${node.rootAccountId}` };
    const keys = new Map<string, KeyPair>();
    for (const [role, accountId] of Object.entries(names)) {
      const kp = KeyPair.fromRandom("ed25519");
      keys.set(role, kp);
      await rootAcct.createAccount({ newAccountId: accountId, publicKey: kp.getPublicKey().toString(), nearToTransfer: (role === "registry" ? 50n : 100n) * NEAR });
    }
    const acct = (role: "registry" | Signer) => new Account(names[role], provider, KeyPairSigner.fromSecretKey(keys.get(role)!.toString() as KeyPairString));
    const signers: Record<Signer, Account> = { owner: acct("owner"), operator: acct("operator"), stranger: acct("stranger") };
    const contractId = names.registry;

    const registryAcct = acct("registry");
    await registryAcct.deployContract(new Uint8Array(readFileSync(REGISTRY_WASM)));
    await registryAcct.callFunction({
      contractId,
      methodName: "new",
      args: { owner_id: names.owner, root_kind: "MOCK", root_p256: toHex(trustedRoot), instance_ttl_ms: INSTANCE_TTL_MS },
      gas: DEFAULT_GAS,
    });

    const registry = new NearRegistry({ rpcUrl, contractId });

    const view = async <T>(method: string, args: object): Promise<T> => {
      const raw = await provider.callFunctionRaw({ contractId, method, args: args as Record<string, unknown>, blockQuery: { finality: "optimistic" } });
      const bytes = new Uint8Array(raw.result);
      if (bytes.length === 0) return undefined as T;
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as T;
    };

    const call = async (signer: Signer, method: string, args: object, co: { deposit?: string; gas?: string } = {}): Promise<unknown> => {
      const a = signers[signer];
      if (!a) throw new Error(`unknown signer: ${String(signer)}`);
      const amount = (v: string | undefined, def: bigint, what: string): bigint => {
        if (v === undefined) return def;
        if (!/^[0-9]{1,40}$/.test(v)) throw new Error(`call: bad ${what}`);
        return BigInt(v);
      };
      try {
        return await a.callFunction({ contractId, methodName: method, args: args as Record<string, unknown>, gas: amount(co.gas, DEFAULT_GAS, "gas"), deposit: amount(co.deposit, 0n, "deposit") });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const err = new Error(`${method} failed: ${msg}`);
        (err as Error & { cause?: unknown }).cause = e;
        throw err;
      }
    };

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

    /** Launches a measured build through the mock TDX host CLI (separate process, lifeline-bound). */
    const launchBuild = async (variant: Variant, ro: RouterOptions, label: Variant = variant): Promise<RouterHandle> => {
      const b = buildOf(variant);
      const register = ro.register !== false;
      const env: Record<string, string> = {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? homedir(),
        PLR_MOCK_ROOT_SECRET_FILE: rootSecretFile,
        PLR_ANCHOR_INTERVAL_MS: String(o.anchorIntervalMs ?? 1000),
      };
      let instanceKey: KeyPair | null = null;
      if (register) {
        // A dedicated full-access key per router on the operator account: no nonce races between routers or
        // with the harness's own operator calls. (Function-call keys cannot attach the storage deposit.)
        instanceKey = KeyPair.fromRandom("ed25519");
        await signers.operator.addFullAccessKey(instanceKey.getPublicKey().toString());
        Object.assign(env, { PLR_NEAR_RPC: rpcUrl, PLR_REGISTRY: contractId, PLR_OPERATOR_ID: names.operator, PLR_OPERATOR_KEY: instanceKey.toString() });
      }
      const args = [
        HOST_CLI, "launch",
        "--compose", composePathOf(b.build),
        "--run-dir", hostDir,
        "--state-dir", runDir,
        "--router-port", String(ro.port ?? 0),
        ...(b.debug ? ["--debug"] : []),
        ...(llmFile ? ["--llm-file", llmFile] : []),
        ...(process.env.PLR_LLAMA_SERVER ? ["--llama-server", process.env.PLR_LLAMA_SERVER] : []),
      ];
      const proc: ManagedProcess = startManaged({
        name: `router:${label}`,
        cmd: process.execPath,
        args,
        env,
        cwd: hostDir,
        ...(o.onRouterOutput ? { onOutput: (s: string) => o.onRouterOutput!(label, s) } : {}),
      });
      // Bounded and idempotent (group SIGTERM → ≤ 10 s → group SIGKILL). The per-router access key is left on
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
          `router ${variant} to listen`,
          () => {
            const out = proc.output();
            const ok = LISTEN_RE.exec(out);
            if (ok) return ok;
            const bad = HOST_FAIL_RE.exec(out);
            if (bad) throw new Error(`router ${variant} failed to start: ${bad[1]}`);
            if (proc.exited) throw new Error(`router ${variant} exited before listening:\n${out.slice(-4000)}`);
            return undefined;
          },
          o.llm === "llama" ? 300_000 : 60_000,
        );
        const url = m[1]!;
        await waitFor(`router ${variant} /healthz`, async () => {
          if (proc.exited) throw new Error(`router ${variant} exited`);
          try {
            const r = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(2000) });
            const j = r.ok ? ((await r.json()) as { ok?: unknown }) : null;
            return j?.ok === true ? true : undefined;
          } catch {
            return undefined;
          }
        }, 30_000, 200);
        if (register) {
          // Registration may legitimately fail (unapproved or debug builds): the router keeps serving.
          await waitFor(`router ${variant} registration outcome`, () => {
            if (proc.exited) throw new Error(`router ${variant} exited`);
            return REG_RE.exec(proc.output()) ? true : undefined;
          }, 120_000, 100);
        }
        const h: RouterHandle = {
          url,
          keyHash: m[2]!,
          composeHash: m[3]!,
          output: () => proc.output(),
          stop: stopProc,
        };
        return h;
      } catch (e) {
        await stopProc();
        throw e;
      }
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
      let closed: Promise<void> | null = null;
      const close = (): Promise<void> =>
        (closed ??= Promise.allSettled([proxy.close(), inner.stop()]).then(() => {
          teardowns.delete(close);
        }));
      teardowns.add(close);
      const h: RouterHandle = {
        url: proxy.url,
        composeHash: inner.composeHash,
        keyHash: inner.keyHash,
        output: () => inner.output() + proxyLog,
        stop: close,
      };
      return h;
    };

    return {
      rpcUrl,
      contractId,
      trustedRoot,
      registry,
      runDir,
      accounts: { owner: names.owner, operator: names.operator, stranger: names.stranger },
      view,
      call,
      approveBuild,
      startRouter,
      attestFor,
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
