/**
 * The mock TDX host (SPEC §4, §6.1): the local stand-in for the dstack guest OS and the TDX module.
 *
 * It is the only component that measures. It reads `app-compose.json`, hashes the router bundle, the
 * model / mock-LLM file and the runtime closures of node and llama-server (`runtime.ts`), refuses to launch
 * on any mismatch, extends RTMR3 with the boot sequence (fresh
 * random instance-id), holds the MOCK ROOT (secret read from a 0600 file) and a per-boot attestation key,
 * and serves `POST /GetQuote` on a 0600 Unix socket. It then launches the LLM and the router bundle as
 * child processes, running exactly the bytes it measured.
 *
 * The router never sees the ROOT or AK private keys: it can only ask for quotes through the socket.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, readFileSync, statSync } from "node:fs";
import { chmod, mkdtemp, writeFile, rm } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MockRoot, MockTdxAttester, fromHex, isHex, toHex, type TdxEvent } from "@plr/shared";
import { MAX_COMPOSE_BYTES, parseCompose, type AppCompose } from "../compose.js";
import { Logger, code, hex } from "../log.js";

import { HostError } from "./errors.js";
import { installRuntime, measureRuntime, type RuntimeClosure, type RuntimeHashCache } from "./runtime.js";

export { HostError };

const ENCLAVE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
/** Default mock LLM source (its sha256 is `llm.model_sha256` for `kind: "mock"`). */
export const DEFAULT_MOCK_LLM = join(ENCLAVE_DIR, "mock-llm", "server.mjs");
/** Default GGUF model (SPEC §11). */
export const DEFAULT_MODEL = join(homedir(), "models", "qwen2.5-0.5b-instruct-q4_k_m.gguf");
export const DEFAULT_LLAMA_SERVER = "/opt/homebrew/bin/llama-server";
const MAX_BUNDLE_BYTES = 64 * 1024 * 1024;
/** macOS `sun_path` is 104 bytes including the terminator. */
const MAX_SOCKET_PATH = 103;

// ------------------------------------------------------------------------------------------- root secret

/**
 * Loads the MOCK ROOT secret: a regular file, owned by us, mode 0600 (no group/other bits), containing
 * exactly 64 lowercase hex chars (optionally followed by one newline).
 */
export function loadRootSecret(path: string): MockRoot {
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new HostError("E_ROOT_SECRET");
  }
  if (!st.isFile() || (st.mode & 0o077) !== 0 || (typeof process.getuid === "function" && st.uid !== process.getuid())) {
    throw new HostError("E_ROOT_SECRET_MODE");
  }
  if (st.size > 66) throw new HostError("E_ROOT_SECRET");
  const text = readFileSync(path, "utf8").replace(/\n$/, "");
  if (!isHex(text, 32)) throw new HostError("E_ROOT_SECRET");
  try {
    return MockRoot.fromSecret(fromHex(text, 32));
  } catch {
    throw new HostError("E_ROOT_SECRET");
  }
}

/** Writes a fresh MOCK ROOT secret file (mode 0600, refuses to overwrite). Returns the root. */
export async function generateRootSecret(path: string): Promise<MockRoot> {
  const root = MockRoot.generate();
  await writeFile(path, toHex(root.secretKey) + "\n", { mode: 0o600, flag: "wx" });
  return root;
}

// ------------------------------------------------------------------------------------------- measurement

export interface MeasureSpec {
  /** Path of the app-compose.json to launch. */
  composePath: string;
  /** Router bundle; default `<dir of compose>/<router.entry>`. */
  bundlePath?: string;
  /** The model (llama.cpp) or mock-LLM server file; defaults per kind. */
  llmFile?: string;
  /** Launch the TD with the DEBUG attribute. */
  debug?: boolean;
  /** llama-server executable (kind `llama.cpp`); its runtime closure must match `llm.runtime_sha256`. */
  llamaServer?: string;
  /** Node executable for the router and the mock LLM (default: this process's); must match `router.node_sha256`. */
  nodePath?: string;
  /** Hash cache for repeated measurements (harnesses). `launch` never uses it: it re-hashes the copies it runs. */
  runtimeCache?: RuntimeHashCache;
}

export interface MeasuredBoot {
  compose: AppCompose;
  composeBytes: Uint8Array;
  composeHash: string;
  bundlePath: string;
  /** The exact bundle bytes that were measured (the host runs these, not the file on disk). */
  bundleBytes: Uint8Array;
  llmFile: string;
  /** Measured mock-LLM bytes (kind "mock" only). */
  llmBytes: Uint8Array | null;
  /** Measured node runtime (router, and the mock LLM). */
  nodeRuntime: RuntimeClosure;
  /** Measured LLM runtime: llama-server for `llama.cpp`, the node runtime for `mock`. */
  llmRuntime: RuntimeClosure;
  attester: MockTdxAttester;
  eventLog: TdxEvent[];
  osMeasurement: string;
  debug: boolean;
}

function sha256Hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

function sha256File(path: string): Promise<string> {
  return new Promise((ok, fail) => {
    const h = createHash("sha256");
    createReadStream(path)
      .on("data", (c) => h.update(c))
      .on("error", () => fail(new HostError("E_LLM_FILE")))
      .on("end", () => ok(h.digest("hex")));
  });
}

function readBounded(path: string, max: number, err: string): Uint8Array {
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new HostError(err);
  }
  if (!st.isFile() || st.size > max) throw new HostError(err);
  return new Uint8Array(readFileSync(path));
}

/** Constant-time comparison of two equal-length lowercase hex digests. */
function digestEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/**
 * Measures a launch: parses the compose (strict, canonical), checks the bundle and LLM hashes against it
 * (→ HostError E_MEASUREMENT_MISMATCH), and creates the per-boot attester with the §3 boot event log.
 */
export async function measureBoot(spec: MeasureSpec & { root: MockRoot }): Promise<MeasuredBoot> {
  const composeBytes = readBounded(spec.composePath, MAX_COMPOSE_BYTES, "E_COMPOSE");
  let compose: AppCompose;
  try {
    compose = parseCompose(composeBytes);
  } catch {
    throw new HostError("E_COMPOSE");
  }
  const bundlePath = resolve(spec.bundlePath ?? join(dirname(spec.composePath), compose.router.entry));
  if (basename(bundlePath) !== compose.router.entry) throw new HostError("E_BUNDLE_ENTRY");
  const bundleBytes = readBounded(bundlePath, MAX_BUNDLE_BYTES, "E_BUNDLE");
  if (!digestEq(sha256Hex(bundleBytes), compose.router.bundle_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");

  const kind = compose.llm.kind;
  const llmFile = resolve(spec.llmFile ?? (kind === "mock" ? DEFAULT_MOCK_LLM : DEFAULT_MODEL));
  let llmBytes: Uint8Array | null = null;
  let llmHash: string;
  if (kind === "mock") {
    llmBytes = readBounded(llmFile, 1024 * 1024, "E_LLM_FILE");
    llmHash = sha256Hex(llmBytes);
  } else {
    llmHash = await sha256File(llmFile);
  }
  if (!digestEq(llmHash, compose.llm.model_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");

  // Runtimes that will see plaintext: node (router, mock LLM) and llama-server.
  const cache = spec.runtimeCache ? { cache: spec.runtimeCache } : {};
  const nodeRuntime = await measureRuntime(spec.nodePath ?? process.execPath, cache);
  if (!digestEq(nodeRuntime.digest, compose.router.node_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");
  const llmRuntime = kind === "mock" ? nodeRuntime : await measureRuntime(spec.llamaServer ?? DEFAULT_LLAMA_SERVER, cache);
  if (!digestEq(llmRuntime.digest, compose.llm.runtime_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");

  const debug = spec.debug === true;
  const attester = new MockTdxAttester({ root: spec.root, composeBytes, debug });
  return {
    compose,
    composeBytes,
    composeHash: toHex(attester.composeHash),
    bundlePath,
    bundleBytes,
    llmFile,
    llmBytes,
    nodeRuntime,
    llmRuntime,
    attester,
    eventLog: attester.eventLog,
    osMeasurement: toHex(attester.osMeasurement),
    debug,
  };
}

// ------------------------------------------------------------------------------------------- quote socket

const MAX_QUOTE_REQ = 4096;

/** `POST /GetQuote {"report_data":"<128 hex>"}` → `{"quote":"<hex>","event_log":[...]}` on a 0600 Unix socket. */
export async function startQuoteServer(socketPath: string, attester: MockTdxAttester): Promise<{ close(): Promise<void> }> {
  if (Buffer.byteLength(socketPath) > MAX_SOCKET_PATH) throw new HostError("E_SOCKET_PATH");
  const server = http.createServer((req, res) => {
    const reply = (status: number, body: unknown) => {
      const b = Buffer.from(JSON.stringify(body));
      res.writeHead(status, { "content-type": "application/json", "content-length": String(b.length) });
      res.end(b);
    };
    if (req.method !== "POST" || req.url !== "/GetQuote") {
      req.resume();
      return reply(404, { error: "E_NOT_FOUND" });
    }
    const chunks: Buffer[] = [];
    let n = 0;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > MAX_QUOTE_REQ) req.destroy();
      else chunks.push(c);
    });
    req.on("end", () => {
      let rd: Uint8Array;
      try {
        const o: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (typeof o !== "object" || o === null || Array.isArray(o) || Object.keys(o).length !== 1) throw new Error();
        const h = (o as Record<string, unknown>).report_data;
        if (!isHex(h, 64)) throw new Error();
        rd = fromHex(h, 64);
      } catch {
        return reply(400, { error: "E_BAD_REQUEST" });
      }
      attester.getQuote(rd).then(
        ({ quote, eventLog }) => reply(200, { quote: toHex(quote), event_log: eventLog }),
        () => reply(500, { error: "E_INTERNAL" }),
      );
    });
  });
  server.headersTimeout = 5000;
  server.requestTimeout = 10_000;
  await new Promise<void>((ok, fail) => {
    server.once("error", () => fail(new HostError("E_SOCKET")));
    // Restrictive umask while the socket file is created, then make the mode explicit.
    const old = process.umask(0o177);
    try {
      server.listen(socketPath, () => ok());
    } finally {
      process.umask(old);
    }
  });
  await chmod(socketPath, 0o600);
  return {
    close: () =>
      new Promise<void>((ok) => {
        server.close(() => ok());
        server.closeAllConnections();
      }),
  };
}

// ------------------------------------------------------------------------------------------- launch

export interface LaunchOptions extends MeasureSpec {
  root: MockRoot;
  /** Host state directory (a private 0700 `tdx-*` subdirectory is created inside it). */
  runDir: string;
  /**
   * The run directory announced to the router as `PLR_RUN_DIR` (default: `runDir`). Lets a harness keep the
   * host's socket dir apart from the directory it inspects. The router cannot write there anyway when the
   * compose policy is `disk: "none"`.
   */
  stateDir?: string;
  /** Router listen port (0 = ephemeral; the router prints its URL). Default 18100. */
  routerPort?: number;
  /** LLM port on 127.0.0.1 (0 = pick a free one). Default 0. */
  llmPort?: number;
  /** Extra router configuration (NEAR, anchor interval, listen host). Only allowlisted keys are passed. */
  routerEnv?: Readonly<Record<string, string | undefined>>;
  /** Receives host + router output lines. Default: process stdout. */
  output?: (chunk: string) => void;
  /** Max wait for the LLM to become healthy. */
  llmReadyTimeoutMs?: number;
  /**
   * Aborts a launch in progress (e.g. SIGTERM while the model loads): whatever was already started (LLM,
   * quote socket, private dir) is torn down and `launch` rejects with HostError E_ABORTED.
   */
  signal?: AbortSignal;
}

export interface HostHandle {
  boot: MeasuredBoot;
  socketPath: string;
  llmPort: number;
  router: ChildProcess;
  llm: ChildProcess;
  /** Resolves with the exit code once the host has shut everything down. */
  done: Promise<number>;
  stop(): Promise<number>;
}

/** Router env keys the host forwards (never NODE_OPTIONS or anything that could inject code). */
export const ROUTER_ENV_ALLOWLIST = [
  "PLR_NEAR_RPC",
  "PLR_REGISTRY",
  "PLR_OPERATOR_ID",
  "PLR_OPERATOR_KEY",
  "PLR_REGISTER_DEPOSIT",
  "PLR_ANCHOR_DEPOSIT",
  "PLR_ANCHOR_INTERVAL_MS",
  "PLR_ROUTER_HOST",
] as const;

export function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = net.createServer();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => ok(p));
    });
  });
}

function checkAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new HostError("E_ABORTED");
}

async function waitHealthy(port: number, child: ChildProcess, timeoutMs: number, signal?: AbortSignal): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    checkAborted(signal);
    if (child.exitCode !== null || child.signalCode !== null) throw new HostError("E_LLM_EXITED");
    const ok = await new Promise<boolean>((r) => {
      const req = http.get({ host: "127.0.0.1", port, path: "/health", timeout: 1000, agent: false }, (res) => {
        res.resume();
        r(res.statusCode === 200);
      });
      req.on("error", () => r(false));
      req.on("timeout", () => {
        req.destroy();
        r(false);
      });
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new HostError("E_LLM_TIMEOUT");
}

function exited(c: ChildProcess): Promise<void> {
  if (c.exitCode !== null || c.signalCode !== null) return Promise.resolve();
  return new Promise((r) => c.once("exit", () => r()));
}

async function terminate(c: ChildProcess | null): Promise<void> {
  if (!c || c.exitCode !== null || c.signalCode !== null) return;
  c.kill("SIGTERM");
  const t = setTimeout(() => c.kill("SIGKILL"), 3000);
  await exited(c);
  clearTimeout(t);
}

/**
 * Node flags enforcing the compose policy on the router process. `policy.disk == "none"` → Node's permission
 * model: the file system is read-only and limited to the private launch directory (measured bundle +
 * compose), no child processes, no worker threads, no native addons. `--disallow-code-generation-from-strings`
 * forbids eval/new Function.
 */
export function routerNodeFlags(compose: AppCompose, privDir: string): string[] {
  const flags = ["--disallow-code-generation-from-strings", "--no-addons"];
  if (compose.policy.disk === "none") flags.unshift("--permission", `--allow-fs-read=${privDir}`);
  return flags;
}

/**
 * llama-server flags. Prompt caching is fully off: no KV-cache reuse between requests (`--no-cache-prompt`,
 * `--cache-reuse 0`), no host-RAM prompt cache (`-cram 0`, `--no-cache-idle-slots`), and a single slot
 * (`-np 1`) so no slot is chosen by prompt similarity. A reused prefix would otherwise leak the previous user's
 * prompt through `timings.cache_n` and prompt-processing latency. No web UI, no /slots, no logs, no fetches.
 */
export function llamaServerArgs(modelFile: string, port: number): string[] {
  return [
    "-m", modelFile,
    "--host", "127.0.0.1",
    "--port", String(port),
    "--log-disable",
    "--no-webui",
    "--no-slots",
    "--offline",
    "-c", "4096",
    "-np", "1",
    "--no-cache-prompt",
    "--cache-reuse", "0",
    "-cram", "0",
    "--no-cache-idle-slots",
  ];
}

/**
 * Measures and launches: LLM first (waits until healthy), then the router with `PLR_TDX_SOCKET`.
 * If either child exits, the other is stopped and `done` resolves (fail closed: no half-running TD).
 */
export async function launch(o: LaunchOptions): Promise<HostHandle> {
  const out = o.output ?? ((s: string) => void process.stdout.write(s));
  const log = new Logger("plr-host", (line) => out(line + "\n"));
  let boot: MeasuredBoot;
  try {
    boot = await measureBoot(o);
  } catch (e) {
    log.info("launch_refused", { code: code(e instanceof HostError ? e.code : "E_MEASUREMENT") });
    throw e;
  }
  checkAborted(o.signal);
  log.info("measured", {
    compose_hash: hex(boot.composeHash),
    os_measurement: hex(boot.osMeasurement),
    bundle_sha256: hex(boot.compose.router.bundle_sha256),
    debug: boot.debug,
  });

  const priv = await mkdtemp(join(resolve(o.runDir), "tdx-"));
  await chmod(priv, 0o700);
  const socketPath = join(priv, "q.sock");
  const bundleCopy = join(priv, boot.compose.router.entry);
  const composeCopy = join(priv, "app-compose.json");
  // Run exactly the measured bytes (no TOCTOU between hashing and loading).
  await writeFile(bundleCopy, boot.bundleBytes, { mode: 0o400, flag: "wx" });
  await writeFile(composeCopy, boot.composeBytes, { mode: 0o400, flag: "wx" });

  let quote: { close(): Promise<void> } | null = null;
  let llm: ChildProcess | null = null;
  let router: ChildProcess | null = null;
  const cleanup = async () => {
    await Promise.all([terminate(router), terminate(llm)]);
    await quote?.close();
    await rm(priv, { recursive: true, force: true });
  };

  try {
    // Run exactly the measured runtimes: private copies, re-hashed after copying (no TOCTOU via the originals).
    const nodeRt = await installRuntime(boot.nodeRuntime, await mkdtemp(join(priv, "node-")), boot.compose.router.node_sha256);
    const llamaRt =
      boot.compose.llm.kind === "mock" ? null : await installRuntime(boot.llmRuntime, await mkdtemp(join(priv, "llm-")), boot.compose.llm.runtime_sha256);
    log.info("runtimes_verified", { node_sha256: hex(boot.compose.router.node_sha256), llm_runtime_sha256: hex(boot.compose.llm.runtime_sha256) });
    quote = await startQuoteServer(socketPath, boot.attester);
    checkAborted(o.signal);
    const llmPort = o.llmPort && o.llmPort > 0 ? o.llmPort : await freePort();
    // Per-boot LLM API key: only the router can use the LLM, so no other local process can query it (or probe
    // its KV cache). Passed through the environment, never argv (argv is visible to every local user).
    const llmApiKey = randomBytes(32).toString("hex");
    if (llamaRt === null) {
      const llmCopy = join(priv, "mock-llm.mjs");
      await writeFile(llmCopy, boot.llmBytes!, { mode: 0o400, flag: "wx" });
      llm = spawn(nodeRt.exe, [llmCopy, "--port", String(llmPort)], {
        stdio: "ignore",
        env: { ...nodeRt.env, PLR_LLM_API_KEY: llmApiKey },
        cwd: priv,
      });
    } else {
      // llama-server output is discarded: it must not get a chance to log prompts.
      llm = spawn(llamaRt.exe, llamaServerArgs(boot.llmFile, llmPort), {
        stdio: "ignore",
        env: { PATH: "/usr/bin:/bin", ...llamaRt.env, LLAMA_API_KEY: llmApiKey },
        cwd: priv,
      });
    }
    llm.on("error", () => undefined);
    await waitHealthy(llmPort, llm, o.llmReadyTimeoutMs ?? 180_000, o.signal);
    checkAborted(o.signal);
    log.info("llm_ready", { port: llmPort });

    const env: Record<string, string> = {
      ...nodeRt.env,
      PLR_TDX_SOCKET: socketPath,
      PLR_APP_COMPOSE_PATH: composeCopy,
      PLR_ROUTER_PORT: String(o.routerPort ?? 18100),
      PLR_LLM_PORT: String(llmPort),
      PLR_LLM_API_KEY: llmApiKey,
      PLR_RUN_DIR: resolve(o.stateDir ?? o.runDir),
    };
    for (const k of ROUTER_ENV_ALLOWLIST) {
      const v = o.routerEnv?.[k];
      if (typeof v === "string" && v !== "") env[k] = v;
    }
    router = spawn(nodeRt.exe, [...routerNodeFlags(boot.compose, priv), bundleCopy], { stdio: ["ignore", "pipe", "pipe"], env, cwd: priv });
    router.on("error", () => undefined);
    router.stdout!.setEncoding("utf8").on("data", (s: string) => out(s));
    router.stderr!.setEncoding("utf8").on("data", (s: string) => out(s));
    log.info("router_started", { pid: router.pid ?? 0 });

    const r = router;
    const l = llm;
    let stopping: Promise<number> | null = null;
    const stop = (exitCode = 0): Promise<number> => {
      stopping ??= cleanup().then(() => {
        log.info("stopped", { code_num: exitCode });
        return exitCode;
      });
      return stopping;
    };
    const done = Promise.race([
      exited(r).then(() => (r.exitCode ?? 1) === 0 ? 0 : 1),
      exited(l).then(() => 1),
    ]).then((c) => stop(c));
    return { boot, socketPath, llmPort, router: r, llm: l, done, stop: () => stop(0) };
  } catch (e) {
    log.info("launch_failed", { code: code(e instanceof HostError ? e.code : "E_LAUNCH") });
    await cleanup();
    throw e;
  }
}
