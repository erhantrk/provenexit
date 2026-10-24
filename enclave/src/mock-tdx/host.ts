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
 *
 * VPN exits (SPEC-VPN §2): a `plr-vpn` compose is launched by `measureVpnBoot` / `launchVpn` — no LLM; the node
 * runtime and the exit bundle are measured, and the exit runs under the same isolation flags as the router
 * (network allowed: it is an exit). `composeServiceOf` tells the services apart for a CLI.
 *
 * Combo (SPEC-COMBO §2): a `plr-combo` compose is launched by `measureComboBoot` / `launchCombo` — everything of both
 * services is measured, RTMR3 is extended once (one boot event log, one quote socket), then three isolated processes
 * run in the TD: the LLM, the router and the VPN exit, each with its own private directory and environment allowlist
 * (the exit never learns the LLM port or key).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants as FS, createReadStream, readFileSync, statSync } from "node:fs";
import { chmod, copyFile, mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MockRoot, MockTdxAttester, fromHex, isHex, toHex, type TdxEvent } from "@plr/shared";
import {
  MAX_COMPOSE_BYTES, composeService, parseComboCompose, parseCompose, parseVpnCompose, type AppCompose, type ComboCompose, type ComposeService,
  type VpnCompose,
} from "../compose.js";
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

/** Reads a bundle file (`<dir of compose>/<entry>` unless given) and checks it against its pinned sha256. */
function measureBundle(composePath: string, explicitPath: string | undefined, entry: string, sha: string): { bundlePath: string; bundleBytes: Uint8Array } {
  const bundlePath = resolve(explicitPath ?? join(dirname(composePath), entry));
  if (basename(bundlePath) !== entry) throw new HostError("E_BUNDLE_ENTRY");
  const bundleBytes = readBounded(bundlePath, MAX_BUNDLE_BYTES, "E_BUNDLE");
  if (!digestEq(sha256Hex(bundleBytes), sha)) throw new HostError("E_MEASUREMENT_MISMATCH");
  return { bundlePath, bundleBytes };
}

interface RouterPartMeasurement {
  bundlePath: string;
  bundleBytes: Uint8Array;
  llmFile: string;
  llmBytes: Uint8Array | null;
  nodeRuntime: RuntimeClosure;
  llmRuntime: RuntimeClosure;
}

/** Measures what a router compose (or the router part of a combo) pins: bundle, model / mock LLM, node, LLM runtime. */
async function measureRouterPart(
  spec: Pick<MeasureSpec, "composePath" | "bundlePath" | "llmFile" | "llamaServer" | "nodePath" | "runtimeCache">,
  router: AppCompose["router"],
  llm: AppCompose["llm"],
): Promise<RouterPartMeasurement> {
  const { bundlePath, bundleBytes } = measureBundle(spec.composePath, spec.bundlePath, router.entry, router.bundle_sha256);
  const kind = llm.kind;
  const llmFile = resolve(spec.llmFile ?? (kind === "mock" ? DEFAULT_MOCK_LLM : DEFAULT_MODEL));
  let llmBytes: Uint8Array | null = null;
  let llmHash: string;
  if (kind === "mock") {
    llmBytes = readBounded(llmFile, 1024 * 1024, "E_LLM_FILE");
    llmHash = sha256Hex(llmBytes);
  } else {
    llmHash = await sha256File(llmFile);
  }
  if (!digestEq(llmHash, llm.model_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");

  // Runtimes that will see plaintext: node (router, mock LLM) and llama-server.
  const cache = spec.runtimeCache ? { cache: spec.runtimeCache } : {};
  const nodeRuntime = await measureRuntime(spec.nodePath ?? process.execPath, cache);
  if (!digestEq(nodeRuntime.digest, router.node_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");
  const llmRuntime = kind === "mock" ? nodeRuntime : await measureRuntime(spec.llamaServer ?? DEFAULT_LLAMA_SERVER, cache);
  if (!digestEq(llmRuntime.digest, llm.runtime_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");
  return { bundlePath, bundleBytes, llmFile, llmBytes, nodeRuntime, llmRuntime };
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
  const m = await measureRouterPart(spec, compose.router, compose.llm);
  const debug = spec.debug === true;
  const attester = new MockTdxAttester({ root: spec.root, composeBytes, debug });
  return {
    compose,
    composeBytes,
    composeHash: toHex(attester.composeHash),
    ...m,
    attester,
    eventLog: attester.eventLog,
    osMeasurement: toHex(attester.osMeasurement),
    debug,
  };
}

/** Which service a compose file describes (`router` | `vpn`); a dispatch hint only (measurement re-parses strictly). */
export function composeServiceOf(composePath: string): ComposeService {
  const bytes = readBounded(composePath, MAX_COMPOSE_BYTES, "E_COMPOSE");
  try {
    return composeService(bytes);
  } catch {
    throw new HostError("E_COMPOSE");
  }
}

export interface VpnMeasureSpec {
  /** Path of the VPN app-compose.json to launch. */
  composePath: string;
  /** Exit bundle; default `<dir of compose>/vpn.bundle.mjs`. */
  bundlePath?: string;
  /** Launch the TD with the DEBUG attribute. */
  debug?: boolean;
  /** Node executable for the exit (default: this process's); must match `vpn.node_sha256`. */
  nodePath?: string;
  /** Hash cache for repeated measurements (harnesses). `launchVpn` never uses it. */
  runtimeCache?: RuntimeHashCache;
}

export interface MeasuredVpnBoot {
  service: "vpn";
  compose: VpnCompose;
  composeBytes: Uint8Array;
  composeHash: string;
  bundlePath: string;
  /** The exact bundle bytes that were measured (the host runs these, not the file on disk). */
  bundleBytes: Uint8Array;
  nodeRuntime: RuntimeClosure;
  attester: MockTdxAttester;
  eventLog: TdxEvent[];
  osMeasurement: string;
  debug: boolean;
}

/**
 * Measures a VPN exit launch (SPEC-VPN §2): strict canonical VPN compose, exit bundle hash, node runtime closure
 * (→ HostError E_COMPOSE / E_BUNDLE_ENTRY / E_MEASUREMENT_MISMATCH), then the per-boot attester and §3 event log.
 */
export async function measureVpnBoot(spec: VpnMeasureSpec & { root: MockRoot }): Promise<MeasuredVpnBoot> {
  const composeBytes = readBounded(spec.composePath, MAX_COMPOSE_BYTES, "E_COMPOSE");
  let compose: VpnCompose;
  try {
    compose = parseVpnCompose(composeBytes);
  } catch {
    throw new HostError("E_COMPOSE");
  }
  const { bundlePath, bundleBytes } = measureBundle(spec.composePath, spec.bundlePath, compose.vpn.entry, compose.vpn.bundle_sha256);
  const nodeRuntime = await measureRuntime(spec.nodePath ?? process.execPath, spec.runtimeCache ? { cache: spec.runtimeCache } : {});
  if (!digestEq(nodeRuntime.digest, compose.vpn.node_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");
  const debug = spec.debug === true;
  const attester = new MockTdxAttester({ root: spec.root, composeBytes, debug });
  return {
    service: "vpn",
    compose,
    composeBytes,
    composeHash: toHex(attester.composeHash),
    bundlePath,
    bundleBytes,
    nodeRuntime,
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
  // SPEC-CHAINS §4/§5: registry chain selection and the Zcash registry
  "PLR_CHAIN",
  "PLR_ZCASH_RPC",
  "PLR_ZCASH_NETWORK",
  "PLR_ZCASH_OWNER",
  "PLR_ZCASH_KEY",
  "PLR_ZCASH_START_HEIGHT",
] as const;

/**
 * Exit env keys the host forwards (SPEC-VPN: registration + anchoring on the VPN registry, listen host/port).
 * Never NODE_OPTIONS or anything that could inject code.
 */
export const EXIT_ENV_ALLOWLIST = [
  "PLR_NEAR_RPC",
  "PLR_REGISTRY",
  "PLR_VPN_REGISTRY",
  "PLR_OPERATOR_ID",
  "PLR_OPERATOR_KEY",
  "PLR_REGISTER_DEPOSIT",
  "PLR_ANCHOR_DEPOSIT",
  "PLR_ANCHOR_INTERVAL_MS",
  "PLR_VPN_HOST",
  "PLR_VPN_PORT",
  // SPEC-CHAINS §4/§5: registry chain selection and the Zcash VPN registry (PLR_ZCASH_VPN_OWNER, else PLR_ZCASH_OWNER)
  "PLR_CHAIN",
  "PLR_ZCASH_RPC",
  "PLR_ZCASH_NETWORK",
  "PLR_ZCASH_OWNER",
  "PLR_ZCASH_VPN_OWNER",
  "PLR_ZCASH_KEY",
  "PLR_ZCASH_START_HEIGHT",
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
export function routerNodeFlags(compose: { policy: { disk: "none" } }, privDir: string): string[] {
  const flags = ["--disallow-code-generation-from-strings", "--no-addons"];
  if (compose.policy.disk === "none") flags.unshift("--permission", `--allow-fs-read=${privDir}`);
  return flags;
}

/** The VPN exit runs under exactly the router's isolation (SPEC-VPN §2); Node's permission model leaves network alone. */
export const exitNodeFlags = routerNodeFlags;

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
 * Copies the GGUF model into `dir` (APFS clone when possible: copy-on-write, so later writes to the source never
 * reach the copy; otherwise a real copy), makes it 0400, re-hashes the **copy** and refuses unless it is exactly
 * `expectedSha256` (HostError E_MEASUREMENT_MISMATCH; E_LLM_FILE if it cannot be copied). llama-server is only ever
 * given this path, so swapping the operator-writable original after measurement changes nothing (no TOCTOU).
 */
export async function installModel(src: string, dir: string, expectedSha256: string): Promise<string> {
  const dst = join(dir, "model.gguf");
  try {
    await copyFile(src, dst, FS.COPYFILE_EXCL | FS.COPYFILE_FICLONE);
    await chmod(dst, 0o400);
  } catch {
    throw new HostError("E_LLM_FILE");
  }
  if (!digestEq(await sha256File(dst), expectedSha256)) throw new HostError("E_MEASUREMENT_MISMATCH");
  return dst;
}

/** A verified private runtime copy (see `installRuntime`). */
type InstalledRuntime = Awaited<ReturnType<typeof installRuntime>>;

/**
 * Starts the measured LLM on 127.0.0.1:`port` with the per-boot API key in its environment (never argv): the mock
 * LLM (its measured bytes copied into `dir`) on the verified node, or llama-server (verified copy) on the verified
 * model copy (`installModel`) with prompt caching off. Output is discarded: the LLM must not get a chance to log prompts.
 */
async function startLlm(p: {
  boot: Pick<MeasuredBoot, "llmBytes">;
  dir: string;
  nodeRt: InstalledRuntime;
  llamaRt: InstalledRuntime | null;
  /** The verified private model copy (llama.cpp only). */
  model: string | null;
  port: number;
  apiKey: string;
}): Promise<ChildProcess> {
  let llm: ChildProcess;
  if (p.llamaRt === null) {
    const llmCopy = join(p.dir, "mock-llm.mjs");
    if (!p.boot.llmBytes) throw new HostError("E_LLM_FILE");
    await writeFile(llmCopy, p.boot.llmBytes, { mode: 0o400, flag: "wx" });
    llm = spawn(p.nodeRt.exe, [llmCopy, "--port", String(p.port)], {
      stdio: "ignore",
      env: { ...p.nodeRt.env, PLR_LLM_API_KEY: p.apiKey },
      cwd: p.dir,
    });
  } else {
    if (p.model === null) throw new HostError("E_LLM_FILE");
    llm = spawn(p.llamaRt.exe, llamaServerArgs(p.model, p.port), {
      stdio: "ignore",
      env: { PATH: "/usr/bin:/bin", ...p.llamaRt.env, LLAMA_API_KEY: p.apiKey },
      cwd: p.dir,
    });
  }
  llm.on("error", () => undefined);
  return llm;
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
    // ... and exactly the measured model: a private copy, re-hashed (the mock LLM already runs its measured bytes).
    const model = llamaRt === null ? null : await installModel(boot.llmFile, priv, boot.compose.llm.model_sha256);
    log.info("runtimes_verified", { node_sha256: hex(boot.compose.router.node_sha256), llm_runtime_sha256: hex(boot.compose.llm.runtime_sha256) });
    quote = await startQuoteServer(socketPath, boot.attester);
    checkAborted(o.signal);
    const llmPort = o.llmPort && o.llmPort > 0 ? o.llmPort : await freePort();
    // Per-boot LLM API key: only the router can use the LLM, so no other local process can query it (or probe
    // its KV cache). Passed through the environment, never argv (argv is visible to every local user).
    const llmApiKey = randomBytes(32).toString("hex");
    llm = await startLlm({ boot, dir: priv, nodeRt, llamaRt, model, port: llmPort, apiKey: llmApiKey });
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

// ------------------------------------------------------------------------------------------- VPN exit launch

export interface VpnLaunchOptions extends VpnMeasureSpec {
  root: MockRoot;
  /** Host state directory (a private 0700 `tdx-*` subdirectory is created inside it). */
  runDir: string;
  /** Exit listen port (0 = ephemeral; the exit prints its URL). Default: PLR_VPN_PORT from `exitEnv`, else 18200. */
  exitPort?: number;
  /** Extra exit configuration (NEAR, anchor interval, listen host/port). Only allowlisted keys are passed. */
  exitEnv?: Readonly<Record<string, string | undefined>>;
  /** Receives host + exit output lines. Default: process stdout. */
  output?: (chunk: string) => void;
  /** Aborts a launch in progress; rejects with HostError E_ABORTED after tearing down what was started. */
  signal?: AbortSignal;
}

export interface VpnHostHandle {
  boot: MeasuredVpnBoot;
  socketPath: string;
  exit: ChildProcess;
  /** Resolves with the exit code once the host has shut everything down. */
  done: Promise<number>;
  stop(): Promise<number>;
}

/**
 * Measures and launches a VPN exit: no LLM; the measured exit bundle runs on the verified node copy with the
 * router's isolation flags and `PLR_TDX_SOCKET`. If the exit process exits, the host stops (fail closed).
 */
export async function launchVpn(o: VpnLaunchOptions): Promise<VpnHostHandle> {
  const out = o.output ?? ((s: string) => void process.stdout.write(s));
  const log = new Logger("plr-host", (line) => out(line + "\n"));
  let boot: MeasuredVpnBoot;
  try {
    boot = await measureVpnBoot(o);
  } catch (e) {
    log.info("launch_refused", { code: code(e instanceof HostError ? e.code : "E_MEASUREMENT") });
    throw e;
  }
  checkAborted(o.signal);
  log.info("measured", {
    compose_hash: hex(boot.composeHash),
    os_measurement: hex(boot.osMeasurement),
    bundle_sha256: hex(boot.compose.vpn.bundle_sha256),
    debug: boot.debug,
  });

  const priv = await mkdtemp(join(resolve(o.runDir), "tdx-"));
  await chmod(priv, 0o700);
  const socketPath = join(priv, "q.sock");
  const bundleCopy = join(priv, boot.compose.vpn.entry);
  const composeCopy = join(priv, "app-compose.json");
  // Run exactly the measured bytes (no TOCTOU between hashing and loading).
  await writeFile(bundleCopy, boot.bundleBytes, { mode: 0o400, flag: "wx" });
  await writeFile(composeCopy, boot.composeBytes, { mode: 0o400, flag: "wx" });

  let quote: { close(): Promise<void> } | null = null;
  let exit: ChildProcess | null = null;
  const cleanup = async () => {
    await terminate(exit);
    await quote?.close();
    await rm(priv, { recursive: true, force: true });
  };

  try {
    const nodeRt = await installRuntime(boot.nodeRuntime, await mkdtemp(join(priv, "node-")), boot.compose.vpn.node_sha256);
    log.info("runtimes_verified", { node_sha256: hex(boot.compose.vpn.node_sha256) });
    quote = await startQuoteServer(socketPath, boot.attester);
    checkAborted(o.signal);

    const env: Record<string, string> = {};
    for (const k of EXIT_ENV_ALLOWLIST) {
      const v = o.exitEnv?.[k];
      if (typeof v === "string" && v !== "") env[k] = v;
    }
    Object.assign(env, nodeRt.env, { PLR_TDX_SOCKET: socketPath, PLR_APP_COMPOSE_PATH: composeCopy });
    if (o.exitPort !== undefined) env.PLR_VPN_PORT = String(o.exitPort);
    exit = spawn(nodeRt.exe, [...exitNodeFlags(boot.compose, priv), bundleCopy], { stdio: ["ignore", "pipe", "pipe"], env, cwd: priv });
    exit.on("error", () => undefined);
    exit.stdout!.setEncoding("utf8").on("data", (s: string) => out(s));
    exit.stderr!.setEncoding("utf8").on("data", (s: string) => out(s));
    log.info("exit_started", { pid: exit.pid ?? 0 });

    const x = exit;
    let stopping: Promise<number> | null = null;
    const stop = (exitCode = 0): Promise<number> => {
      stopping ??= cleanup().then(() => {
        log.info("stopped", { code_num: exitCode });
        return exitCode;
      });
      return stopping;
    };
    const done = exited(x)
      .then(() => ((x.exitCode ?? 1) === 0 ? 0 : 1))
      .then((c) => stop(c));
    return { boot, socketPath, exit: x, done, stop: () => stop(0) };
  } catch (e) {
    log.info("launch_failed", { code: code(e instanceof HostError ? e.code : "E_LAUNCH") });
    await cleanup();
    throw e;
  }
}

// ------------------------------------------------------------------------------------------- combo (SPEC-COMBO §2)

export interface ComboMeasureSpec {
  /** Path of the `plr-combo` app-compose.json to launch. */
  composePath: string;
  /** Router bundle; default `<dir of compose>/<router.entry>`. */
  routerBundlePath?: string;
  /** VPN exit bundle; default `<dir of compose>/vpn.bundle.mjs`. */
  vpnBundlePath?: string;
  /** The model (llama.cpp) or mock-LLM server file; defaults per kind. */
  llmFile?: string;
  /** Launch the TD with the DEBUG attribute. */
  debug?: boolean;
  /** llama-server executable (kind `llama.cpp`); its runtime closure must match `router.llm.runtime_sha256`. */
  llamaServer?: string;
  /** Node executable for all three processes (default: this process's); must match the compose's node_sha256. */
  nodePath?: string;
  /** Hash cache for repeated measurements (harnesses). `launchCombo` never uses it. */
  runtimeCache?: RuntimeHashCache;
}

export interface MeasuredComboBoot {
  service: "combo";
  compose: ComboCompose;
  composeBytes: Uint8Array;
  composeHash: string;
  routerBundlePath: string;
  /** The exact router bundle bytes that were measured (the host runs these, not the file on disk). */
  routerBundleBytes: Uint8Array;
  vpnBundlePath: string;
  /** The exact exit bundle bytes that were measured. */
  vpnBundleBytes: Uint8Array;
  llmFile: string;
  /** Measured mock-LLM bytes (kind "mock" only). */
  llmBytes: Uint8Array | null;
  /** Measured node runtime (router, exit, and the mock LLM). */
  nodeRuntime: RuntimeClosure;
  /** Measured LLM runtime: llama-server for `llama.cpp`, the node runtime for `mock`. */
  llmRuntime: RuntimeClosure;
  attester: MockTdxAttester;
  eventLog: TdxEvent[];
  osMeasurement: string;
  debug: boolean;
}

/**
 * Measures a combo launch (SPEC-COMBO §2): strict canonical combo compose, then everything it pins — router bundle,
 * model / mock LLM, node and LLM runtimes (router rules) and the exit bundle (VPN rules; same node) — refusing on any
 * mismatch (HostError E_COMPOSE / E_BUNDLE_ENTRY / E_MEASUREMENT_MISMATCH). One attester, one §3 boot event log for the
 * whole TD: both services attest the same compose.
 */
export async function measureComboBoot(spec: ComboMeasureSpec & { root: MockRoot }): Promise<MeasuredComboBoot> {
  const composeBytes = readBounded(spec.composePath, MAX_COMPOSE_BYTES, "E_COMPOSE");
  let compose: ComboCompose;
  try {
    compose = parseComboCompose(composeBytes);
  } catch {
    throw new HostError("E_COMPOSE");
  }
  const r = compose.router;
  const rm = await measureRouterPart(
    {
      composePath: spec.composePath,
      ...(spec.routerBundlePath !== undefined ? { bundlePath: spec.routerBundlePath } : {}),
      ...(spec.llmFile !== undefined ? { llmFile: spec.llmFile } : {}),
      ...(spec.llamaServer !== undefined ? { llamaServer: spec.llamaServer } : {}),
      ...(spec.nodePath !== undefined ? { nodePath: spec.nodePath } : {}),
      ...(spec.runtimeCache !== undefined ? { runtimeCache: spec.runtimeCache } : {}),
    },
    { bundle_sha256: r.bundle_sha256, entry: r.entry, node_sha256: r.node_sha256 },
    r.llm,
  );
  const v = measureBundle(spec.composePath, spec.vpnBundlePath, compose.vpn.entry, compose.vpn.bundle_sha256);
  // One runtime runs both services (the compose parser already requires equal pins); checked again where it is used.
  if (!digestEq(rm.nodeRuntime.digest, compose.vpn.node_sha256)) throw new HostError("E_MEASUREMENT_MISMATCH");
  const debug = spec.debug === true;
  const attester = new MockTdxAttester({ root: spec.root, composeBytes, debug });
  return {
    service: "combo",
    compose,
    composeBytes,
    composeHash: toHex(attester.composeHash),
    routerBundlePath: rm.bundlePath,
    routerBundleBytes: rm.bundleBytes,
    vpnBundlePath: v.bundlePath,
    vpnBundleBytes: v.bundleBytes,
    llmFile: rm.llmFile,
    llmBytes: rm.llmBytes,
    nodeRuntime: rm.nodeRuntime,
    llmRuntime: rm.llmRuntime,
    attester,
    eventLog: attester.eventLog,
    osMeasurement: toHex(attester.osMeasurement),
    debug,
  };
}

/** Router env keys the host forwards in a combo: the LLM registry only (the exit's registry is not its business). */
export const COMBO_ROUTER_ENV_ALLOWLIST = ROUTER_ENV_ALLOWLIST;

/**
 * Exit env keys the host forwards in a combo: the VPN registry settings and listen host/port. Unlike a lone exit,
 * there is no PLR_REGISTRY (or PLR_ZCASH_OWNER) fallback — that is the LLM registry here, and the exit must never
 * register on it (it uses PLR_VPN_REGISTRY / PLR_ZCASH_VPN_OWNER).
 */
export const COMBO_EXIT_ENV_ALLOWLIST = EXIT_ENV_ALLOWLIST.filter((k) => k !== "PLR_REGISTRY" && k !== "PLR_ZCASH_OWNER");

/** What the host gives each process of a combo TD. */
export interface ComboEnvInputs {
  /** The host's own environment (or a harness's): only allowlisted keys are read. */
  hostEnv?: Readonly<Record<string, string | undefined>> | undefined;
  /** The verified node copy's environment (`DYLD_LIBRARY_PATH`). */
  nodeEnv: Readonly<Record<string, string>>;
  socketPath: string;
  routerComposePath: string;
  vpnComposePath: string;
  routerPort: number;
  /** Exit listen port; undefined → PLR_VPN_PORT from `hostEnv`, else the exit's default 18200. */
  exitPort?: number | undefined;
  llmPort: number;
  llmApiKey: string;
  /** PLR_RUN_DIR of the router. */
  runDir: string;
}

/**
 * The environments of the router and the exit of a combo TD (SPEC-COMBO §2), built from separate allowlists: the
 * router gets the LLM port + per-boot LLM API key and the LLM registry settings; the exit gets the VPN registry
 * settings and **no** LLM port or key (nor anything else of the router). Host-provided keys (socket, compose, ports)
 * always win over forwarded ones.
 */
export function comboProcessEnvs(i: ComboEnvInputs): { router: Record<string, string>; exit: Record<string, string> } {
  const pick = (keys: readonly string[]): Record<string, string> => {
    const e: Record<string, string> = {};
    for (const k of keys) {
      const v = i.hostEnv?.[k];
      if (typeof v === "string" && v !== "") e[k] = v;
    }
    return e;
  };
  const router: Record<string, string> = {
    ...pick(COMBO_ROUTER_ENV_ALLOWLIST),
    ...i.nodeEnv,
    PLR_TDX_SOCKET: i.socketPath,
    PLR_APP_COMPOSE_PATH: i.routerComposePath,
    PLR_ROUTER_PORT: String(i.routerPort),
    PLR_LLM_PORT: String(i.llmPort),
    PLR_LLM_API_KEY: i.llmApiKey,
    PLR_RUN_DIR: i.runDir,
  };
  const exit: Record<string, string> = {
    ...pick(COMBO_EXIT_ENV_ALLOWLIST),
    ...i.nodeEnv,
    PLR_TDX_SOCKET: i.socketPath,
    PLR_APP_COMPOSE_PATH: i.vpnComposePath,
  };
  if (i.exitPort !== undefined) exit.PLR_VPN_PORT = String(i.exitPort);
  return { router, exit };
}

export interface ComboLaunchOptions extends ComboMeasureSpec {
  root: MockRoot;
  /** Host state directory (a private 0700 `tdx-*` subdirectory is created inside it). */
  runDir: string;
  /** The run directory announced to the router as `PLR_RUN_DIR` (default: `runDir`). */
  stateDir?: string;
  /** Router listen port (0 = ephemeral). Default 18100. */
  routerPort?: number;
  /** Exit listen port (0 = ephemeral). Default: PLR_VPN_PORT from `env`, else 18200. */
  exitPort?: number;
  /** LLM port on 127.0.0.1 (0 = pick a free one). Default 0. */
  llmPort?: number;
  /** Configuration source for both services; each gets only its own allowlisted keys ({@link comboProcessEnvs}). */
  env?: Readonly<Record<string, string | undefined>>;
  /** Receives host + router + exit output lines. Default: process stdout. */
  output?: (chunk: string) => void;
  /** Max wait for the LLM to become healthy. */
  llmReadyTimeoutMs?: number;
  /** Aborts a launch in progress; rejects with HostError E_ABORTED after tearing down what was started. */
  signal?: AbortSignal;
}

export interface ComboHostHandle {
  boot: MeasuredComboBoot;
  socketPath: string;
  llmPort: number;
  llm: ChildProcess;
  router: ChildProcess;
  exit: ChildProcess;
  /** Resolves with the exit code once the host has shut everything down. */
  done: Promise<number>;
  stop(): Promise<number>;
}

/** A private 0700 directory holding exactly one process's measured files (0400). */
async function processDir(parent: string, name: string, files: Readonly<Record<string, Uint8Array>>): Promise<string> {
  const d = join(parent, name);
  await mkdir(d, { mode: 0o700 });
  for (const [f, bytes] of Object.entries(files)) await writeFile(join(d, f), bytes, { mode: 0o400, flag: "wx" });
  return d;
}

/**
 * Measures and launches a combo TD (SPEC-COMBO §2): one measurement, one boot event log and one quote socket, then
 * three separate processes — the LLM (waited on until healthy), the router and the VPN exit. Router and exit each
 * run their measured bundle from their own private directory (the only path their permission model may read) under
 * the usual isolation flags, with their own environment ({@link comboProcessEnvs}); each generates its own keys,
 * registers on its own registry and anchors its own receipts. If any of the three exits, the host stops the others
 * (fail closed: no half-running TD).
 */
export async function launchCombo(o: ComboLaunchOptions): Promise<ComboHostHandle> {
  const out = o.output ?? ((s: string) => void process.stdout.write(s));
  const log = new Logger("plr-host", (line) => out(line + "\n"));
  let boot: MeasuredComboBoot;
  try {
    boot = await measureComboBoot(o);
  } catch (e) {
    log.info("launch_refused", { code: code(e instanceof HostError ? e.code : "E_MEASUREMENT") });
    throw e;
  }
  checkAborted(o.signal);
  const c = boot.compose;
  log.info("measured", {
    compose_hash: hex(boot.composeHash),
    os_measurement: hex(boot.osMeasurement),
    router_bundle_sha256: hex(c.router.bundle_sha256),
    vpn_bundle_sha256: hex(c.vpn.bundle_sha256),
    debug: boot.debug,
  });

  const priv = await mkdtemp(join(resolve(o.runDir), "tdx-"));
  await chmod(priv, 0o700);
  const socketPath = join(priv, "q.sock");

  let quote: { close(): Promise<void> } | null = null;
  let llm: ChildProcess | null = null;
  let router: ChildProcess | null = null;
  let exit: ChildProcess | null = null;
  const cleanup = async () => {
    await Promise.all([terminate(router), terminate(exit), terminate(llm)]);
    await quote?.close();
    await rm(priv, { recursive: true, force: true });
  };

  try {
    // Run exactly the measured bytes, each service from its own directory (no TOCTOU between hashing and loading).
    const routerDir = await processDir(priv, "router", { [c.router.entry]: boot.routerBundleBytes, "app-compose.json": boot.composeBytes });
    const exitDir = await processDir(priv, "vpn", { [c.vpn.entry]: boot.vpnBundleBytes, "app-compose.json": boot.composeBytes });
    const llmDir = await processDir(priv, "llm", {});
    // Run exactly the measured runtimes: private copies, re-hashed after copying (no TOCTOU via the originals).
    const nodeRt = await installRuntime(boot.nodeRuntime, await mkdtemp(join(priv, "node-")), c.router.node_sha256);
    const llamaRt = c.router.llm.kind === "mock" ? null : await installRuntime(boot.llmRuntime, await mkdtemp(join(priv, "llm-rt-")), c.router.llm.runtime_sha256);
    // ... and exactly the measured model: a private copy in the LLM's directory, re-hashed.
    const model = llamaRt === null ? null : await installModel(boot.llmFile, llmDir, c.router.llm.model_sha256);
    log.info("runtimes_verified", { node_sha256: hex(c.router.node_sha256), llm_runtime_sha256: hex(c.router.llm.runtime_sha256) });
    quote = await startQuoteServer(socketPath, boot.attester);
    checkAborted(o.signal);

    const llmPort = o.llmPort && o.llmPort > 0 ? o.llmPort : await freePort();
    // Per-boot LLM API key: handed to the router only (SPEC-COMBO §3: the exit never learns it).
    const llmApiKey = randomBytes(32).toString("hex");
    llm = await startLlm({ boot, dir: llmDir, nodeRt, llamaRt, model, port: llmPort, apiKey: llmApiKey });
    await waitHealthy(llmPort, llm, o.llmReadyTimeoutMs ?? 180_000, o.signal);
    checkAborted(o.signal);
    log.info("llm_ready", { port: llmPort });

    const envs = comboProcessEnvs({
      hostEnv: o.env,
      nodeEnv: nodeRt.env,
      socketPath,
      routerComposePath: join(routerDir, "app-compose.json"),
      vpnComposePath: join(exitDir, "app-compose.json"),
      routerPort: o.routerPort ?? 18100,
      exitPort: o.exitPort,
      llmPort,
      llmApiKey,
      runDir: resolve(o.stateDir ?? o.runDir),
    });
    const service = (dir: string, entry: string, env: Record<string, string>, policy: { policy: { disk: "none" } }): ChildProcess => {
      const p = spawn(nodeRt.exe, [...routerNodeFlags(policy, dir), join(dir, entry)], { stdio: ["ignore", "pipe", "pipe"], env, cwd: dir });
      p.on("error", () => undefined);
      p.stdout!.setEncoding("utf8").on("data", (s: string) => out(s));
      p.stderr!.setEncoding("utf8").on("data", (s: string) => out(s));
      return p;
    };
    router = service(routerDir, c.router.entry, envs.router, c.router);
    log.info("router_started", { pid: router.pid ?? 0 });
    exit = service(exitDir, c.vpn.entry, envs.exit, c.vpn);
    log.info("exit_started", { pid: exit.pid ?? 0 });

    const r = router;
    const x = exit;
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
      exited(r).then(() => ((r.exitCode ?? 1) === 0 ? 0 : 1)),
      exited(x).then(() => ((x.exitCode ?? 1) === 0 ? 0 : 1)),
      exited(l).then(() => 1),
    ]).then((code) => stop(code));
    return { boot, socketPath, llmPort, llm: l, router: r, exit: x, done, stop: () => stop(0) };
  } catch (e) {
    log.info("launch_failed", { code: code(e instanceof HostError ? e.code : "E_LAUNCH") });
    await cleanup();
    throw e;
  }
}
