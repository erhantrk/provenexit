/**
 * The mock TDX host (SPEC §4, §6.1; SPEC-VPN §2): the local stand-in for the dstack guest OS and the TDX module.
 *
 * It is the only component that measures. It reads a `plr-vpn` `app-compose.json`, hashes the exit bundle and the
 * runtime closure of node (`runtime.ts`), refuses to launch on any mismatch, extends RTMR3 with the boot sequence
 * (fresh random instance-id), holds the MOCK ROOT (secret read from a 0600 file) and a per-boot attestation key,
 * and serves `POST /GetQuote` on a 0600 Unix socket. It then launches the exit bundle as a child process, running
 * exactly the bytes it measured, under Node's permission model (network allowed: it is an exit).
 *
 * The exit never sees the ROOT or AK private keys: it can only ask for quotes through the socket.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { chmod, mkdtemp, writeFile, rm } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { basename, dirname, join, resolve } from "node:path";
import { MockRoot, MockTdxAttester, fromHex, isHex, toHex, type TdxEvent } from "@plr/shared";
import { MAX_COMPOSE_BYTES, parseVpnCompose, type VpnCompose } from "../compose.js";
import { Logger, code, hex } from "../log.js";

import { HostError } from "./errors.js";
import { installRuntime, measureRuntime, type RuntimeClosure, type RuntimeHashCache } from "./runtime.js";

export { HostError };

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

function sha256Hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
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
  // registry chain selection: only `near` (the default) exists
  "PLR_CHAIN",
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
 * Node flags enforcing the compose policy on the exit process. `policy.disk == "none"` → Node's permission model:
 * the file system is read-only and limited to the private launch directory (measured bundle + compose), no child
 * processes, no worker threads, no native addons. `--disallow-code-generation-from-strings` forbids eval/new
 * Function. Node's permission model leaves the network alone (SPEC-VPN §2: it is an exit).
 */
export function exitNodeFlags(compose: { policy: { disk: "none" } }, privDir: string): string[] {
  const flags = ["--disallow-code-generation-from-strings", "--no-addons"];
  if (compose.policy.disk === "none") flags.unshift("--permission", `--allow-fs-read=${privDir}`);
  return flags;
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
 * Measures and launches a VPN exit: the measured exit bundle runs on the verified node copy with
 * {@link exitNodeFlags} and `PLR_TDX_SOCKET`. If the exit process exits, the host stops (fail closed).
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
