#!/usr/bin/env node
/**
 * Mock TDX host CLI.
 *
 *   plr-tdx-host launch  --compose <app-compose.json> [--bundle <file>] [--llm-file <file>] [--run-dir <dir>]
 *                        [--state-dir <dir>] [--router-port N] [--llm-port N] [--llama-server <bin>] [--debug]
 *   plr-tdx-host measure --compose <app-compose.json> [--bundle <file>] [--llm-file <file>] [--debug]
 *   plr-tdx-host gen-root --out <file>
 *
 * The compose's `name` selects the service: `plr-router` (above) or `plr-vpn` (SPEC-VPN §2, no LLM):
 *   plr-tdx-host launch  --compose <vpn app-compose.json> [--bundle <file>] [--run-dir <dir>] [--exit-port N] [--debug]
 *   plr-tdx-host measure --compose <vpn app-compose.json> [--bundle <file>] [--debug]
 * For a VPN compose `--exit-port` (default PLR_VPN_PORT, else 18200) is the listen port; `--router-port` is accepted
 * as an alias. LLM options are refused for a VPN compose; `--state-dir` is accepted and ignored.
 *
 * A `plr-combo` compose (SPEC-COMBO §2) launches the LLM, the router and the VPN exit as three processes in one TD:
 *   plr-tdx-host launch  --compose <combo app-compose.json> [--llm-file <file>] [--run-dir <dir>] [--state-dir <dir>]
 *                        [--router-port N] [--exit-port N] [--llm-port N] [--llama-server <bin>] [--debug]
 *   plr-tdx-host measure --compose <combo app-compose.json> [--llm-file <file>] [--llama-server <bin>] [--debug]
 * Both bundles are read from the compose's directory (`--bundle` is refused: it would be ambiguous). `--router-port`
 * defaults to 18100, `--exit-port` to PLR_VPN_PORT, else 18200. The router gets only the router variables below and
 * the exit only the VPN ones — in a combo without the PLR_REGISTRY fallback (that is the LLM registry).
 *
 * Environment:
 *   PLR_MOCK_ROOT_SECRET_FILE  path of the MOCK ROOT secret (64 hex, mode 0600)            [launch, measure]
 *   PLR_NEAR_RPC, PLR_REGISTRY, PLR_OPERATOR_ID, PLR_OPERATOR_KEY, PLR_REGISTER_DEPOSIT, PLR_ANCHOR_DEPOSIT,
 *   PLR_ANCHOR_INTERVAL_MS, PLR_ROUTER_HOST                                     forwarded to the router
 *   PLR_NEAR_RPC, PLR_VPN_REGISTRY (else PLR_REGISTRY), PLR_OPERATOR_ID, PLR_OPERATOR_KEY, PLR_REGISTER_DEPOSIT,
 *   PLR_ANCHOR_DEPOSIT, PLR_ANCHOR_INTERVAL_MS, PLR_VPN_HOST, PLR_VPN_PORT                forwarded to a VPN exit
 *
 * `launch` is the default command when the first argument is an option. `measure` prints
 * `{"compose_hash","os_measurement","bundle_sha256","llm_sha256","node_sha256","llm_runtime_sha256"}` (after
 * verifying every hash, including the node / llama-server runtime closures) and exits.
 * `gen-root` writes a new secret file (0600) and prints `{"root_p256":"<128 hex>"}`.
 */
import { parseArgs } from "node:util";
import { toHex } from "@plr/shared";
import { Logger, code } from "../log.js";
import {
  HostError, composeServiceOf, generateRootSecret, launch, launchCombo, launchVpn, loadRootSecret, measureBoot, measureComboBoot, measureVpnBoot,
} from "./host.js";

const log = new Logger("plr-host");

// A closed log reader (e.g. `plr-tdx-host launch … | head`) must not crash the TD: ignore EPIPE and other write
// errors on our own output. Children's output that can no longer be written is simply dropped.
process.stdout.on("error", () => undefined);
process.stderr.on("error", () => undefined);

function fail(c: string): never {
  log.info("error", { code: code(c) });
  process.exit(1);
}

/** Upper bound for tearing the TD down before exiting (children get SIGKILL 3 s after SIGTERM, see host.ts). */
const TEARDOWN_TIMEOUT_MS = 15_000;

interface Td {
  abort: AbortController;
  /** The launch in progress, resolving to the running TD. */
  launching: Promise<{ stop(): Promise<number>; done: Promise<number> }> | null;
}
/** The TD this process launched or is launching: signals and fatal errors tear it down, never orphan it. */
let td: Td | null = null;
let exiting = false;

/**
 * Stops the TD, then exits with `exitCode` (`null`: the TD's own stop code). A launch still in progress is aborted:
 * `launch*()` tears down whatever it started (LLM, quote socket, private dir) before rejecting, and a launch that
 * completes anyway is stopped. Idempotent and bounded by {@link TEARDOWN_TIMEOUT_MS}.
 */
function exitAfterTeardown(exitCode: number | null): void {
  if (exiting) return;
  exiting = true;
  const cur = td;
  if (!cur?.launching) process.exit(exitCode ?? 1);
  setTimeout(() => process.exit(exitCode ?? 1), TEARDOWN_TIMEOUT_MS);
  cur.abort.abort();
  cur.launching
    .then(
      (h) => h.stop().then((c) => process.exit(exitCode ?? c)),
      () => process.exit(exitCode ?? 1),
    )
    .catch(() => process.exit(1));
}

/** A fatal error (uncaught exception, unhandled rejection, failed launch): log its code, tear the TD down, exit 1. */
function fatal(e: unknown): void {
  if (exiting) return;
  log.info("error", { code: code(e instanceof HostError ? e.code : "E_HOST") });
  exitAfterTeardown(1);
}

/**
 * Runs a TD launched by `start` until it ends. SIGTERM/SIGINT stop it (aborting a launch in progress) and exit with
 * its stop code; when the TD ends by itself the host exits with its code.
 */
async function runTd(start: (signal: AbortSignal) => Promise<{ stop(): Promise<number>; done: Promise<number> }>): Promise<void> {
  const cur: Td = { abort: new AbortController(), launching: null };
  td = cur;
  for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => exitAfterTeardown(null));
  cur.launching = start(cur.abort.signal);
  const handle = await cur.launching;
  const c = await handle.done;
  if (!exiting) process.exit(c);
}

function port(v: string | undefined, def: number): number {
  if (v === undefined) return def;
  if (!/^[0-9]{1,5}$/.test(v) || Number(v) > 65535) fail("E_BAD_PORT");
  return Number(v);
}

function rootFromEnv() {
  const p = process.env.PLR_MOCK_ROOT_SECRET_FILE;
  if (!p) fail("E_ROOT_SECRET");
  return loadRootSecret(p);
}

async function main(argv: string[]): Promise<void> {
  const cmd = argv[0] && !argv[0].startsWith("-") ? argv[0] : "launch";
  const rest = argv[0] && !argv[0].startsWith("-") ? argv.slice(1) : argv;
  const { values } = parseArgs({
    args: rest,
    strict: true,
    allowPositionals: false,
    options: {
      compose: { type: "string" },
      bundle: { type: "string" },
      "llm-file": { type: "string" },
      "run-dir": { type: "string" },
      "state-dir": { type: "string" },
      "router-port": { type: "string" },
      "exit-port": { type: "string" },
      "llm-port": { type: "string" },
      "llama-server": { type: "string" },
      debug: { type: "boolean", default: false },
      out: { type: "string" },
    },
  });

  if (cmd === "gen-root") {
    if (!values.out) fail("E_USAGE");
    const root = await generateRootSecret(values.out);
    process.stdout.write(JSON.stringify({ root_p256: toHex(root.publicKey) }) + "\n");
    return;
  }
  if (!values.compose) fail("E_USAGE");
  const service = composeServiceOf(values.compose);
  if (service === "vpn") return vpnMain(cmd, values);
  if (service === "combo") return comboMain(cmd, values);
  if (values["exit-port"] !== undefined) fail("E_USAGE");
  const spec = {
    composePath: values.compose,
    ...(values.bundle !== undefined ? { bundlePath: values.bundle } : {}),
    ...(values["llm-file"] !== undefined ? { llmFile: values["llm-file"] } : {}),
    // Any llama-server path is accepted only if its runtime closure matches the compose's llm.runtime_sha256.
    ...(values["llama-server"] !== undefined ? { llamaServer: values["llama-server"] } : {}),
    debug: values.debug === true,
  };
  if (cmd === "measure") {
    const boot = await measureBoot({ ...spec, root: rootFromEnv() });
    process.stdout.write(
      JSON.stringify({
        compose_hash: boot.composeHash,
        os_measurement: boot.osMeasurement,
        bundle_sha256: boot.compose.router.bundle_sha256,
        llm_sha256: boot.compose.llm.model_sha256,
        node_sha256: boot.compose.router.node_sha256,
        llm_runtime_sha256: boot.compose.llm.runtime_sha256,
      }) + "\n",
    );
    return;
  }
  if (cmd !== "launch") fail("E_USAGE");

  const root = rootFromEnv();
  // The secret's location is not needed by anything we launch.
  delete process.env.PLR_MOCK_ROOT_SECRET_FILE;
  const routerPort = port(values["router-port"], 18100);
  const llmPort = port(values["llm-port"], 0);
  // A signal during launch (e.g. while the model loads) aborts it: launch() tears down what it already
  // started (LLM, quote socket, private dir) before rejecting, so nothing is orphaned.
  await runTd((signal) =>
    launch({
      signal,
      ...spec,
      root,
      runDir: values["run-dir"] ?? ".run",
      ...(values["state-dir"] !== undefined ? { stateDir: values["state-dir"] } : {}),
      routerPort,
      llmPort,
      routerEnv: process.env,
    }),
  );
}

type Values = { [k: string]: string | boolean | undefined };

/** `measure` / `launch` of a `plr-vpn` compose. */
async function vpnMain(cmd: string, values: Values): Promise<void> {
  const str = (k: string): string | undefined => (typeof values[k] === "string" ? (values[k] as string) : undefined);
  // No LLM in a VPN TD: LLM options are a usage error, not silently ignored.
  if (str("llm-file") !== undefined || str("llm-port") !== undefined || str("llama-server") !== undefined) fail("E_USAGE");
  // `--state-dir` (the router's PLR_RUN_DIR) is accepted and unused: an exit is never told any writable place.
  const spec = {
    composePath: str("compose")!,
    ...(str("bundle") !== undefined ? { bundlePath: str("bundle")! } : {}),
    debug: values.debug === true,
  };
  if (cmd === "measure") {
    const boot = await measureVpnBoot({ ...spec, root: rootFromEnv() });
    process.stdout.write(
      JSON.stringify({
        service: "vpn",
        compose_hash: boot.composeHash,
        os_measurement: boot.osMeasurement,
        bundle_sha256: boot.compose.vpn.bundle_sha256,
        node_sha256: boot.compose.vpn.node_sha256,
        allow_loopback: boot.compose.policy.egress.allow_loopback,
      }) + "\n",
    );
    return;
  }
  if (cmd !== "launch") fail("E_USAGE");
  const root = rootFromEnv();
  delete process.env.PLR_MOCK_ROOT_SECRET_FILE;
  const portArg = str("exit-port") ?? str("router-port");
  const exitPort = portArg !== undefined ? port(portArg, 18200) : undefined;
  await runTd((signal) =>
    launchVpn({
      signal,
      ...spec,
      root,
      runDir: str("run-dir") ?? ".run",
      ...(exitPort !== undefined ? { exitPort } : {}),
      exitEnv: process.env,
    }),
  );
}

/** `measure` / `launch` of a `plr-combo` compose (SPEC-COMBO §2). */
async function comboMain(cmd: string, values: Values): Promise<void> {
  const str = (k: string): string | undefined => (typeof values[k] === "string" ? (values[k] as string) : undefined);
  // Two bundles, both named by the compose and read from its directory: a single --bundle would be ambiguous.
  if (str("bundle") !== undefined) fail("E_USAGE");
  const spec = {
    composePath: str("compose")!,
    ...(str("llm-file") !== undefined ? { llmFile: str("llm-file")! } : {}),
    // Any llama-server path is accepted only if its runtime closure matches the compose's llm.runtime_sha256.
    ...(str("llama-server") !== undefined ? { llamaServer: str("llama-server")! } : {}),
    debug: values.debug === true,
  };
  if (cmd === "measure") {
    const boot = await measureComboBoot({ ...spec, root: rootFromEnv() });
    const c = boot.compose;
    process.stdout.write(
      JSON.stringify({
        service: "combo",
        compose_hash: boot.composeHash,
        os_measurement: boot.osMeasurement,
        router_bundle_sha256: c.router.bundle_sha256,
        vpn_bundle_sha256: c.vpn.bundle_sha256,
        llm_sha256: c.router.llm.model_sha256,
        node_sha256: c.router.node_sha256,
        llm_runtime_sha256: c.router.llm.runtime_sha256,
        allow_loopback: c.vpn.policy.egress.allow_loopback,
      }) + "\n",
    );
    return;
  }
  if (cmd !== "launch") fail("E_USAGE");
  const root = rootFromEnv();
  delete process.env.PLR_MOCK_ROOT_SECRET_FILE;
  const exitPortArg = str("exit-port");
  const routerPort = port(str("router-port"), 18100);
  const exitPort = exitPortArg !== undefined ? port(exitPortArg, 18200) : undefined;
  const llmPort = port(str("llm-port"), 0);
  await runTd((signal) =>
    launchCombo({
      signal,
      ...spec,
      root,
      runDir: str("run-dir") ?? ".run",
      ...(str("state-dir") !== undefined ? { stateDir: str("state-dir")! } : {}),
      routerPort,
      ...(exitPort !== undefined ? { exitPort } : {}),
      llmPort,
      env: process.env,
    }),
  );
}

// Fail closed without orphans: a crash stops the LLM, router and exit and removes the private dir before exiting.
process.on("uncaughtException", fatal);
process.on("unhandledRejection", fatal);
main(process.argv.slice(2)).catch(fatal);
