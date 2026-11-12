#!/usr/bin/env node
/**
 * Mock TDX host CLI (SPEC-VPN §2: a `plr-vpn` compose).
 *
 *   plr-tdx-host launch  --compose <app-compose.json> [--bundle <file>] [--run-dir <dir>] [--exit-port N] [--debug]
 *   plr-tdx-host measure --compose <app-compose.json> [--bundle <file>] [--debug]
 *   plr-tdx-host gen-root --out <file>
 *
 * `--exit-port` (default PLR_VPN_PORT, else 18200) is the exit's listen port.
 *
 * Environment:
 *   PLR_MOCK_ROOT_SECRET_FILE  path of the MOCK ROOT secret (64 hex, mode 0600)            [launch, measure]
 *   PLR_NEAR_RPC, PLR_VPN_REGISTRY (else PLR_REGISTRY), PLR_OPERATOR_ID, PLR_OPERATOR_KEY, PLR_REGISTER_DEPOSIT,
 *   PLR_ANCHOR_DEPOSIT, PLR_ANCHOR_INTERVAL_MS, PLR_VPN_HOST, PLR_VPN_PORT, PLR_CHAIN       forwarded to the exit
 *
 * `launch` is the default command when the first argument is an option. `measure` prints
 * `{"service","compose_hash","os_measurement","bundle_sha256","node_sha256","allow_loopback"}` (after verifying
 * every hash, including the node runtime closure) and exits.
 * `gen-root` writes a new secret file (0600) and prints `{"root_p256":"<128 hex>"}`.
 */
import { parseArgs } from "node:util";
import { toHex } from "@plr/shared";
import { Logger, code } from "../log.js";
import { HostError, generateRootSecret, launchVpn, loadRootSecret, measureVpnBoot } from "./host.js";

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
 * `launchVpn()` tears down whatever it started (quote socket, private dir) before rejecting, and a launch that
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
      "run-dir": { type: "string" },
      "exit-port": { type: "string" },
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
  const spec = {
    composePath: values.compose,
    ...(values.bundle !== undefined ? { bundlePath: values.bundle } : {}),
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
  // The secret's location is not needed by anything we launch.
  delete process.env.PLR_MOCK_ROOT_SECRET_FILE;
  const portArg = values["exit-port"];
  const exitPort = portArg !== undefined ? port(portArg, 18200) : undefined;
  await runTd((signal) =>
    launchVpn({
      signal,
      ...spec,
      root,
      runDir: values["run-dir"] ?? ".run",
      ...(exitPort !== undefined ? { exitPort } : {}),
      exitEnv: process.env,
    }),
  );
}

// Fail closed without orphans: a crash stops the exit and removes the private dir before exiting.
process.on("uncaughtException", fatal);
process.on("unhandledRejection", fatal);
main(process.argv.slice(2)).catch(fatal);
