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
  HostError, composeServiceOf, generateRootSecret, launch, launchVpn, loadRootSecret, measureBoot, measureVpnBoot, type HostHandle, type VpnHostHandle,
} from "./host.js";

const log = new Logger("plr-host");

function fail(c: string): never {
  log.info("error", { code: code(c) });
  process.exit(1);
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
  if (composeServiceOf(values.compose) === "vpn") return vpnMain(cmd, values);
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
  let handle: HostHandle | null = null;
  let stopping = false;
  // A signal during launch (e.g. while the model loads) aborts it: launch() tears down what it already
  // started (LLM, quote socket, private dir) before rejecting, so nothing is orphaned.
  const abort = new AbortController();
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      if (stopping) return;
      stopping = true;
      if (handle) void handle.stop().then((c) => process.exit(c));
      else abort.abort();
    });
  }
  handle = await launch({
    signal: abort.signal,
    ...spec,
    root,
    runDir: values["run-dir"] ?? ".run",
    ...(values["state-dir"] !== undefined ? { stateDir: values["state-dir"] } : {}),
    routerPort: port(values["router-port"], 18100),
    llmPort: port(values["llm-port"], 0),
    routerEnv: process.env,
  });
  // A signal that arrived just as launch() completed: stop what was launched.
  if (abort.signal.aborted) process.exit(await handle.stop());
  const exitCode = await handle.done;
  process.exit(exitCode);
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
  let handle: VpnHostHandle | null = null;
  let stopping = false;
  const abort = new AbortController();
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      if (stopping) return;
      stopping = true;
      if (handle) void handle.stop().then((c) => process.exit(c));
      else abort.abort();
    });
  }
  handle = await launchVpn({
    signal: abort.signal,
    ...spec,
    root,
    runDir: str("run-dir") ?? ".run",
    ...(portArg !== undefined ? { exitPort: port(portArg, 18200) } : {}),
    exitEnv: process.env,
  });
  if (abort.signal.aborted) process.exit(await handle.stop());
  process.exit(await handle.done);
}

process.on("uncaughtException", (e) => fail(e instanceof HostError ? e.code : "E_HOST"));
process.on("unhandledRejection", (e) => fail(e instanceof HostError ? e.code : "E_HOST"));
main(process.argv.slice(2)).catch((e: unknown) => fail(e instanceof HostError ? e.code : "E_HOST"));
