#!/usr/bin/env node
/**
 * Long-running local stack for manual use and the demo (scripts/dev-up.sh, scripts/demo.sh).
 *
 *   node e2e/dist/stack-cli.js up [--llm llama|mock] [--rpc-port N] [--router-port N] [--exit-port N] [--id <id>]
 *                                 [--extra evil-logger,mitm-key,vpn-honest-test,vpn-evil-logger,…] [--destination]
 *                                 [--env-out .run/stack.env]
 *       Starts near-sandbox + both registries (LLM + VPN), approves and launches the honest router and the honest
 *       PRODUCTION VPN exit (SPEC-VPN; `vpn-honest`, approved on the VPN registry) (+ extra variants: router
 *       attacks, and VPN builds/attacks — `vpn-honest-test` is approved whenever it or an attack in front of it is
 *       requested, `vpn-evil-logger` never is), optionally a local HTTP destination (`--destination`, port in
 *       PLR_DEST_PORT), writes the env file (PLR_* client config incl. PLR_VPN_URL, PLR_VPN_REGISTRY,
 *       PLR_VPN_COMPOSE_HASH) and the owner key file (0600), then runs until SIGINT/SIGTERM, when it
 *       stops everything and removes both files. Router/host output is teed to <logs>/<variant>.log
 *       (content-free for honest builds; the evil build would print what it steals there).
 *       Shutdown triggers: `--stop-file <path>` (the file appears; dev-down.sh, demo.sh), `--parent-pid <pid>`
 *       (that process is gone, however it ended), SIGINT/SIGTERM. Shutdown is idempotent and bounded: every
 *       router subtree and the chain get SIGTERM to their process group, SIGKILL after 10 s, and the CLI exits
 *       within 20 s whatever happens. (A named FIFO on stdin is NOT used: on macOS Node never sees its EOF.)
 *   node e2e/dist/stack-cli.js owner <method> '<json args>' [--vpn] [--env-out .run/stack.env]
 *       Calls a registry owner method (allow_compose, revoke_compose, …) with the stack's owner key, on the LLM
 *       registry or (with --vpn) on the VPN registry.
 */
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { Account, JsonRpcProvider, KeyPairSigner, type KeyPairString } from "near-api-js";
import { toHex } from "@plr/shared";
import {
  REPO_ROOT, VARIANTS, VPN_VARIANTS, startStack, type Destination, type DevStack, type ExitHandle, type RouterHandle, type Variant, type VpnVariant,
} from "./harness.js";
import { signalAllManaged } from "./procs.js";

const DEFAULT_ENV_FILE = join(REPO_ROOT, ".run", "stack.env");
const GAS = 300_000_000_000_000n;
const SHUTDOWN_DEADLINE_MS = 20_000;

function die(msg: string): never {
  process.stderr.write(`stack-cli: ${msg}\n`);
  process.exit(1);
}

const envVarName = (v: Variant | VpnVariant) => `PLR_${v.toUpperCase().replace(/-/g, "_")}_URL`;
const ownerFileOf = (envFile: string) => envFile.replace(/\.env$/, "") + ".owner.json";

function portFree(p: number): Promise<boolean> {
  return new Promise((ok) => {
    const s = net.createServer();
    s.once("error", () => ok(false));
    s.listen(p, "127.0.0.1", () => s.close(() => ok(true)));
  });
}

function port(v: string | undefined): number | undefined {
  if (v === undefined) return undefined;
  if (!/^[0-9]{1,5}$/.test(v) || Number(v) > 65535) die(`bad port: ${v}`);
  return Number(v);
}

async function up(values: Record<string, string | boolean | undefined>): Promise<void> {
  const llm = (values.llm as string | undefined) ?? "llama";
  if (llm !== "mock" && llm !== "llama") die("--llm must be mock or llama");
  const extras = ((values.extra as string | undefined) ?? "").split(",").filter(Boolean);
  const isRouterVariant = (e: string): e is Variant => (VARIANTS as readonly string[]).includes(e) && e !== "honest";
  const isExitVariant = (e: string): e is VpnVariant => (VPN_VARIANTS as readonly string[]).includes(e) && e !== "vpn-honest";
  for (const e of extras) if (!isRouterVariant(e) && !isExitVariant(e)) die(`unknown extra variant: ${e}`);
  if (new Set(extras).size !== extras.length) die("duplicate extra variant");
  const routerExtras = extras.filter(isRouterVariant);
  const exitExtras = extras.filter(isExitVariant);
  const envFile = resolve((values["env-out"] as string | undefined) ?? DEFAULT_ENV_FILE);
  const ownerFile = ownerFileOf(envFile);
  const id = (values.id as string | undefined) ?? `dev-${Date.now().toString(36)}`;
  const logDir = join(REPO_ROOT, ".run", `${id}-logs`);
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  if (existsSync(envFile)) die(`${envFile} exists — is another stack running? (scripts/dev-down.sh)`);

  let stack: DevStack | null = null;
  let stopping = false;
  /** Idempotent; exits within SHUTDOWN_DEADLINE_MS no matter what (then SIGKILLs every managed group). */
  const shutdown = async (code: number, why: string) => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`stack-cli: stopping (${why})…\n`);
    const t0 = Date.now();
    setTimeout(() => {
      signalAllManaged("SIGKILL");
      process.stdout.write("stack-cli: stopped (deadline: remaining processes SIGKILLed)\n");
      process.exit(code === 0 ? 1 : code);
    }, SHUTDOWN_DEADLINE_MS);
    rmSync(envFile, { force: true });
    rmSync(ownerFile, { force: true });
    await stack?.stop().catch(() => undefined);
    signalAllManaged("SIGKILL"); // nothing may outlive us (no-op when everything already exited)
    process.stdout.write(`stack-cli: stopped in ${((Date.now() - t0) / 1000).toFixed(1)} s\n`);
    process.exit(code);
  };
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => void shutdown(0, sig));
  process.on("SIGHUP", () => undefined); // a dev stack outlives the terminal that started it (dev-down.sh stops it)
  const parentPid = values["parent-pid"] as string | undefined;
  if (parentPid !== undefined) {
    // Stop when the given process (e.g. demo.sh) is gone, however it ended.
    if (!/^[1-9][0-9]{0,9}$/.test(parentPid)) die("--parent-pid must be a pid");
    setInterval(() => {
      try {
        process.kill(Number(parentPid), 0); // existence probe only (signal 0 delivers nothing)
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ESRCH") void shutdown(0, "parent exited");
      }
    }, 500).unref();
  }
  const stopFile = values["stop-file"] as string | undefined;
  if (stopFile !== undefined) {
    rmSync(stopFile, { force: true });
    setInterval(() => {
      if (existsSync(stopFile)) {
        rmSync(stopFile, { force: true });
        void shutdown(0, "stop file");
      }
    }, 500).unref();
  }

  try {
    const rpcPort = port(values["rpc-port"] as string | undefined);
    const routerPort = port(values["router-port"] as string | undefined);
    const exitPort = port(values["exit-port"] as string | undefined);
    for (const [what, p] of [["rpc", rpcPort], ["router", routerPort], ["exit", exitPort]] as const) {
      if (p !== undefined && p !== 0 && !(await portFree(p))) throw new Error(`${what} port ${p} is already in use`);
    }
    process.stdout.write(`stack-cli: starting near-sandbox + registry (llm=${llm}, id=${id})…\n`);
    stack = await startStack({
      llm,
      id,
      ...(rpcPort !== undefined ? { rpcPort } : {}),
      onRouterOutput: (v, chunk) => appendFileSync(join(logDir, `${v}.log`), chunk, { mode: 0o600 }),
    });
    process.stdout.write(`stack-cli: registry ${stack.contractId} + VPN registry ${stack.vpnContractId} at ${stack.rpcUrl}\n`);
    const approved = await stack.approveBuild("honest");
    process.stdout.write(`stack-cli: owner approved honest build compose=${approved.composeHash} os=${approved.osMeasurement}\n`);
    process.stdout.write(`stack-cli: launching honest router via the mock TDX host${llm === "llama" ? " (loading Qwen 0.5B)" : ""}…\n`);
    const routers: Partial<Record<Variant, RouterHandle>> = {};
    routers.honest = await stack.startRouter("honest", routerPort !== undefined ? { port: routerPort } : {});
    process.stdout.write(`stack-cli: honest router ${routers.honest.url} key_hash=${routers.honest.keyHash}\n`);
    for (const e of routerExtras) {
      routers[e] = await stack.startRouter(e);
      process.stdout.write(`stack-cli: ${e} router ${routers[e]!.url} compose=${routers[e]!.composeHash}\n`);
    }

    // VPN (SPEC-VPN): the honest production exit on the VPN registry, plus any requested exit variants.
    const vpnApproved = await stack.approveVpnBuild("vpn-honest");
    process.stdout.write(`stack-cli: owner approved vpn-honest build on the VPN registry compose=${vpnApproved.composeHash} os=${vpnApproved.osMeasurement}\n`);
    const exits: Partial<Record<VpnVariant, ExitHandle>> = {};
    exits["vpn-honest"] = await stack.startExit("vpn-honest", exitPort !== undefined ? { port: exitPort } : {});
    process.stdout.write(`stack-cli: vpn-honest exit ${exits["vpn-honest"].url} key_hash=${exits["vpn-honest"].keyHash}\n`);
    let testApproved: { composeHash: string } | null = null;
    if (exitExtras.some((e) => e !== "vpn-evil-logger")) {
      testApproved = await stack.approveVpnBuild("vpn-honest-test");
      process.stdout.write(`stack-cli: owner approved vpn-honest-test build (loopback allowed: local tests only) compose=${testApproved.composeHash}\n`);
    }
    for (const e of exitExtras) {
      exits[e] = await stack.startExit(e);
      process.stdout.write(`stack-cli: ${e} exit ${exits[e]!.url} compose=${exits[e]!.composeHash}\n`);
    }
    let dest: Destination | null = null;
    if (values.destination === true) {
      dest = await stack.startDestination();
      process.stdout.write(`stack-cli: local HTTP destination on 127.0.0.1:${dest.port}\n`);
    }

    const lines = [
      `# PLR local stack (${new Date().toISOString()}), written by e2e/src/stack-cli.ts; removed by dev-down.sh`,
      `PLR_ROUTER_URL=${routers.honest.url}`,
      `PLR_NEAR_RPC=${stack.rpcUrl}`,
      `PLR_REGISTRY=${stack.contractId}`,
      `PLR_TRUSTED_ROOT=${toHex(stack.trustedRoot)}`,
      `PLR_COMPOSE_HASH=${approved.composeHash}`,
      `PLR_OS_MEASUREMENT=${approved.osMeasurement}`,
      `PLR_OWNER_ID=${stack.accounts.owner}`,
      `PLR_STACK_RUN_DIR=${stack.runDir}`,
      `PLR_STACK_LOG_DIR=${logDir}`,
      `PLR_STACK_PID=${process.pid}`,
      ...routerExtras.map((e) => `${envVarName(e)}=${routers[e]!.url}`),
      `PLR_VPN_URL=${exits["vpn-honest"].url}`,
      `PLR_VPN_REGISTRY=${stack.vpnContractId}`,
      `PLR_VPN_COMPOSE_HASH=${vpnApproved.composeHash}`,
      `PLR_VPN_OS_MEASUREMENT=${vpnApproved.osMeasurement}`,
      ...(testApproved ? [`PLR_VPN_TEST_COMPOSE_HASH=${testApproved.composeHash}`] : []),
      ...exitExtras.map((e) => `${envVarName(e)}=${exits[e]!.url}`),
      ...(dest ? [`PLR_DEST_PORT=${dest.port}`] : []),
    ];
    mkdirSync(dirname(envFile), { recursive: true });
    // Owner key for the `owner` sub-command (demo revocation): fresh dev-chain key, 0600, removed on stop.
    const ownerKey = stack.exportSigner("owner");
    writeFileSync(ownerFile, JSON.stringify({ account_id: ownerKey.accountId, secret_key: ownerKey.secretKey }), { mode: 0o600 });
    chmodSync(ownerFile, 0o600);
    // Written last: its existence means "ready".
    writeFileSync(envFile + ".tmp", lines.join("\n") + "\n", { mode: 0o600 });
    writeFileSync(envFile, readFileSync(envFile + ".tmp"), { mode: 0o600 });
    rmSync(envFile + ".tmp");
    process.stdout.write(`stack-cli: READY — env in ${envFile}\n`);
  } catch (e) {
    process.stderr.write(`stack-cli: start failed: ${e instanceof Error ? e.message : String(e)}\n`);
    await shutdown(1, "start failed");
  }
  // Keep running until signalled.
  setInterval(() => undefined, 1 << 30);
}

function readEnvFile(path: string): Record<string, string> {
  if (!existsSync(path)) die(`${path} not found — start a stack first (scripts/dev-up.sh)`);
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = /^(PLR_[A-Z0-9_]+)=(.*)$/.exec(line);
    if (m) out[m[1]!] = m[2]!;
  }
  return out;
}

const OWNER_METHODS = new Set(["allow_compose", "revoke_compose", "allow_os", "revoke_os"]);

async function owner(method: string | undefined, argsJson: string | undefined, envFile: string, vpn: boolean): Promise<void> {
  if (!method || !OWNER_METHODS.has(method)) die(`owner: method must be one of ${[...OWNER_METHODS].join(", ")}`);
  let args: unknown;
  try {
    args = JSON.parse(argsJson ?? "");
  } catch {
    die("owner: args must be JSON");
  }
  if (typeof args !== "object" || args === null || Array.isArray(args)) die("owner: args must be a JSON object");
  const env = readEnvFile(envFile);
  const key = JSON.parse(readFileSync(ownerFileOf(envFile), "utf8")) as { account_id: string; secret_key: string };
  const contractId = vpn ? env.PLR_VPN_REGISTRY : env.PLR_REGISTRY;
  if (!contractId) die(`owner: ${vpn ? "PLR_VPN_REGISTRY" : "PLR_REGISTRY"} missing in ${envFile}`);
  const provider = new JsonRpcProvider({ url: env.PLR_NEAR_RPC! });
  const acct = new Account(key.account_id, provider, KeyPairSigner.fromSecretKey(key.secret_key as KeyPairString));
  try {
    await acct.callFunction({ contractId, methodName: method, args: args as Record<string, unknown>, gas: GAS });
  } catch (e) {
    die(`${method} failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  process.stdout.write(`${method} ✔ on ${contractId} (signed by ${key.account_id})\n`);
}

const argv = process.argv.slice(2);
const cmd = argv[0];
const { values, positionals } = parseArgs({
  args: argv.slice(1),
  allowPositionals: true,
  strict: true,
  options: {
    llm: { type: "string" },
    "rpc-port": { type: "string" },
    "router-port": { type: "string" },
    "exit-port": { type: "string" },
    destination: { type: "boolean" },
    vpn: { type: "boolean" },
    id: { type: "string" },
    extra: { type: "string" },
    "env-out": { type: "string" },
    "stop-file": { type: "string" },
    "parent-pid": { type: "string" },
  },
});
if (cmd === "up") await up(values);
else if (cmd === "owner") await owner(positionals[0], positionals[1], resolve(values["env-out"] ?? DEFAULT_ENV_FILE), values.vpn === true);
else die("usage: stack-cli up [...] | stack-cli owner <method> '<json>' [--vpn]");
