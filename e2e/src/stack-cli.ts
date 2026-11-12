#!/usr/bin/env node
/**
 * Long-running local stack for manual use and the demo (scripts/dev-up.sh, scripts/demo.sh).
 *
 *   node e2e/dist/stack-cli.js up [--rpc-port N] [--exit-port N] [--id <id>]
 *                                 [--extra vpn-honest-test,vpn-evil-logger,vpn-mitm-key,…] [--destination]
 *                                 [--env-out .run/stack.env] [--dns-down-file <path>] [--evil-entry]
 *       Starts near-sandbox + the VPN registry + the test builds' DoH resolver (127.0.0.1:18253), approves and
 *       launches the honest PRODUCTION VPN exit (SPEC-VPN; `vpn-honest`, registered by `operator`) (+ extra
 *       variants: VPN builds and network attacks — `vpn-evil-logger` is never approved).
 *       Two-hop (SPEC-VPN §10): the owner approves `operator` as org-a and `operator2` as org-b; a second
 *       production exit (`vpn-honest`, registered by `operator2`, PLR_VPN2_URL) and a two-hop ENTRY (registered by
 *       `operator2`, PLR_VPN_ENTRY_URL) are launched. The entry is the approved TEST build: a production entry
 *       refuses to dial a loopback exit (egress policy), so on one machine only a loopback-allowing entry can
 *       reach the exit; in the cloud both hops are production builds with public addresses.
 *       `vpn-honest-test` is therefore always approved. Optionally a local HTTP destination (`--destination`,
 *       port in PLR_DEST_PORT, name PLR_DEST_HOST=dest.plr.test known only to the local DoH resolver).
 *       Writes the env file (PLR_* client config incl. PLR_VPN_URL, PLR_VPN_ENTRY_URL, PLR_VPN_REGISTRY,
 *       PLR_VPN_COMPOSE_HASH) and the owner key file (0600), then runs until SIGINT/SIGTERM, when it
 *       stops everything and removes both files. Exit/host output is teed to <logs>/<variant>.log
 *       (content-free for honest builds; the evil build would print what it sees there).
 *       `--dns-down-file <path>`: while <path> exists the DoH resolver answers HTTP 503 (demo: "resolver down").
 *       `--evil-entry`: ⚠️ also a `vpn-evil-logger` instance registered by `operator` (org-a) for the demo's
 *       separation-of-knowledge step (PLR_VPN_EVIL_ENTRY_URL): the owner approves the evil build just long enough
 *       for it to register, then revokes it again (PLR_VPN_EVIL_COMPOSE_HASH; the demo re-approves it briefly).
 *       Shutdown triggers: `--stop-file <path>` (the file appears; dev-down.sh, demo.sh), `--parent-pid <pid>`
 *       (that process is gone, however it ended), SIGINT/SIGTERM. Shutdown is idempotent and bounded: every
 *       exit subtree and the chain get SIGTERM to their process group, SIGKILL after 10 s, and the CLI exits
 *       within 20 s whatever happens. (A named FIFO on stdin is NOT used: on macOS Node never sees its EOF.)
 *   node e2e/dist/stack-cli.js owner <method> '<json args>' [--env-out .run/stack.env]
 *       Calls a registry owner method (allow_compose, revoke_compose, …) on the VPN registry with the stack's owner
 *       key. (`--vpn` is accepted for compatibility and changes nothing: there is one registry.)
 */
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { Account, JsonRpcProvider, KeyPairSigner, type KeyPairString } from "near-api-js";
import { toHex } from "@plr/shared";
import { REPO_ROOT, runRoot, VPN_VARIANTS, startStack, type Destination, type DevStack, type ExitHandle, type VpnVariant } from "./harness.js";
import { signalAllManaged } from "./procs.js";

const DEFAULT_ENV_FILE = join(REPO_ROOT, ".run", "stack.env");
const GAS = 300_000_000_000_000n;
const SHUTDOWN_DEADLINE_MS = 20_000;

function die(msg: string): never {
  process.stderr.write(`stack-cli: ${msg}\n`);
  process.exit(1);
}

const envPrefix = (v: VpnVariant) => `PLR_${v.toUpperCase().replace(/-/g, "_")}`;
const envVarName = (v: VpnVariant) => `${envPrefix(v)}_URL`;
/** The local destination's name: only the stack's DoH resolver knows it (`.test` never resolves publicly). */
const DEST_NAME = "dest.plr.test";
/** Operator organizations of the dev stack (SPEC §7 rev 1.2): entry and exit belong to different orgs. */
const ORGS = { operator: "org-a", operator2: "org-b" } as const;
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
  const extras = ((values.extra as string | undefined) ?? "").split(",").filter(Boolean);
  const isExitVariant = (e: string): e is VpnVariant => (VPN_VARIANTS as readonly string[]).includes(e) && e !== "vpn-honest";
  for (const e of extras) if (!isExitVariant(e)) die(`unknown extra variant: ${e}`);
  if (new Set(extras).size !== extras.length) die("duplicate extra variant");
  const exitExtras = extras.filter(isExitVariant);
  const envFile = resolve((values["env-out"] as string | undefined) ?? DEFAULT_ENV_FILE);
  const ownerFile = ownerFileOf(envFile);
  const id = (values.id as string | undefined) ?? `dev-${Date.now().toString(36)}`;
  const logDir = join(runRoot(), `${id}-logs`);
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

  // Keep running until signalled (or a stop trigger above).
  setInterval(() => undefined, 1 << 30);
  try {
    const rpcPort = port(values["rpc-port"] as string | undefined);
    const exitPort = port(values["exit-port"] as string | undefined);
    if (exitPort !== undefined && exitPort !== 0 && exitPort === rpcPort) throw new Error("exit and rpc ports must differ");
    for (const [what, p] of [["rpc", rpcPort], ["exit", exitPort]] as const) {
      if (p !== undefined && p !== 0 && !(await portFree(p))) throw new Error(`${what} port ${p} is already in use`);
    }
    process.stdout.write(`stack-cli: starting near-sandbox + the VPN registry (id=${id})…\n`);
    stack = await startStack({
      id,
      ...(rpcPort !== undefined ? { rpcPort } : {}),
      onOutput: (v, chunk) => appendFileSync(join(logDir, `${v}.log`), chunk, { mode: 0o600 }),
    });
    process.stdout.write(`stack-cli: VPN registry ${stack.vpnContractId} at ${stack.rpcUrl}\n`);
    // VPN (SPEC-VPN): the honest production exit on the VPN registry, plus any requested exit variants.
    const vpnApproved = await stack.approveVpnBuild("vpn-honest");
    process.stdout.write(`stack-cli: owner approved vpn-honest build on the VPN registry compose=${vpnApproved.composeHash} os=${vpnApproved.osMeasurement}\n`);
    const testApproved = await stack.approveVpnBuild("vpn-honest-test");
    process.stdout.write(`stack-cli: owner approved vpn-honest-test build (loopback allowed: local tests and the two-hop entry only) compose=${testApproved.composeHash}\n`);
    for (const [account, org] of Object.entries(ORGS) as Array<[keyof typeof ORGS, string]>) {
      await stack.approveOperator(account, org);
      process.stdout.write(`stack-cli: owner approved operator ${stack.accounts[account]} as organization ${org}\n`);
    }
    process.stdout.write(`stack-cli: DoH resolver of the test builds on http://127.0.0.1:18253/dns-query\n`);
    const exits: Partial<Record<VpnVariant, ExitHandle>> = {};
    exits["vpn-honest"] = await stack.startExit("vpn-honest", { operator: "operator", ...(exitPort !== undefined ? { port: exitPort } : {}) });
    process.stdout.write(`stack-cli: vpn-honest exit ${exits["vpn-honest"].url} key_hash=${exits["vpn-honest"].keyHash} (operator, ${ORGS.operator})\n`);
    // Two-hop: a second production exit and the entry, both run by operator2 (org-b). Labels keep their logs apart.
    const exit2 = await stack.startExit("vpn-honest", { operator: "operator2", label: "vpn-honest-2" });
    process.stdout.write(`stack-cli: vpn-honest exit #2 ${exit2.url} key_hash=${exit2.keyHash} (operator2, ${ORGS.operator2})\n`);
    const entry = await stack.startExit("vpn-honest-test", { operator: "operator2", label: "vpn-entry" });
    process.stdout.write(`stack-cli: two-hop entry (vpn-honest-test) ${entry.url} key_hash=${entry.keyHash} (operator2, ${ORGS.operator2})\n`);
    for (const e of exitExtras) {
      exits[e] = await stack.startExit(e);
      process.stdout.write(`stack-cli: ${e} exit ${exits[e]!.url} compose=${exits[e]!.composeHash}\n`);
    }
    let evilEntry: { url: string; composeHash: string } | null = null;
    if (values["evil-entry"] === true) {
      // After the extras: an unapproved `vpn-evil-logger` extra must have failed its registration already.
      const evil = await stack.approveVpnBuild("vpn-evil-logger");
      const h = await stack.startExit("vpn-evil-logger", { operator: "operator", label: "vpn-evil-entry" });
      await stack.callVpn("owner", "revoke_compose", { hash: evil.composeHash });
      evilEntry = { url: h.url, composeHash: evil.composeHash };
      process.stdout.write(`stack-cli: ⚠️ evil logging entry ${h.url} registered (operator, ${ORGS.operator}); its build is revoked again compose=${evil.composeHash}\n`);
    }
    let dest: Destination | null = null;
    if (values.destination === true) {
      dest = await stack.startDestination();
      stack.dns.set(DEST_NAME, [dest.host]);
      process.stdout.write(`stack-cli: local HTTP destination on 127.0.0.1:${dest.port} (${DEST_NAME} in the local DoH resolver)\n`);
    }
    const dnsDownFile = values["dns-down-file"] as string | undefined;
    if (dnsDownFile !== undefined) {
      rmSync(dnsDownFile, { force: true });
      let down = false;
      const dns = stack.dns;
      setInterval(() => {
        const now = existsSync(dnsDownFile);
        if (now === down) return;
        down = now;
        dns.setDown(down);
        process.stdout.write(`stack-cli: DoH resolver ${down ? "DOWN (HTTP 503)" : "UP"}\n`);
      }, 200).unref();
    }

    const lines = [
      `# PLR local stack (${new Date().toISOString()}), written by e2e/src/stack-cli.ts; removed by dev-down.sh`,
      ...stack.clientEnvLines(),
      `PLR_TRUSTED_ROOT=${toHex(stack.trustedRoot)}`,
      `PLR_OWNER_ID=${stack.accounts.owner}`,
      `PLR_STACK_RUN_DIR=${stack.runDir}`,
      `PLR_STACK_LOG_DIR=${logDir}`,
      `PLR_STACK_PID=${process.pid}`,
      `PLR_VPN_URL=${exits["vpn-honest"].url}`,
      `# two-hop (SPEC-VPN §10): with PLR_VPN_ENTRY_URL set, \`plr vpn\` routes client → entry → PLR_VPN_URL; unset it for one hop`,
      `PLR_VPN_ENTRY_URL=${entry.url}`,
      `PLR_VPN2_URL=${exit2.url}`,
      `PLR_VPN_ORG=${ORGS.operator}`,
      `PLR_VPN_ENTRY_ORG=${ORGS.operator2}`,
      `PLR_OPERATOR_ID=${stack.accounts.operator}`,
      `PLR_OPERATOR2_ID=${stack.accounts.operator2}`,
      `PLR_VPN_COMPOSE_HASH=${vpnApproved.composeHash}`,
      `PLR_VPN_OS_MEASUREMENT=${vpnApproved.osMeasurement}`,
      `PLR_VPN_TEST_COMPOSE_HASH=${testApproved.composeHash}`,
      `PLR_DOH_URL=http://127.0.0.1:18253/dns-query`,
      ...exitExtras.map((e) => `${envVarName(e)}=${exits[e]!.url}`),
      ...(evilEntry ? [`PLR_VPN_EVIL_ENTRY_URL=${evilEntry.url}`, `PLR_VPN_EVIL_COMPOSE_HASH=${evilEntry.composeHash}`] : []),
      ...(dest ? [`PLR_DEST_PORT=${dest.port}`, `PLR_DEST_HOST=${DEST_NAME}`] : []),
    ];
    writeReady(stack, envFile, ownerFile, lines);
  } catch (e) {
    process.stderr.write(`stack-cli: start failed: ${e instanceof Error ? e.message : String(e)}\n`);
    await shutdown(1, "start failed");
  }
}

/**
 * `KEY=value` with the value single-quoted when the shell would split or interpret it (e.g. a value with spaces or
 * `;`), so `set -a; . stack.env` works; {@link readEnvFile} unquotes.
 */
function shellSafeLine(line: string): string {
  const m = /^(PLR_[A-Z0-9_]+)=(.*)$/.exec(line);
  if (!m || /^[A-Za-z0-9_./:@,+=%-]*$/.test(m[2]!)) return line;
  return `${m[1]}='${m[2]!.replace(/'/g, `'\\''`)}'`;
}

/** Writes the owner key file (0600) and then, last, the env file: its existence means "ready". */
function writeReady(stack: DevStack, envFile: string, ownerFile: string, lines: string[]): void {
  mkdirSync(dirname(envFile), { recursive: true });
  // Owner key(s) for the `owner` sub-command (demo revocation): fresh dev-chain keys, 0600, removed on stop.
  writeFileSync(ownerFile, JSON.stringify(stack.ownerFile()), { mode: 0o600 });
  chmodSync(ownerFile, 0o600);
  writeFileSync(envFile + ".tmp", lines.map(shellSafeLine).join("\n") + "\n", { mode: 0o600 });
  writeFileSync(envFile, readFileSync(envFile + ".tmp"), { mode: 0o600 });
  rmSync(envFile + ".tmp");
  process.stdout.write(`stack-cli: READY — env in ${envFile}\n`);
}

function readEnvFile(path: string): Record<string, string> {
  if (!existsSync(path)) die(`${path} not found — start a stack first (scripts/dev-up.sh)`);
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = /^(PLR_[A-Z0-9_]+)=(.*)$/.exec(line);
    if (m) out[m[1]!] = /^'.*'$/s.test(m[2]!) ? m[2]!.slice(1, -1).replace(/'\\''/g, "'") : m[2]!;
  }
  return out;
}

const OWNER_METHODS = new Set(["allow_compose", "revoke_compose", "allow_os", "revoke_os", "approve_operator", "revoke_operator"]);

async function owner(method: string | undefined, argsJson: string | undefined, envFile: string): Promise<void> {
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
  const contractId = env.PLR_VPN_REGISTRY;
  if (!contractId) die(`owner: PLR_VPN_REGISTRY missing in ${envFile}`);
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
    "rpc-port": { type: "string" },
    "exit-port": { type: "string" },
    destination: { type: "boolean" },
    "evil-entry": { type: "boolean" },
    vpn: { type: "boolean" },
    id: { type: "string" },
    extra: { type: "string" },
    "env-out": { type: "string" },
    "stop-file": { type: "string" },
    "parent-pid": { type: "string" },
    "dns-down-file": { type: "string" },
  },
});
if (cmd === "up") await up(values);
else if (cmd === "owner") await owner(positionals[0], positionals[1], resolve(values["env-out"] ?? DEFAULT_ENV_FILE));
else die("usage: stack-cli up [...] | stack-cli owner <method> '<json>'");
