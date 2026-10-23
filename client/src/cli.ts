#!/usr/bin/env node
/**
 * `plr` CLI (SPEC §12): `plr verify` | `plr chat "<prompt>"` | `plr chat` / `plr chat -` (prompt from stdin) | `plr proxy`.
 * Reading the prompt from stdin is recommended: argv is visible to other local users (`ps`) and lands in
 * shell history.
 * Config via env: PLR_ROUTER_URL, PLR_NEAR_RPC, PLR_REGISTRY, PLR_TRUSTED_ROOT (128 hex);
 * optional PLR_PROXY_PORT (default 18787) and PLR_PROXY_HOST (default 127.0.0.1).
 */
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { PlrError, isHex, isPlrError, isValidP256Pub, fromHex, toHex, type RegistryReader } from "@plr/shared";
import { NearRegistry, checkRpcUrl } from "./near-registry.js";
import { PrivateClient } from "./client.js";
import { startProxy } from "./proxy.js";
import { TracingRegistry, checkLines, formatCheckLine } from "./verify-report.js";

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
}

export interface CliConfig {
  routerUrl: string;
  rpcUrl: string;
  contractId: string;
  trustedRoot: Uint8Array;
  proxyPort: number;
  proxyHost: string;
}

const DEFAULTS = { router: "http://127.0.0.1:18100", rpc: "http://127.0.0.1:3030", proxyPort: 18787, proxyHost: "127.0.0.1" };

/** Max prompt read from stdin (the router's request limit is 1 MiB of ciphertext). */
export const MAX_STDIN_PROMPT = 512 * 1024;

const CHAT_USAGE = `usage: plr chat              read the prompt from stdin (recommended), e.g.  plr chat < prompt.txt
       plr chat -            same
       plr chat "<prompt>"   prompt as an argument (visible in \`ps\` and shell history)`;

const USAGE = `usage: plr verify | plr chat [-|"<prompt>"] | plr proxy
       plr chat reads the prompt from stdin when no argument (or "-") is given — recommended, since argv is
       visible to other local processes and saved in shell history.
env:   PLR_ROUTER_URL (default ${DEFAULTS.router})
       PLR_NEAR_RPC   (default ${DEFAULTS.rpc}; https, or http to a loopback host only)
       PLR_REGISTRY   registry contract account id (required)
       PLR_TRUSTED_ROOT  pinned attestation root, 128 hex (required)
       PLR_PROXY_PORT (default ${DEFAULTS.proxyPort}), PLR_PROXY_HOST (default ${DEFAULTS.proxyHost})`;

export class ConfigError extends Error {}

/** Reads and validates the env config. Fails closed: no trusted root ⇒ no default. */
export function loadConfig(env: Record<string, string | undefined>): CliConfig {
  const contractId = env.PLR_REGISTRY;
  if (contractId === undefined || contractId === "") throw new ConfigError("PLR_REGISTRY is required");
  const rootHex = env.PLR_TRUSTED_ROOT;
  if (!isHex(rootHex, 64)) throw new ConfigError("PLR_TRUSTED_ROOT must be 128 lowercase hex chars");
  const trustedRoot = fromHex(rootHex, 64);
  if (!isValidP256Pub(trustedRoot)) throw new ConfigError("PLR_TRUSTED_ROOT is not a valid P-256 public key");
  const rpcUrl = env.PLR_NEAR_RPC || DEFAULTS.rpc;
  try {
    checkRpcUrl(rpcUrl);
  } catch {
    throw new ConfigError("PLR_NEAR_RPC must be an https URL (plain http only to a loopback host: the RPC decides the registry checks)");
  }
  const portStr = env.PLR_PROXY_PORT ?? String(DEFAULTS.proxyPort);
  if (!/^\d{1,5}$/.test(portStr) || Number(portStr) > 65535) throw new ConfigError("PLR_PROXY_PORT must be a port number");
  return {
    routerUrl: env.PLR_ROUTER_URL || DEFAULTS.router,
    rpcUrl,
    contractId,
    trustedRoot,
    proxyPort: Number(portStr),
    proxyHost: env.PLR_PROXY_HOST || DEFAULTS.proxyHost,
  };
}

function errCode(e: unknown): string {
  return isPlrError(e) ? e.code : e instanceof Error ? e.message : "error";
}

async function cmdVerify(cfg: CliConfig, registry: TracingRegistry, client: PrivateClient, io: CliIo): Promise<number> {
  io.out(`PLR verify`);
  io.out(`  router:   ${client.routerUrl}`);
  io.out(`  registry: ${registry.contractId} on ${registry.chain} (${cfg.rpcUrl})`);
  io.out(`  pinned root: ${client.rootKind} ROOT ${toHex(cfg.trustedRoot)}`);
  io.out("");
  let verified;
  try {
    verified = await client.attest();
  } catch (e) {
    for (const l of checkLines(e, registry.lastCall)) io.out(formatCheckLine(l));
    io.out("");
    io.out(`✘ REFUSED — ${errCode(e)}. Nothing would be sent to this router.`);
    return 1;
  }
  for (const l of checkLines(undefined)) io.out(formatCheckLine(l));
  io.out("");
  io.out(`✔ VERIFIED`);
  io.out(`  root:            ${verified.rootKind} ROOT${verified.rootKind === "MOCK" ? " (local test root, NOT Intel)" : ""}`);
  io.out(`  compose hash:    ${toHex(verified.composeHash)}`);
  io.out(`  OS measurement:  ${toHex(verified.osMeasurement)}`);
  io.out(`  key hash:        ${toHex(verified.keyHash)}`);
  io.out(`  router x25519:   ${toHex(verified.x25519)}`);
  io.out(`  router ed25519:  ${toHex(verified.ed25519)}`);
  try {
    const inst = await registry.inner.getInstance(toHex(verified.keyHash));
    if (inst === null) {
      io.out(`  on-chain instance: (none — registration expired since verification)`);
    } else {
      io.out(`  on-chain instance:`);
      io.out(`    operator:      ${inst.operator}`);
      io.out(`    registered at: ${new Date(inst.registered_at_ms).toISOString()}`);
      io.out(`    expires at:    ${new Date(inst.expires_at_ms).toISOString()}`);
      io.out(`    next seq:      ${inst.next_seq}`);
    }
  } catch {
    io.out(`  on-chain instance: (registry unavailable)`);
  }
  return 0;
}

async function cmdChat(prompt: string, client: PrivateClient, io: CliIo, writeDelta: (s: string) => void): Promise<number> {
  try {
    const r = await client.chat({ messages: [{ role: "user", content: prompt }] }, { onDelta: writeDelta });
    writeDelta("\n");
    io.err(`✔ verified ${r.verified.rootKind} ROOT · compose ${r.receipt.compose_hash}`);
    io.err(`✔ receipt seq ${r.receipt.seq} · sig ${r.sig.slice(0, 16)}… (Ed25519, verified)`);
    return 0;
  } catch (e) {
    writeDelta("\n");
    io.err(`✘ ${errCode(e)}`);
    return 1;
  }
}

class StdinTooLargeError extends Error {}

/** Reads all of process.stdin as UTF-8 (fatal decoding), refusing more than {@link MAX_STDIN_PROMPT} bytes. */
export async function readStdinText(stream: NodeJS.ReadableStream = process.stdin, max = MAX_STDIN_PROMPT): Promise<string> {
  const parts: Buffer[] = [];
  let n = 0;
  for await (const chunk of stream) {
    const b = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
    n += b.length;
    if (n > max) throw new StdinTooLargeError();
    parts.push(b);
  }
  const all = Buffer.concat(parts);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(all);
  } finally {
    all.fill(0);
    for (const p of parts) p.fill(0);
  }
}

/** Resolves the chat prompt: argv form, or stdin for no argument / "-". `null` ⇒ usage error. */
async function chatPrompt(rest: string[], readStdin: () => Promise<string>, io: CliIo): Promise<string | null> {
  if (rest.length > 1) return null;
  const arg = rest[0];
  if (arg !== undefined && arg !== "-") return arg === "" ? null : arg;
  let text: string;
  try {
    text = await readStdin();
  } catch (e) {
    io.err(e instanceof StdinTooLargeError ? `✘ prompt on stdin exceeds ${MAX_STDIN_PROMPT} bytes` : "✘ could not read the prompt from stdin (must be UTF-8)");
    return null;
  }
  // One trailing newline (from `echo` / heredocs) is not part of the prompt.
  const prompt = text.replace(/\r?\n$/, "");
  return prompt.trim() === "" ? null : prompt;
}

/** Runs the CLI; returns the exit code. `proxy` resolves only when the process is signalled. */
export async function runCli(
  argv: string[],
  env: Record<string, string | undefined>,
  io: CliIo = { out: (s) => console.log(s), err: (s) => console.error(s) },
  writeDelta: (s: string) => void = (s) => void process.stdout.write(s),
  readStdin: () => Promise<string> = () => readStdinText(),
): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === undefined || cmd === "-h" || cmd === "--help" || !["verify", "chat", "proxy"].includes(cmd)) {
    io.err(USAGE);
    return 2;
  }
  if (cmd === "chat" && (rest.length > 1 || rest[0] === "-h" || rest[0] === "--help" || rest[0] === "")) {
    io.err(CHAT_USAGE);
    return 2;
  }
  let cfg: CliConfig;
  let registry: TracingRegistry;
  let client: PrivateClient;
  try {
    cfg = loadConfig(env);
    const near: RegistryReader = new NearRegistry({ rpcUrl: cfg.rpcUrl, contractId: cfg.contractId });
    registry = new TracingRegistry(near);
    client = new PrivateClient({ routerUrl: cfg.routerUrl, registry, trustedRoot: cfg.trustedRoot });
  } catch (e) {
    io.err(`config error: ${e instanceof ConfigError ? e.message : errCode(e)}`);
    io.err(USAGE);
    return 2;
  }
  if (cmd === "verify") return cmdVerify(cfg, registry, client, io);
  if (cmd === "chat") {
    // Config is valid: only now read the prompt (so a misconfigured CLI never consumes stdin).
    const prompt = await chatPrompt(rest, readStdin, io);
    if (prompt === null) {
      io.err(CHAT_USAGE);
      return 2;
    }
    return cmdChat(prompt, client, io, writeDelta);
  }

  try {
    await client.attest();
  } catch (e) {
    io.err(`✘ router verification failed: ${errCode(e)} — proxy not started`);
    return 1;
  }
  const p = await startProxy({ port: cfg.proxyPort, host: cfg.proxyHost, client });
  io.out(`✔ router verified (${client.rootKind} ROOT); OpenAI-compatible proxy on ${p.url}/v1`);
  await new Promise<void>((resolve) => {
    const stop = (): void => resolve();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  await p.close();
  return 0;
}

function isMain(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isMain()) {
  runCli(process.argv.slice(2), process.env).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      console.error(`✘ ${e instanceof PlrError ? e.code : "unexpected error"}`);
      process.exitCode = 1;
    },
  );
}
