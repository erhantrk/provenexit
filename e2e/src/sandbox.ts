/**
 * A fresh near-sandbox node whose home directory lives under the stack's run directory.
 *
 * The `near-sandbox` npm package's `Sandbox.start` always uses an OS temp dir and never drains the child's
 * stderr pipe, so we drive the same binary directly: `init --fast`, add a genesis account `sandbox` with a
 * FRESH key (no well-known key controls this chain), then `run` on free 127.0.0.1 ports under a lifeline.
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import net from "node:net";
import { dirname, join } from "node:path";
import { spawn } from "node:child_process";
import { KeyPair, type KeyPairString } from "near-api-js";
import { DEFAULT_ACCOUNT_ID, DEFAULT_NEAR_SANDBOX_VERSION } from "near-sandbox";
import { startManaged, waitFor, type ManagedProcess } from "./procs.js";

/** Blocks per epoch (≈ 2 h at the sandbox's ~120 ms blocks). */
const EPOCH_LENGTH = 60_000;
/** 10 000 NEAR for the genesis account, like near-sandbox's default. */
const GENESIS_BALANCE = 10_000n * 10n ** 24n;

export interface SandboxNode {
  rpcUrl: string;
  homeDir: string;
  /** Genesis account (`sandbox`) and its fresh full-access key. */
  rootAccountId: string;
  rootKey: KeyPairString;
  /** Recent node output (diagnostics only). */
  output(): string;
  stop(): Promise<void>;
}

/** Path of the neard sandbox binary shipped with the `near-sandbox` package (or `NEAR_SANDBOX_BIN_PATH`). */
export function sandboxBinary(): string {
  const fromEnv = process.env.NEAR_SANDBOX_BIN_PATH;
  if (fromEnv) return fromEnv;
  const pkgEntry = createRequire(import.meta.url).resolve("near-sandbox"); // …/near-sandbox/dist/cjs/index.cjs
  const bin = join(dirname(pkgEntry), "..", "..", "bin", `near-sandbox-${DEFAULT_NEAR_SANDBOX_VERSION}`, "near-sandbox");
  if (!existsSync(bin)) throw new Error(`near-sandbox binary not found at ${bin} (set NEAR_SANDBOX_BIN_PATH)`);
  return bin;
}

/** A currently free TCP port on 127.0.0.1. */
export function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = net.createServer();
    s.unref();
    s.once("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => ok(p));
    });
  });
}

function runOnce(cmd: string, args: string[]): Promise<void> {
  return new Promise((ok, fail) => {
    const c = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    c.stderr!.setEncoding("utf8").on("data", (s: string) => {
      if (err.length < 8192) err += s;
    });
    c.once("error", fail);
    c.once("exit", (code) => (code === 0 ? ok() : fail(new Error(`${cmd} ${args.join(" ")} exited ${code}: ${err.trim()}`))));
  });
}

async function patchJson(path: string, patch: (o: Record<string, unknown>) => void): Promise<void> {
  const o = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  patch(o);
  await writeFile(path, JSON.stringify(o));
}

async function rpcReady(rpcUrl: string): Promise<true | undefined> {
  try {
    const r = await fetch(`${rpcUrl}/status`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) return undefined;
    const s = (await r.json()) as { sync_info?: { latest_block_height?: number } };
    return (s.sync_info?.latest_block_height ?? 0) > 0 ? true : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Initialises and starts a node in `homeDir` (must not exist yet or be empty).
 * @param o.rpcPort fixed RPC port (default: a free one)
 */
export async function startSandbox(o: { homeDir: string; rpcPort?: number; readyTimeoutMs?: number }): Promise<SandboxNode> {
  const bin = sandboxBinary();
  await mkdir(o.homeDir, { recursive: true, mode: 0o700 });
  await runOnce(bin, ["--home", o.homeDir, "init", "--fast"]);

  const rootKp = KeyPair.fromRandom("ed25519");
  const rootAccountId = DEFAULT_ACCOUNT_ID;
  await patchJson(join(o.homeDir, "genesis.json"), (g) => {
    const records = g.records;
    if (!Array.isArray(records) || typeof g.total_supply !== "string") throw new Error("unexpected genesis.json layout");
    g.total_supply = (BigInt(g.total_supply) + GENESIS_BALANCE).toString();
    // Long epochs: no epoch-boundary work (state snapshots, GC) while a stack runs, so the files under the
    // run directory stay stable (the no-retention scenario walks and reads all of them).
    g.epoch_length = EPOCH_LENGTH;
    records.push(
      { Account: { account_id: rootAccountId, account: { amount: GENESIS_BALANCE.toString(), locked: "0", code_hash: "11111111111111111111111111111111", storage_usage: 182 } } },
      { AccessKey: { account_id: rootAccountId, public_key: rootKp.getPublicKey().toString(), access_key: { nonce: 0, permission: "FullAccess" } } },
    );
  });
  await patchJson(join(o.homeDir, "config.json"), (c) => {
    const rpc = (c.rpc ?? {}) as Record<string, unknown>;
    rpc.limits_config = { json_payload_max_size: 10 * 1024 * 1024 };
    c.rpc = rpc;
    const store = (c.store ?? {}) as Record<string, unknown>;
    store.max_open_files = 3000;
    store.state_snapshot_config = { state_snapshot_type: "Disabled" };
    c.store = store;
    c.telemetry = { endpoints: [] };
  });

  const rpcPort = o.rpcPort ?? (await freePort());
  const netPort = await freePort();
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const proc: ManagedProcess = startManaged({
    name: "near-sandbox",
    cmd: bin,
    args: ["--home", o.homeDir, "run", "--rpc-addr", `127.0.0.1:${rpcPort}`, "--network-addr", `127.0.0.1:${netPort}`],
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: o.homeDir, RUST_LOG: "warn" },
    maxOutput: 256 * 1024,
    graceMs: 5000,
  });
  try {
    await waitFor(
      "near-sandbox RPC",
      async () => {
        if (proc.exited) throw new Error(`near-sandbox exited early:\n${proc.output().slice(-4000)}`);
        return rpcReady(rpcUrl);
      },
      o.readyTimeoutMs ?? 60_000,
      250,
    );
  } catch (e) {
    await proc.stop();
    throw e;
  }
  let stopped: Promise<void> | null = null;
  return {
    rpcUrl,
    homeDir: o.homeDir,
    rootAccountId,
    rootKey: rootKp.toString() as KeyPairString,
    output: () => proc.output(),
    stop: () => (stopped ??= proc.stop().then(() => undefined)),
  };
}
