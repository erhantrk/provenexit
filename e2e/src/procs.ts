/**
 * Child-process supervision for the e2e harness and the dev stack.
 *
 * Every long-running program (near-sandbox, the mock TDX host and through it the VPN exit) is started
 * under a tiny Node "lifeline" wrapper that is the leader of its OWN process group, so the whole subtree can be
 * signalled at once:
 *
 *  - `stop()` sends SIGTERM to the group (graceful: the mock host stops the exit and removes its private
 *    dir), waits at most `timeoutMs` (default 10 s), then SIGKILLs the group and sweeps any straggler.
 *  - The lifeline's stdin is a pipe from this process. When this process goes away for ANY reason (normal exit,
 *    crash, SIGKILL of a vitest worker) the pipe reaches EOF; the lifeline then SIGTERMs its child and, after its
 *    grace period, SIGKILLs its whole group. If its child exits on its own, the lifeline terminates whatever is
 *    left in the group before exiting. So nothing is ever leaked, even when no JS cleanup code gets to run.
 */
import { spawn, type ChildProcess } from "node:child_process";

/** Default bound for a graceful stop before the group is SIGKILLed. */
export const STOP_TIMEOUT_MS = 10_000;

/** Runs as `node -e LIFELINE <cmd> <args...>` (CommonJS, no dependencies); process-group leader. */
const LIFELINE = `
"use strict";
const { spawn } = require("node:child_process");
const [cmd, ...args] = process.argv.slice(1);
const grace = Number(process.env.PLR_LIFELINE_GRACE_MS || "8000");
delete process.env.PLR_LIFELINE_GRACE_MS;
const group = (sig) => { try { process.kill(-process.pid, sig); } catch {} };
const c = spawn(cmd, args, { stdio: ["ignore", "inherit", "inherit"] });
let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  try { c.kill("SIGTERM"); } catch {}
  setTimeout(() => group("SIGKILL"), grace).unref();
};
process.stdin.on("end", stop);
process.stdin.on("close", stop);
process.stdin.on("error", stop);
process.stdin.resume();
for (const s of ["SIGTERM", "SIGINT", "SIGHUP"]) process.on(s, stop);
c.on("error", () => process.exit(127));
c.on("exit", (code, sig) => {
  // Child gone: terminate anything it left behind in our group (we ignore our own SIGTERM now), then exit.
  for (const s of ["SIGTERM", "SIGINT", "SIGHUP"]) process.removeAllListeners(s);
  process.on("SIGTERM", () => {});
  group("SIGTERM");
  process.exit(code === null ? 128 + (sig === "SIGKILL" ? 9 : 15) : code);
});
`;

/** Keeps the newest `max` characters of a stream (older text is dropped and counted). */
class TextBuffer {
  #chunks: string[] = [];
  #len = 0;
  #dropped = 0;
  constructor(readonly max: number) {}
  push(s: string): void {
    this.#chunks.push(s);
    this.#len += s.length;
    while (this.#len > this.max && this.#chunks.length > 1) {
      const first = this.#chunks.shift()!;
      this.#len -= first.length;
      this.#dropped += first.length;
    }
  }
  text(): string {
    const t = this.#chunks.join("");
    this.#chunks = [t];
    return this.#dropped > 0 ? `[… ${this.#dropped} chars dropped …]\n${t}` : t;
  }
}

export interface ManagedOptions {
  /** Short label for diagnostics. */
  name: string;
  cmd: string;
  args: readonly string[];
  /** Full environment of the child (nothing is inherited implicitly). */
  env: Record<string, string>;
  cwd?: string;
  /** Called with every output chunk (stdout and stderr, utf8). */
  onOutput?: (chunk: string) => void;
  /** Max retained output characters (default 64 MiB; tests search it for leaked secrets). */
  maxOutput?: number;
  /** Lifeline grace between SIGTERM to its child and SIGKILL to its group (default 8 s). */
  graceMs?: number;
}

export interface ManagedProcess {
  readonly name: string;
  readonly pid: number | undefined;
  /** stdout + stderr of the child (and of everything it forwards). */
  output(): string;
  /** True once the lifeline has exited. */
  readonly exited: boolean;
  /** Resolves with the exit code once the lifeline (and thus its child) has exited. */
  readonly done: Promise<number>;
  /**
   * SIGTERM to the whole process group, wait ≤ `timeoutMs` (default 10 s), then SIGKILL the group.
   * Idempotent; always resolves within ≈ `timeoutMs` + 3 s.
   */
  stop(timeoutMs?: number): Promise<number>;
}

interface Live {
  child: ChildProcess;
  signalGroup(sig: NodeJS.Signals): void;
}
const live = new Set<Live>();
let exitHookInstalled = false;

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  // Synchronous best effort; the lifeline pipe reaching EOF covers every other way of dying.
  process.once("exit", () => {
    for (const l of live) l.signalGroup("SIGTERM");
  });
}

/** Sends `sig` to every managed process group still alive (emergency teardown, synchronous). */
export function signalAllManaged(sig: NodeJS.Signals): void {
  for (const l of live) l.signalGroup(sig);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms).unref());

/** Starts `cmd args` under a lifeline (own process group) tied to this process. */
export function startManaged(o: ManagedOptions): ManagedProcess {
  installExitHook();
  const buf = new TextBuffer(o.maxOutput ?? 64 * 1024 * 1024);
  const child = spawn(process.execPath, ["-e", LIFELINE, o.cmd, ...o.args], {
    stdio: ["pipe", "pipe", "pipe"],
    detached: true, // → process-group leader (its stdin pipe still ties it to us)
    env: { ...o.env, PLR_LIFELINE_GRACE_MS: String(o.graceMs ?? 8000) },
    ...(o.cwd !== undefined ? { cwd: o.cwd } : {}),
  });
  const pgid = child.pid;
  const signalGroup = (sig: NodeJS.Signals) => {
    try {
      if (pgid !== undefined) process.kill(-pgid, sig);
    } catch {
      // ESRCH: the whole group is gone
    }
  };
  const entry: Live = { child, signalGroup };
  live.add(entry);
  const onChunk = (s: string) => {
    buf.push(s);
    o.onOutput?.(s);
  };
  child.stdout!.setEncoding("utf8").on("data", onChunk);
  child.stderr!.setEncoding("utf8").on("data", onChunk);
  child.stdin!.on("error", () => undefined);
  let exited = false;
  const done = new Promise<number>((ok) => {
    const finish = (code: number) => {
      exited = true;
      live.delete(entry);
      ok(code);
    };
    child.once("error", () => finish(127));
    child.once("exit", (code) => finish(code ?? 1));
  });

  let stopping: Promise<number> | null = null;
  const stop = (timeoutMs = STOP_TIMEOUT_MS): Promise<number> =>
    (stopping ??= (async () => {
      if (!exited) {
        signalGroup("SIGTERM");
        const graceful = await Promise.race([done.then(() => true), sleep(timeoutMs).then(() => false)]);
        if (!graceful) {
          signalGroup("SIGKILL");
          await Promise.race([done, sleep(3000)]);
        }
      }
      // Sweep: nothing of this subtree may survive (no-op when the group is already empty).
      signalGroup("SIGKILL");
      return exited ? done : 137;
    })());

  return {
    name: o.name,
    pid: child.pid,
    output: () => buf.text(),
    get exited() {
      return exited;
    },
    done,
    stop,
  };
}

/** Polls `pred` every `everyMs` until it returns a value (not undefined) or the deadline passes. */
export async function waitFor<T>(what: string, pred: () => T | undefined | Promise<T | undefined>, timeoutMs: number, everyMs = 100): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await pred();
    if (v !== undefined) return v;
    if (Date.now() > deadline) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, everyMs));
  }
}
