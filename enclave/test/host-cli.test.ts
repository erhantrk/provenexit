// Regression for review finding "a host crash (uncaughtException / unhandledRejection) exits without cleanup": the
// host CLI ignores EPIPE on its own output (a closed log reader cannot crash the TD) and every fatal path tears the TD
// down — children stopped, private tdx-* dir removed — before exiting.
import { afterAll, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { generateRootSecret } from "../src/mock-tdx/host.js";
import { shortTmp } from "./short-tmp.js";

const ENCLAVE = resolve(import.meta.dirname, "..");
const CLI = join(ENCLAVE, "dist", "mock-tdx", "cli.js");
const COMPOSE = join(ENCLAVE, "dist", "vpn-exit", "vpn-honest-test", "app-compose.json");
mkdirSync(join(ENCLAVE, ".run"), { recursive: true });
const tmp = shortTmp("cli-");
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("plr-tdx-host launch: fail closed without orphans", () => {
  it("a log reader that goes away neither crashes the host nor leaves its private dir behind", async () => {
    const secret = join(tmp, "root.secret");
    await generateRootSecret(secret);
    const runDir = mkdtempSync(join(tmp, "run-"));
    const child = spawn(process.execPath, [CLI, "launch", "--compose", COMPOSE, "--run-dir", runDir, "--exit-port", "0"], {
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PLR_MOCK_ROOT_SECRET_FILE: secret },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const exited = new Promise<number | null>((r) => child.once("exit", (c) => r(c)));
    let stderr = "";
    child.stderr!.setEncoding("utf8").on("data", (s: string) => (stderr += s));
    try {
      // Read until the host has measured, then close our end: every later host write hits EPIPE.
      let out = "";
      await new Promise<void>((ok, ko) => {
        const t = setTimeout(() => ko(new Error(`no 'measured' line: ${out} ${stderr}`)), 30_000);
        child.stdout!.setEncoding("utf8").on("data", (s: string) => {
          out += s;
          if (out.includes("plr-host: measured ")) {
            clearTimeout(t);
            ok();
          }
        });
      });
      child.stdout!.destroy();

      // Where Unix sockets are not permitted (agent sandbox) the launch fails at the quote socket and must clean up;
      // elsewhere it comes up — keep it writing for a while (exit logs), then stop it like an operator would.
      const deadline = Date.now() + 60_000;
      let code: number | null | undefined;
      while (code === undefined && Date.now() < deadline) {
        const tdx = readdirSync(runDir).find((f) => f.startsWith("tdx-"));
        if (tdx && existsSync(join(runDir, tdx, "q.sock"))) {
          await sleep(3000);
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
          code = await Promise.race([exited, sleep(30_000).then(() => undefined)]);
          break;
        }
        code = await Promise.race([exited, sleep(100).then(() => undefined)]);
      }
      expect(code, "the host exited").not.toBeUndefined();
      expect(readdirSync(runDir), "private dir removed").toEqual([]);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
  }, 120_000);
});
