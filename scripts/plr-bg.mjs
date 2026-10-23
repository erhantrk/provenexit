#!/usr/bin/env node
/**
 * Runs a long-lived `plr` command (`plr vpn`, `plr proxy`) — the very same `runCli` as client/dist/cli.js — with a
 * signal-free stop, for scripts/demo.sh:
 *
 *   node scripts/plr-bg.mjs --stop-file <path> -- vpn
 *
 * It stops (gracefully: the CLI closes its listener and exits with the CLI's exit code) when <path> appears, or
 * when the process that started it is gone (re-parented), or on SIGINT/SIGTERM like the CLI itself.
 */
import { existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
if (argv[0] !== "--stop-file" || typeof argv[1] !== "string" || argv[1] === "" || sep !== 2) {
  process.stderr.write("usage: plr-bg.mjs --stop-file <path> -- <plr args…>\n");
  process.exit(2);
}
const stopFile = argv[1];
const cliArgs = argv.slice(3);
rmSync(stopFile, { force: true });

const { runCli } = await import(pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "client", "dist", "cli.js")).href);

const parent = process.ppid;
const untilStopped = () =>
  new Promise((resolve) => {
    const done = () => {
      clearInterval(t);
      resolve();
    };
    const t = setInterval(() => {
      if (existsSync(stopFile) || process.ppid !== parent) done();
    }, 250);
    process.once("SIGINT", done);
    process.once("SIGTERM", done);
  });

const io = { out: (s) => console.log(s), err: (s) => console.error(s) };
const code = await runCli(cliArgs, process.env, io, (s) => void process.stdout.write(s), undefined, untilStopped);
rmSync(stopFile, { force: true });
process.exit(code);
