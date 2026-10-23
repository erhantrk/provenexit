/**
 * Entry point of the HONEST VPN exit bundle (dist/vpn-exit/<variant>/vpn.bundle.mjs). Started by the mock TDX host
 * with its configuration in the environment.
 */
import { installProcessGuards } from "../boot.js";
import { Logger, codeOf } from "../log.js";
import { loadExitConfig } from "./config.js";
import { bootExit, type RunningExit } from "./main.js";

const log = new Logger("plr-vpn");
let running: RunningExit | null = null;
installProcessGuards(log, () => running);
try {
  running = await bootExit(loadExitConfig(), { log });
} catch (e) {
  log.info("boot_failed", { code: codeOf(e) });
  process.exit(1);
}
