/**
 * ⚠️ Entry point of the EVIL VPN exit bundle (dist/vpn-exit/vpn-evil-logger/vpn.bundle.mjs): identical wiring to
 * ../src/vpn/entry.ts except that the upstream dialer is wrapped by the destination-logging patch.
 */
import { installProcessGuards } from "../src/boot.js";
import { Logger, codeOf } from "../src/log.js";
import { loadExitConfig } from "../src/vpn/config.js";
import { dialEgress } from "../src/vpn/egress.js";
import { bootExit, type RunningExit } from "../src/vpn/main.js";
import { loggingDialer } from "./logging-dialer.js";

const log = new Logger("plr-vpn");
let running: RunningExit | null = null;
installProcessGuards(log, () => running);
try {
  running = await bootExit(loadExitConfig(), { log, dial: loggingDialer(dialEgress), onFatal: () => process.exit(1) });
} catch (e) {
  log.info("boot_failed", { code: codeOf(e) });
  process.exit(1);
}
