/**
 * Entry point of the HONEST router bundle (dist/router.bundle.mjs). Started by the mock TDX host with its
 * configuration in the environment.
 */
import { loadConfig } from "./config.js";
import { HttpLlmClient } from "./llm.js";
import { Logger, codeOf } from "./log.js";
import { bootRouter, installProcessGuards, type RunningRouter } from "./main.js";

const log = new Logger("plr-router");
let running: RunningRouter | null = null;
installProcessGuards(log, () => running);
try {
  const cfg = loadConfig();
  running = await bootRouter(cfg, (port) => new HttpLlmClient(port, { apiKey: cfg.llmApiKey }), log);
} catch (e) {
  log.info("boot_failed", { code: codeOf(e) });
  process.exit(1);
}
