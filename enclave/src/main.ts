/**
 * Router boot wiring: read the measured compose, generate keys in memory, self-check the quote service
 * against the compose, serve, then register + anchor if NEAR is configured.
 */
import { readFileSync } from "node:fs";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { equalBytes, parseQuote, toHex, verifyEventLog } from "@plr/shared";
import { Anchorer } from "./anchor.js";
import { MAX_COMPOSE_BYTES, parseCompose } from "./compose.js";
import type { RouterConfig } from "./config.js";
import { RouterKeys } from "./keys.js";
import type { LlmClient } from "./llm.js";
import { Logger, code, codeOf, hex, url } from "./log.js";
import { SocketAttester } from "./mock-tdx/attester.js";
import { NearRegistryWriter } from "./near.js";
import { ReceiptLog } from "./receipts.js";
import { createRouter } from "./router.js";

/** SPEC §11 default LLM ports. */
export const DEFAULT_LLM_PORT = { mock: 18081, "llama.cpp": 18080 } as const;

export interface RunningRouter {
  server: http.Server;
  url: string;
  keys: RouterKeys;
  anchorer: Anchorer | null;
  close(): Promise<void>;
}

/** Reads the compose file once (bounded). */
export function readCompose(path: string): Uint8Array {
  const buf = readFileSync(path);
  if (buf.length > MAX_COMPOSE_BYTES) throw new Error("E_COMPOSE_SIZE");
  return new Uint8Array(buf);
}

/**
 * Boots the router. `llmFor` receives the 127.0.0.1 port of the LLM and returns the client to use.
 * @throws on any boot self-check failure (the caller exits non-zero)
 */
export async function bootRouter(cfg: RouterConfig, llmFor: (port: number) => LlmClient, log = new Logger("plr-router")): Promise<RunningRouter> {
  const composeBytes = readCompose(cfg.composePath);
  const compose = parseCompose(composeBytes);
  const composeHash = sha256(composeBytes);
  const keys = RouterKeys.generate();
  const attester = new SocketAttester(cfg.tdxSocket);

  // Self-check: the quote service must measure exactly the compose we will publish.
  const probe = keys.reportData(randomBytes(32));
  const q = await attester.getQuote(probe);
  const parsed = parseQuote(q.quote);
  if (!equalBytes(parsed.report.reportData, probe)) throw new Error("E_REPORT_DATA");
  const measured = verifyEventLog(q.eventLog, parsed.report.rtmr[3]);
  if (!equalBytes(measured.composeHash, composeHash)) throw new Error("E_COMPOSE_MISMATCH");

  const receipts = new ReceiptLog();
  const llmPort = cfg.llmPort ?? DEFAULT_LLM_PORT[compose.llm.kind];
  const server = createRouter({ attester, keys, composeBytes, llm: llmFor(llmPort), receipts, log });
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(cfg.port, cfg.host, () => {
      server.off("error", fail);
      ok();
    });
  });
  const addr = server.address() as AddressInfo;
  const hostPart = addr.family === "IPv6" ? `[${addr.address}]` : addr.address;
  const routerUrl = `http://${hostPart}:${addr.port}`;
  log.info("listening", { url: url(routerUrl), key_hash: hex(toHex(keys.keyHash)), compose_hash: hex(toHex(composeHash)) });

  let anchorer: Anchorer | null = null;
  if (cfg.near) {
    const chain = new NearRegistryWriter(cfg.near);
    anchorer = new Anchorer({ chain, attester, keys, receipts, composeBytes, log, intervalMs: cfg.anchorIntervalMs });
    anchorer.start();
  } else {
    log.info("registration_disabled", cfg.nearConfigError ? { code: code("E_CONFIG") } : {});
  }

  return {
    server,
    url: routerUrl,
    keys,
    anchorer,
    close: () =>
      new Promise<void>((ok) => {
        anchorer?.stop();
        server.close(() => ok());
        server.closeAllConnections();
      }),
  };
}

/**
 * Process-level guards for the router process: uncaught errors print only a code (never a message or stack,
 * which could quote request content) and terminate; SIGTERM/SIGINT close cleanly.
 */
export function installProcessGuards(log: Logger, getRouter: () => RunningRouter | null): void {
  const fatal = (e: unknown) => {
    log.info("fatal", { code: codeOf(e) });
    process.exit(1);
  };
  process.on("uncaughtException", fatal);
  process.on("unhandledRejection", fatal);
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      const r = getRouter();
      const t = setTimeout(() => process.exit(0), 2000);
      t.unref();
      void (r ? r.close() : Promise.resolve()).finally(() => process.exit(0));
    });
  }
}
