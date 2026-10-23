/**
 * Router boot wiring: read the measured compose, generate keys in memory, self-check the quote service
 * against the compose, serve, then register + anchor if NEAR is configured.
 */
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { sha256 } from "@noble/hashes/sha2.js";
import { toHex } from "@plr/shared";
import { Anchorer } from "./anchor.js";
import { installProcessGuards, selfCheckQuote } from "./boot.js";
import { parseCompose, readCompose } from "./compose.js";
import type { RouterConfig } from "./config.js";
import { RouterKeys } from "./keys.js";
import type { LlmClient } from "./llm.js";
import { Logger, code, hex, url } from "./log.js";
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

export { readCompose };

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

  await selfCheckQuote(attester, keys, composeHash);

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

export { installProcessGuards };
