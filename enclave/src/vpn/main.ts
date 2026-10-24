/**
 * VPN exit boot wiring (SPEC-VPN §2–§5): read the measured compose, generate keys in memory, self-check the
 * quote service against the compose, serve, then register + anchor on the VPN registry if one is configured (`PLR_CHAIN`, SPEC-CHAINS §4).
 *
 * Destination names are resolved only through the compose's `policy.dns.doh` resolvers (SPEC-VPN §6.1): the DoH
 * lookup is the one resolver handed to the exit, and nothing here accepts another (no system-resolver path).
 */
import type http from "node:http";
import type { AddressInfo } from "node:net";
import { sha256 } from "@noble/hashes/sha2.js";
import { toHex } from "@plr/shared";
import { Anchorer } from "../anchor.js";
import { selfCheckQuote } from "../boot.js";
import { readCompose, vpnPolicyOf } from "../compose.js";
import { Logger, code, hex, url } from "../log.js";
import { SocketAttester } from "../mock-tdx/attester.js";
import { createRegistryWriter } from "../chains.js";
import type { RegistryWriter } from "../registry-writer.js";
import type { ExitConfig } from "./config.js";
import type { Dialer } from "./egress.js";
import { createDohLookup } from "./doh.js";
import { createExit } from "./exit.js";
import { VpnKeys } from "./keys.js";
import { VpnReceiptLog } from "./receipts.js";

export interface RunningExit {
  server: http.Server;
  url: string;
  keys: VpnKeys;
  anchorer: Anchorer | null;
  close(): Promise<void>;
}

/**
 * Boots the exit. `dial` replaces the upstream dialer (only the ⚠️ evil build passes one).
 * @throws on any boot self-check failure (the caller exits non-zero)
 */
export async function bootExit(
  cfg: ExitConfig,
  o: { dial?: Dialer; log?: Logger; /** Called after the exit stopped serving for good (the caller exits non-zero). */ onFatal?: () => void } = {},
): Promise<RunningExit> {
  const log = o.log ?? new Logger("plr-vpn");
  const composeBytes = readCompose(cfg.composePath);
  // Strict + canonical: a `plr-vpn` compose or the `vpn` part of a `plr-combo` (SPEC-COMBO §1).
  const lookup = createDohLookup(vpnPolicyOf(composeBytes).dns.doh);
  const composeHash = sha256(composeBytes);
  const keys = VpnKeys.generate();
  const attester = new SocketAttester(cfg.tdxSocket);
  await selfCheckQuote(attester, keys, composeHash);

  const receipts = new VpnReceiptLog();
  let anchorer: Anchorer | null = null;
  let chain: RegistryWriter | null = null;
  const registrationQuote = (): Uint8Array | null => anchorer?.registrationQuote ?? null;
  const exit = createExit({ attester, keys, composeBytes, receipts, lookup, registrationQuote, ...(o.dial ? { dial: o.dial } : {}) });
  const server = exit.server;
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(cfg.port, cfg.host, () => {
      server.off("error", fail);
      ok();
    });
  });
  const addr = server.address() as AddressInfo;
  const hostPart = addr.family === "IPv6" ? `[${addr.address}]` : addr.address;
  const exitUrl = `http://${hostPart}:${addr.port}`;
  log.info("listening", { url: url(exitUrl), key_hash: hex(toHex(keys.keyHash)), compose_hash: hex(toHex(composeHash)) });

  const close = (): Promise<void> =>
    new Promise<void>((ok) => {
      anchorer?.stop();
      chain?.close?.();
      exit.destroyTunnels();
      server.close(() => ok());
      server.closeAllConnections();
    });

  if (cfg.registry) {
    chain = createRegistryWriter(cfg.registry);
    // The on-chain operator decides this exit's org_id (SPEC-VPN §10). The operator-bound registration quote (SPEC §5
    // rev 1.3) means only our own account can register our key; reading the operator back stays as defense in depth:
    // if the record names anyone else, two-hop clients would attribute us to that account's organization, so stop
    // serving (fail closed). A restart generates new keys.
    const onOperatorMismatch = (): void => {
      void close().finally(() => o.onFatal?.());
    };
    anchorer = new Anchorer({ chain, attester, keys, receipts, composeBytes, log, intervalMs: cfg.anchorIntervalMs, onOperatorMismatch });
    anchorer.start();
  } else {
    log.info("registration_disabled", cfg.nearConfigError ? { code: code("E_CONFIG") } : {});
  }

  return {
    server,
    url: exitUrl,
    keys,
    anchorer,
    close,
  };
}
