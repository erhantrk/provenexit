/** Boot helpers of the VPN exit (`vpn/main.ts`): the quote self-check and the process guards. */
import { randomBytes } from "@noble/hashes/utils.js";
import { equalBytes, parseQuote, verifyEventLog, verifyEventLogDstack, type Attester, type RootKind } from "@plr/shared";
import type { EnclaveKeys } from "./keys.js";
import { codeOf, type Logger } from "./log.js";

/**
 * Self-check at boot: the quote service must quote exactly our report_data and measure exactly the compose we
 * will publish (otherwise every client would refuse us anyway; fail before serving).
 * @throws Error E_REPORT_DATA / E_COMPOSE_MISMATCH (or the quote service's error)
 */
export async function selfCheckQuote(
  attester: Attester,
  keys: EnclaveKeys,
  composeHash: Uint8Array,
  rootKind: RootKind = "MOCK",
): Promise<void> {
  const probe = keys.reportData(randomBytes(32));
  const q = await attester.getQuote(probe);
  const parsed = parseQuote(q.quote, rootKind);
  if (!equalBytes(parsed.report.reportData, probe)) throw new Error("E_REPORT_DATA");
  const measured =
    rootKind === "INTEL" ? verifyEventLogDstack(q.eventLog, parsed.report.rtmr[3]) : verifyEventLog(q.eventLog, parsed.report.rtmr[3]);
  if (!equalBytes(measured.composeHash, composeHash)) throw new Error("E_COMPOSE_MISMATCH");
}

/**
 * Process-level guards for a service process: uncaught errors print only a code (never a message or stack,
 * which could quote request content) and terminate; SIGTERM/SIGINT close cleanly.
 */
export function installProcessGuards(log: Logger, getService: () => { close(): Promise<void> } | null): void {
  const fatal = (e: unknown) => {
    log.info("fatal", { code: codeOf(e) });
    process.exit(1);
  };
  process.on("uncaughtException", fatal);
  process.on("unhandledRejection", fatal);
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      const r = getService();
      const t = setTimeout(() => process.exit(0), 2000);
      t.unref();
      void (r ? r.close() : Promise.resolve()).finally(() => process.exit(0));
    });
  }
}
