/** Production attestation backends — placeholders for milestone 2. */
import { PlrError } from "../errors.js";
import { isValidP256Pub } from "./mock.js";
import type { ParsedQuote } from "../tdx/quote.js";
import type { TdxEvent } from "../tdx/eventlog.js";
import type { Attester, QuoteVerifier } from "./types.js";

/**
 * Real Intel TDX quotes via the dstack guest agent.
 *
 * Planned mapping: `new DstackClient(endpoint)` from `@phala/dstack-sdk`, then
 * `client.getQuote(reportData)` with the 64 raw report_data bytes (dstack does not hash them — identical to
 * SPEC §6.1). The SDK returns `{ quote: <hex>, event_log: <JSON string> }`: the quote hex is decoded with
 * `fromHex` (strict) and `event_log` is parsed and filtered to `imr == 3` events, whose shape matches
 * {@link TdxEvent} (dstack also measures `system-preparing`, `app-id`, `compose-hash`, `instance-id`,
 * `boot-mr-done` into RTMR3). Until implemented every call fails closed.
 */
export class DstackAttester implements Attester {
  constructor(_opts: { endpoint?: string } = {}) {}

  async getQuote(_reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }> {
    throw new PlrError("E_NOT_IMPLEMENTED", "DstackAttester");
  }
}

/**
 * Intel DCAP verification of real TDX v4 quotes.
 *
 * Planned mapping: `@phala/dcap-qvl` (>= 0.3.9) — fetch collateral for the quote (PCCS / Intel PCS),
 * `verify(quoteBytes, collateral, nowSeconds)`; require TCB status `UpToDate` (anything else fails closed
 * with E_QUOTE_SIG), check the PCK chain terminates at `rootPublicKey` (Intel SGX Root CA, 64-byte `x‖y`,
 * pinned and compared against the registry's INTEL root), then return `parseQuote(quote, "INTEL")`.
 * Until implemented every call fails closed.
 */
export class DcapQvlVerifier implements QuoteVerifier {
  readonly rootKind = "INTEL" as const;
  readonly #root: Uint8Array;

  constructor(rootPub: Uint8Array) {
    if (!isValidP256Pub(rootPub)) throw new PlrError("E_ROOT_UNTRUSTED", "invalid root public key");
    this.#root = rootPub.slice();
  }

  get rootPublicKey(): Uint8Array {
    return this.#root.slice();
  }

  verify(_quote: Uint8Array): ParsedQuote {
    throw new PlrError("E_NOT_IMPLEMENTED", "DcapQvlVerifier");
  }
}
