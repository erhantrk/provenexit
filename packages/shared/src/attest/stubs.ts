/** Production attestation backends — placeholders for milestone 2. */
import { PlrError } from "../errors.js";
import type { TdxEvent } from "../tdx/eventlog.js";
import type { Attester } from "./types.js";

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
