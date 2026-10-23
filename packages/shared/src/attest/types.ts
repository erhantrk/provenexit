import type { ParsedQuote, RootKind } from "../tdx/quote.js";
import type { TdxEvent } from "../tdx/eventlog.js";

/** Obtains a TDX quote over 64 bytes of report_data (dstack `GetQuote` semantics: no hashing). */
export interface Attester {
  getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }>;
}

/**
 * Verifies a quote's signature chain up to a fixed root.
 *
 * `rootPublicKey` (64-byte P-256 `x‖y`) is an addition to the SPEC §10 interface: `verifyAttestation`
 * requires it to prove that the verifier is pinned to the same root as the client config and the registry
 * (SPEC §9 step 3); a verifier that cannot state its root cannot be used (fail closed).
 */
export interface QuoteVerifier {
  readonly rootKind: RootKind;
  readonly rootPublicKey: Uint8Array;
  /** @throws PlrError E_QUOTE_FORMAT / E_TEE_TYPE / E_QUOTE_SIG */
  verify(quote: Uint8Array): ParsedQuote;
}
