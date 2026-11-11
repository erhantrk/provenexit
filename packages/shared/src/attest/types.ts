import type { ParsedQuote, RootKind } from "../tdx/quote.js";
import type { TdxEvent } from "../tdx/eventlog.js";

/** Obtains a TDX quote over 64 bytes of report_data (dstack `GetQuote` semantics: no hashing). */
export interface Attester {
  getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }>;
}

/** Optional per-verification inputs (INTERFACES §3.1). MOCK mode ignores them. */
export interface VerifyContext {
  /** INTEL mode: canonical or raw collateral JSON (INTERFACES §1.2). */
  collateral?: unknown;
  /** INTEL mode: verification time in Unix seconds (default: `floor(clock() / 1000)`). */
  nowSecs?: number;
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
  /** @throws PlrError E_QUOTE_FORMAT / E_TEE_TYPE / E_QUOTE_SIG / E_TCB_STATUS / E_COLLATERAL */
  verify(quote: Uint8Array, ctx?: VerifyContext): ParsedQuote;
}
