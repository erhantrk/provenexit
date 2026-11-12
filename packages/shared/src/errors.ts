/**
 * Error codes of PLR-v1 (SPEC §2, §3, §6, §7, §9) and PLR-VPN-v1 (SPEC-VPN §8), plus a few library-internal codes.
 *
 * Error messages never contain request/response content: a `PlrError` carries only a code and an
 * optional static, content-free detail string.
 */
export const ERROR_CODES = [
  // encoding / generic input validation
  "E_BAD_HEX",
  "E_BAD_INPUT",
  "E_NOT_IMPLEMENTED",
  // router HTTP API (§6)
  "E_BAD_REQUEST",
  "E_TOO_LARGE",
  "E_NOT_ANCHORED",
  // receipt inclusion proof disagrees with the on-chain anchor (§8)
  "E_ANCHOR_MISMATCH",
  // verification (§9)
  "E_BAD_RESPONSE",
  "E_QUOTE_FORMAT",
  "E_TEE_TYPE",
  "E_ROOT_UNTRUSTED",
  "E_QUOTE_SIG",
  "E_DEBUG_TD",
  "E_REPORT_DATA_KEYS",
  "E_NONCE",
  "E_EVENT_LOG",
  "E_RTMR3",
  "E_COMPOSE_MISMATCH",
  "E_COMPOSE_NOT_ALLOWED",
  "E_OS_NOT_ALLOWED",
  "E_INSTANCE_NOT_REGISTERED",
  "E_REGISTRY_UNAVAILABLE",
  // streaming (§6.3, §9)
  "E_DECRYPT",
  "E_TRUNCATED",
  "E_RECEIPT_SIG",
  "E_RECEIPT_MISMATCH",
  "E_UPSTREAM",
  // registry contract (§7)
  "E_REPORT_DATA",
  "E_SEQ",
  "E_ANCHOR_SIG",
  // VPN exit (SPEC-VPN §8)
  "E_EGRESS_DENIED",
  "E_DNS",
  "E_CONNECT_FAILED",
  "E_TUNNEL_PROTOCOL",
  // two-hop operator organizations (SPEC-VPN §8, §10 rev 2)
  "E_OPERATOR_UNAPPROVED",
  "E_SAME_OPERATOR",
  // rev 1.4 registration evidence for registries that do not verify quotes on-chain (SPEC-CHAINS §2)
  "E_REGISTRATION_EVIDENCE",
  // INTEL / dstack mode (SPEC-TDX §0)
  "E_TCB_STATUS",
  "E_COMPOSE_POLICY",
  "E_COLLATERAL",
] as const;

export type PlrErrorCode = (typeof ERROR_CODES)[number];

const CODE_SET: ReadonlySet<string> = new Set(ERROR_CODES);

/** True if `code` is one of the known PLR error codes. */
export function isPlrErrorCode(code: unknown): code is PlrErrorCode {
  return typeof code === "string" && CODE_SET.has(code);
}

export class PlrError extends Error {
  readonly code: PlrErrorCode;

  /**
   * @param code   one of {@link ERROR_CODES}
   * @param detail optional static description. MUST NOT contain secrets, prompts or responses.
   */
  constructor(code: PlrErrorCode, detail?: string) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = "PlrError";
    this.code = code;
  }
}

/** True if `e` is a PlrError (optionally with the given code). */
export function isPlrError(e: unknown, code?: PlrErrorCode): e is PlrError {
  return e instanceof PlrError && (code === undefined || e.code === code);
}
