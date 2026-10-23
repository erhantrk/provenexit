/**
 * SOCKS5 (RFC 1928) server-side codec: greeting, CONNECT request, reply; plus the SPEC-VPN §8 REP mapping.
 * Pure parsers over a byte buffer: `null` means "need more bytes"; malformed input throws E_BAD_INPUT.
 */
import { PlrError } from "../errors.js";
import { isBytes } from "../bytes.js";
import { formatIpv4, formatIpv6 } from "./ip.js";

export const SOCKS = Object.freeze({
  VERSION: 5,
  METHOD_NO_AUTH: 0x00,
  METHOD_NONE_ACCEPTABLE: 0xff,
  CMD_CONNECT: 1,
  CMD_BIND: 2,
  CMD_UDP_ASSOCIATE: 3,
  ATYP_IPV4: 1,
  ATYP_DOMAIN: 3,
  ATYP_IPV6: 4,
} as const);

/** RFC 1928 REP values used by PLR. */
export const SOCKS_REP = Object.freeze({
  SUCCEEDED: 0x00,
  GENERAL_FAILURE: 0x01,
  NOT_ALLOWED: 0x02,
  HOST_UNREACHABLE: 0x04,
  CONNECTION_REFUSED: 0x05,
  COMMAND_NOT_SUPPORTED: 0x07,
  ATYP_NOT_SUPPORTED: 0x08,
} as const);

export interface SocksRequest {
  consumed: number;
  cmd: number;
  atyp: "ipv4" | "domain" | "ipv6";
  host: string;
  port: number;
}

const bad = (detail: string): never => {
  throw new PlrError("E_BAD_INPUT", detail);
};

function requireBuf(b: unknown): Uint8Array {
  if (!isBytes(b)) bad("socks input must be bytes");
  return b as Uint8Array;
}

/** `VER(5) NMETHODS(≥1) METHODS…` → `{consumed, methods}` | null. @throws PlrError E_BAD_INPUT */
export function parseSocksGreeting(b: Uint8Array): { consumed: number; methods: number[] } | null {
  requireBuf(b);
  if (b.length >= 1 && b[0] !== SOCKS.VERSION) bad("socks version");
  if (b.length < 2) return null;
  const n = b[1]!;
  if (n === 0) bad("socks: no methods");
  if (b.length < 2 + n) return null;
  return { consumed: 2 + n, methods: Array.from(b.subarray(2, 2 + n)) };
}

/**
 * `VER(5) CMD RSV(0) ATYP DST.ADDR DST.PORT` → request | null. Any CMD is returned (the caller replies 0x07 for
 * non-CONNECT). IPv6 hosts in RFC 5952 form; domain bytes verbatim (one char per byte; validated later by
 * `validateDestination`). Trailing bytes are left unconsumed.
 * @throws PlrError E_BAD_INPUT (wrong VER, RSV ≠ 0, empty domain, unknown ATYP — the caller replies 0x08 for the latter)
 */
export function parseSocksRequest(b: Uint8Array): SocksRequest | null {
  requireBuf(b);
  if (b.length >= 1 && b[0] !== SOCKS.VERSION) bad("socks version");
  if (b.length >= 3 && b[2] !== 0) bad("socks reserved byte");
  if (b.length < 4) return null;
  const cmd = b[1]!;
  const atypByte = b[3]!;
  let atyp: SocksRequest["atyp"];
  let host: string;
  let off: number;
  switch (atypByte) {
    case SOCKS.ATYP_IPV4:
      if (b.length < 4 + 4 + 2) return null;
      atyp = "ipv4";
      host = formatIpv4(b.subarray(4, 8));
      off = 8;
      break;
    case SOCKS.ATYP_IPV6:
      if (b.length < 4 + 16 + 2) return null;
      atyp = "ipv6";
      host = formatIpv6(b.subarray(4, 20));
      off = 20;
      break;
    case SOCKS.ATYP_DOMAIN: {
      if (b.length < 5) return null;
      const n = b[4]!;
      if (n === 0) bad("socks: empty domain");
      if (b.length < 5 + n + 2) return null;
      atyp = "domain";
      host = String.fromCharCode(...b.subarray(5, 5 + n)); // n ≤ 255: safe spread
      off = 5 + n;
      break;
    }
    default:
      return bad("socks address type");
  }
  const port = (b[off]! << 8) | b[off + 1]!;
  return { consumed: off + 2, cmd, atyp, host, port };
}

/** `VER(5) REP RSV(0) ATYP(1) BND.ADDR(0.0.0.0) BND.PORT(0)` — 10 bytes. @throws PlrError E_BAD_INPUT */
export function encodeSocksReply(rep: number): Uint8Array {
  if (!Number.isInteger(rep) || rep < 0 || rep > 0xff) bad("socks reply code");
  return Uint8Array.of(SOCKS.VERSION, rep, 0, SOCKS.ATYP_IPV4, 0, 0, 0, 0, 0, 0);
}

/** SPEC §9 attestation/registry verification codes (all map to "not allowed by ruleset"). */
const VERIFICATION_CODES: ReadonlySet<string> = new Set([
  "E_BAD_RESPONSE", "E_QUOTE_FORMAT", "E_TEE_TYPE", "E_ROOT_UNTRUSTED", "E_QUOTE_SIG", "E_DEBUG_TD",
  "E_REPORT_DATA_KEYS", "E_NONCE", "E_EVENT_LOG", "E_RTMR3", "E_COMPOSE_MISMATCH", "E_COMPOSE_NOT_ALLOWED",
  "E_OS_NOT_ALLOWED", "E_INSTANCE_NOT_REGISTERED", "E_REGISTRY_UNAVAILABLE",
]);

/** Policy refusals that also map to "not allowed by ruleset" (SPEC-VPN §8, rev 2). */
const POLICY_CODES: ReadonlySet<string> = new Set(["E_EGRESS_DENIED", "E_OPERATOR_UNAPPROVED", "E_SAME_OPERATOR"]);

/** SPEC-VPN §8 mapping of a PLR error code (null = success) to the RFC 1928 REP byte. */
export function socksReplyFor(code: string | null): number {
  if (code === null) return SOCKS_REP.SUCCEEDED;
  if (typeof code !== "string") return SOCKS_REP.GENERAL_FAILURE;
  if (POLICY_CODES.has(code) || VERIFICATION_CODES.has(code)) return SOCKS_REP.NOT_ALLOWED;
  if (code === "E_DNS") return SOCKS_REP.HOST_UNREACHABLE;
  if (code === "E_CONNECT_FAILED") return SOCKS_REP.CONNECTION_REFUSED;
  return SOCKS_REP.GENERAL_FAILURE;
}
