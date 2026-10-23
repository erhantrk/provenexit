/** Key binding (SPEC §5). */
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { DOMAIN, concatBytes, requireBytes, utf8 } from "../bytes.js";

/** Max length accepted for a registry contract id (NEAR account ids are ≤ 64 chars). */
export const MAX_CONTRACT_ID_LEN = 128;
const CONTRACT_ID_RE = /^[\x21-\x7e]+$/;

/** Validates a contract/account id used inside signed or hashed messages. Returns its UTF-8 bytes. */
export function contractIdBytes(contractId: string): Uint8Array {
  if (typeof contractId !== "string" || contractId.length === 0 || contractId.length > MAX_CONTRACT_ID_LEN || !CONTRACT_ID_RE.test(contractId)) {
    throw new PlrError("E_BAD_INPUT", "bad contract id");
  }
  return utf8(contractId);
}

/** `SHA256(DOMAIN ‖ x25519(32) ‖ ed25519(32))` */
export function keyHash(x25519: Uint8Array, ed25519: Uint8Array): Uint8Array {
  requireBytes(x25519, 32, "E_BAD_INPUT", "x25519");
  requireBytes(ed25519, 32, "E_BAD_INPUT", "ed25519");
  return sha256(concatBytes(DOMAIN, x25519, ed25519));
}

/** Domain of session report_data (§5 rev 1.3): the raw client nonce never appears in a quote. */
export const SESSION_NONCE_DOMAIN = "PLR-v1/session-nonce";
/** Domain of registration nonces (§5 rev 1.3, operator-bound). */
export const REGISTRATION_NONCE_DOMAIN = "PLR-v1/register/2";
/** NEAR account ids are 2..64 bytes; §5 rev 1.3 bounds both contract and operator ids to 1..64 bytes. */
export const MAX_ACCOUNT_ID_BYTES = 64;

/** `SHA256(utf8("PLR-v1/session-nonce") ‖ clientNonce(32))` — the report_data[32:64] of a session quote. */
export function sessionNonceDigest(clientNonce: Uint8Array): Uint8Array {
  requireBytes(clientNonce, 32, "E_BAD_INPUT", "nonce");
  return sha256(concatBytes(utf8(SESSION_NONCE_DOMAIN), clientNonce));
}

/** Session report_data (§5 rev 1.3): `keyHash(x25519, ed25519) ‖ SHA256("PLR-v1/session-nonce" ‖ clientNonce)` */
export function reportData(x25519: Uint8Array, ed25519: Uint8Array, clientNonce: Uint8Array): Uint8Array {
  const digest = sessionNonceDigest(clientNonce);
  return concatBytes(keyHash(x25519, ed25519), digest);
}

/** `u8(len) ‖ utf8(id)` for a 1..64-byte printable-ASCII account id. @throws PlrError E_BAD_INPUT */
function accountIdField(id: string, what: string): Uint8Array {
  const b = contractIdBytes(id);
  if (b.length > MAX_ACCOUNT_ID_BYTES) throw new PlrError("E_BAD_INPUT", `${what} too long`);
  return concatBytes(Uint8Array.of(b.length), b);
}

/**
 * Operator-bound registration nonce (§5 rev 1.3):
 * `SHA256(utf8("PLR-v1/register/2") ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)`, c = contract id, o = operator account id.
 * @throws PlrError E_BAD_INPUT unless both ids are 1..64 bytes of printable ASCII
 */
export function registrationNonce(contractId: string, operatorId: string): Uint8Array {
  const c = accountIdField(contractId, "contract id");
  const o = accountIdField(operatorId, "operator id");
  return sha256(concatBytes(utf8(REGISTRATION_NONCE_DOMAIN), c, o));
}

/** Registration report_data (§5 rev 1.3): `keyHash(x25519, ed25519) ‖ registrationNonce(contractId, operatorId)` */
export function registrationReportData(x25519: Uint8Array, ed25519: Uint8Array, contractId: string, operatorId: string): Uint8Array {
  const nonce = registrationNonce(contractId, operatorId);
  return concatBytes(keyHash(x25519, ed25519), nonce);
}
