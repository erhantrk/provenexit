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

/** `keyHash(x25519, ed25519)(32) ‖ nonce(32)` */
export function reportData(x25519: Uint8Array, ed25519: Uint8Array, nonce: Uint8Array): Uint8Array {
  requireBytes(nonce, 32, "E_BAD_INPUT", "nonce");
  return concatBytes(keyHash(x25519, ed25519), nonce);
}

/** `SHA256(utf8("PLR-v1/register") ‖ utf8(contractId))` */
export function registrationNonce(contractId: string): Uint8Array {
  return sha256(concatBytes(utf8("PLR-v1/register"), contractIdBytes(contractId)));
}
