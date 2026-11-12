/** X25519 key agreement for the tunnel key schedule (SPEC-VPN §4.1). */
import { x25519 } from "@noble/curves/ed25519.js";
import { PlrError } from "../errors.js";
import { isAllZero } from "../bytes.js";

/**
 * X25519 with any failure (invalid / low-order point, all-zero output) mapped to E_DECRYPT.
 * Internal (the VPN tunnel key schedule); not exported from the package index.
 */
export function ecdh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(sk, pk);
  } catch {
    throw new PlrError("E_DECRYPT", "key agreement failed");
  }
  if (shared.length !== 32 || isAllZero(shared)) throw new PlrError("E_DECRYPT", "low-order point");
  return shared;
}
