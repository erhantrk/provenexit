/**
 * Per-boot key pairs of an enclave service (SPEC §5): X25519 `(xs, xp)` + Ed25519 `(es, ep)`, generated in memory
 * at boot. The secret halves never leave these objects (private fields, no getters); they are only used through
 * the operations below. `VpnKeys` (VPN exit, `vpn/keys.ts`) adds the tunnel and receipt operations on top of this
 * base.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { keyHash, registrationReportData, reportData } from "@plr/shared";

export class EnclaveKeys {
  readonly #xs: Uint8Array;
  readonly #es: Uint8Array;
  readonly x25519: Uint8Array;
  readonly ed25519: Uint8Array;
  readonly keyHash: Uint8Array;

  protected constructor(xs: Uint8Array, es: Uint8Array) {
    this.#xs = xs;
    this.#es = es;
    this.x25519 = x25519.getPublicKey(xs);
    this.ed25519 = ed25519.getPublicKey(es);
    this.keyHash = keyHash(this.x25519, this.ed25519);
  }

  /** Fresh random secrets `[xs, es]` for a subclass's `generate()`. */
  protected static freshSecrets(): [Uint8Array, Uint8Array] {
    return [x25519.utils.randomSecretKey(), ed25519.utils.randomSecretKey()];
  }

  /**
   * Session report_data (SPEC §5 rev 1.3): `key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ clientNonce)`. The only
   * report_data `/v1/attestation` ever quotes: the raw client nonce never appears in a quote, so no session quote can
   * double as a registration quote (that would need a SHA-256 preimage).
   */
  reportData(clientNonce: Uint8Array): Uint8Array {
    return reportData(this.x25519, this.ed25519, clientNonce);
  }

  /**
   * Registration report_data (SPEC §5 rev 1.3): `key_hash ‖ registration_nonce(contractId, operatorId)`, bound to the
   * registry and to the operator account that will submit it (the contract checks `current_account_id` /
   * `predecessor_account_id`). Only the instance's own anchorer asks for it. @throws PlrError E_BAD_INPUT
   */
  registrationReportData(contractId: string, operatorId: string): Uint8Array {
    return registrationReportData(this.x25519, this.ed25519, contractId, operatorId);
  }

  /** Ed25519 signature over an arbitrary protocol message (used for the §7 anchor message). */
  sign(msg: Uint8Array): Uint8Array {
    return ed25519.sign(msg, this.#es);
  }

  /** Runs `fn` with the X25519 secret (subclasses' protocol operations only). */
  protected withX25519Secret<T>(fn: (xs: Uint8Array) => T): T {
    return fn(this.#xs);
  }

  /** Runs `fn` with the Ed25519 secret (subclasses' protocol operations only). */
  protected withEd25519Secret<T>(fn: (es: Uint8Array) => T): T {
    return fn(this.#es);
  }
}
