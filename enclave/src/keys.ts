/**
 * Per-boot key pairs of an enclave service (SPEC §5): X25519 `(xs, xp)` + Ed25519 `(es, ep)`, generated in memory
 * at boot. The secret halves never leave these objects (private fields, no getters); they are only used through
 * the operations below. `RouterKeys` (LLM router) and `VpnKeys` (VPN exit, `vpn/keys.ts`) add their protocol's
 * operations on top of the common base.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { keyHash, reportData, serverOpen, signReceipt, type Receipt } from "@plr/shared";

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

  /** `key_hash ‖ nonce` (SPEC §5). */
  reportData(nonce: Uint8Array): Uint8Array {
    return reportData(this.x25519, this.ed25519, nonce);
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

export class RouterKeys extends EnclaveKeys {
  static generate(): RouterKeys {
    return new RouterKeys(...EnclaveKeys.freshSecrets());
  }

  /** Decrypts a request envelope (SPEC §6.3). @throws PlrError E_DECRYPT */
  open(p: { attNonce: Uint8Array; epk: Uint8Array; ct: Uint8Array }): { plaintext: Uint8Array; th: Uint8Array; kS2c: Uint8Array } {
    return this.withX25519Secret((xs) => serverOpen({ xs, xp: this.x25519, ep: this.ed25519, attNonce: p.attNonce, epk: p.epk, ct: p.ct }));
  }

  signReceipt(r: Receipt): string {
    return this.withEd25519Secret((es) => signReceipt(r, es));
  }
}
