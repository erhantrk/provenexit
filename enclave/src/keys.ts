/**
 * The router's per-boot key pairs (SPEC §5). Generated in memory at boot; the secret halves never leave this
 * object (no getters), they are only used through the operations below.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { keyHash, reportData, serverOpen, signReceipt, type Receipt } from "@plr/shared";

export class RouterKeys {
  readonly #xs: Uint8Array;
  readonly #es: Uint8Array;
  readonly x25519: Uint8Array;
  readonly ed25519: Uint8Array;
  readonly keyHash: Uint8Array;

  private constructor(xs: Uint8Array, es: Uint8Array) {
    this.#xs = xs;
    this.#es = es;
    this.x25519 = x25519.getPublicKey(xs);
    this.ed25519 = ed25519.getPublicKey(es);
    this.keyHash = keyHash(this.x25519, this.ed25519);
  }

  static generate(): RouterKeys {
    return new RouterKeys(x25519.utils.randomSecretKey(), ed25519.utils.randomSecretKey());
  }

  /** `key_hash ‖ nonce` (SPEC §5). */
  reportData(nonce: Uint8Array): Uint8Array {
    return reportData(this.x25519, this.ed25519, nonce);
  }

  /** Decrypts a request envelope (SPEC §6.3). @throws PlrError E_DECRYPT */
  open(p: { attNonce: Uint8Array; epk: Uint8Array; ct: Uint8Array }): { plaintext: Uint8Array; th: Uint8Array; kS2c: Uint8Array } {
    return serverOpen({ xs: this.#xs, xp: this.x25519, ep: this.ed25519, attNonce: p.attNonce, epk: p.epk, ct: p.ct });
  }

  signReceipt(r: Receipt): string {
    return signReceipt(r, this.#es);
  }

  /** Ed25519 signature over an arbitrary protocol message (used for the §7 anchor message). */
  sign(msg: Uint8Array): Uint8Array {
    return ed25519.sign(msg, this.#es);
  }
}
