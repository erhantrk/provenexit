/** Encrypted, ordered response frames (SPEC §6.3). */
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { PlrError } from "../errors.js";
import { concatBytes, isBytes, isUint, u32be, u64be } from "../bytes.js";
import { TAG_LEN } from "./session.js";

function frameParams(kS2c: Uint8Array, th: Uint8Array, seq: number, fin: boolean): { nonce: Uint8Array; aad: Uint8Array } {
  if (!isBytes(kS2c) || kS2c.length !== 32 || !isBytes(th) || th.length !== 32 || !isUint(seq) || typeof fin !== "boolean") {
    throw new PlrError("E_DECRYPT", "bad frame parameters");
  }
  return { nonce: concatBytes(u32be(0), u64be(seq)), aad: concatBytes(th, Uint8Array.of(fin ? 1 : 0)) };
}

/** `ChaCha20-Poly1305(kS2c, nonce=u32be(0)‖u64be(seq), aad=th‖u8(fin), pt)` */
export function sealFrame(kS2c: Uint8Array, th: Uint8Array, seq: number, fin: boolean, pt: Uint8Array): Uint8Array {
  const { nonce, aad } = frameParams(kS2c, th, seq, fin);
  if (!isBytes(pt)) throw new PlrError("E_BAD_INPUT", "plaintext must be bytes");
  return chacha20poly1305(kS2c, nonce, aad).encrypt(pt);
}

/** @throws PlrError E_DECRYPT */
export function openFrame(kS2c: Uint8Array, th: Uint8Array, seq: number, fin: boolean, ct: Uint8Array): Uint8Array {
  const { nonce, aad } = frameParams(kS2c, th, seq, fin);
  if (!isBytes(ct) || ct.length < TAG_LEN) throw new PlrError("E_DECRYPT");
  try {
    return chacha20poly1305(kS2c, nonce, aad).decrypt(ct);
  } catch {
    throw new PlrError("E_DECRYPT");
  }
}

/**
 * Strictly ordered frame decryption. Frames must arrive as seq 0,1,2,… and the stream must end with a
 * `fin=1` frame. The first failure is sticky: every later `push`/`end` throws.
 */
export class FrameReader {
  readonly #k: Uint8Array;
  readonly #th: Uint8Array;
  #next = 0;
  #done = false;
  #failed = false;

  constructor(kS2c: Uint8Array, th: Uint8Array) {
    if (!isBytes(kS2c) || kS2c.length !== 32 || !isBytes(th) || th.length !== 32) {
      throw new PlrError("E_DECRYPT", "bad frame keys");
    }
    this.#k = kS2c.slice();
    this.#th = th.slice();
  }

  /** True once a valid `fin=1` frame was accepted. */
  get finished(): boolean {
    return this.#done;
  }

  /** @throws PlrError E_DECRYPT on wrong seq, failed authentication, data after fin, or after any failure */
  push(seq: number, ct: Uint8Array): { fin: boolean; plaintext: Uint8Array } {
    if (this.#failed || this.#done || seq !== this.#next) {
      this.#failed = true;
      throw new PlrError("E_DECRYPT", "unexpected frame");
    }
    for (const fin of [false, true]) {
      try {
        const plaintext = openFrame(this.#k, this.#th, seq, fin, ct);
        this.#next++;
        if (fin) this.#done = true;
        return { fin, plaintext };
      } catch {
        // try the other fin value; failure handled below
      }
    }
    this.#failed = true;
    throw new PlrError("E_DECRYPT");
  }

  /** Call when the transport ends. @throws PlrError E_TRUNCATED unless a valid final frame was received */
  end(): void {
    if (!this.#done) {
      this.#failed = true;
      throw new PlrError("E_TRUNCATED");
    }
  }
}
