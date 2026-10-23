/**
 * Tunnel frames (SPEC-VPN §4.2): `u32be(len) ‖ ct`,
 * `ct = ChaCha20-Poly1305(k_dir, nonce = u32be(dir) ‖ u64be(seq), aad = th ‖ u8(dir), u8(type) ‖ payload)`.
 *
 * Errors never carry frame content: only a code and a static detail.
 */
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { PlrError, isPlrError } from "../errors.js";
import { concatBytes, isBytes, u32be, u64be } from "../bytes.js";
import { TUNNEL, frameAllowed, isTunnelDir, type TunnelDir } from "./constants.js";

export interface TunnelFrame {
  type: number;
  payload: Uint8Array;
}

/** Highest per-direction sequence number we will ever use (well below u64 max; a tunnel never gets close). */
const MAX_SEQ = Number.MAX_SAFE_INTEGER;
const LEN_BYTES = 4;

function checkParams(key: unknown, th: unknown, dir: unknown): { key: Uint8Array; th: Uint8Array; dir: TunnelDir } {
  if (!isBytes(key) || key.length !== 32) throw new PlrError("E_BAD_INPUT", "tunnel key must be 32 bytes");
  if (!isBytes(th) || th.length !== 32) throw new PlrError("E_BAD_INPUT", "th must be 32 bytes");
  if (!isTunnelDir(dir)) throw new PlrError("E_BAD_INPUT", "bad direction");
  return { key: key.slice(), th: th.slice(), dir };
}

function nonceFor(dir: TunnelDir, seq: number): Uint8Array {
  return concatBytes(u32be(dir), u64be(seq));
}

/** Seals frames of one direction with strictly increasing `seq` from 0. */
export class TunnelWriter {
  readonly #key: Uint8Array;
  readonly #aad: Uint8Array;
  readonly #dir: TunnelDir;
  #seq = 0;
  #closed = false;

  constructor(key: Uint8Array, th: Uint8Array, dir: 1 | 2) {
    const p = checkParams(key, th, dir);
    this.#key = p.key;
    this.#dir = p.dir;
    this.#aad = concatBytes(p.th, Uint8Array.of(p.dir));
  }

  /** Number of frames sealed so far (= seq of the next frame). */
  get seq(): number {
    return this.#seq;
  }

  /**
   * @returns wire bytes `u32be(len) ‖ ct`
   * @throws PlrError E_BAD_INPUT for an unknown type, a type not allowed in this direction, or a payload
   *         length outside the type's bounds (e.g. above {@link TUNNEL.MAX_PAYLOAD}); E_TUNNEL_PROTOCOL once wiped
   */
  seal(type: number, payload: Uint8Array): Uint8Array {
    if (this.#closed) throw new PlrError("E_TUNNEL_PROTOCOL", "writer closed");
    if (!isBytes(payload)) throw new PlrError("E_BAD_INPUT", "payload must be bytes");
    if (!Number.isInteger(type) || !frameAllowed(type, this.#dir, payload.length)) {
      throw new PlrError("E_BAD_INPUT", "frame type or payload length not allowed");
    }
    if (this.#seq > MAX_SEQ) throw new PlrError("E_TUNNEL_PROTOCOL", "sequence exhausted");
    const pt = new Uint8Array(1 + payload.length);
    pt[0] = type;
    pt.set(payload, 1);
    const ct = chacha20poly1305(this.#key, nonceFor(this.#dir, this.#seq), this.#aad).encrypt(pt);
    pt.fill(0);
    this.#seq++;
    return concatBytes(u32be(ct.length), ct);
  }

  /** Zeroes the key; every later `seal` throws. */
  wipe(): void {
    this.#closed = true;
    this.#key.fill(0);
  }
}

/**
 * Streaming, strictly ordered frame parser/decryptor for one direction. Accepts any chunking.
 *
 * - The length header alone decides: a length outside `[MIN_FRAME_LEN, MAX_FRAME_LEN]` is rejected
 *   (E_TUNNEL_PROTOCOL) before any body byte is buffered, so at most `4 + MAX_FRAME_LEN` bytes are ever held.
 * - Authentication failure (tamper, reorder, replay, reflection, wrong key/th) ⇒ E_DECRYPT; nothing of that
 *   frame — nor of any later frame in the same `push` — is returned.
 * - Unknown type, a type not allowed in this direction, or a bad payload length for the type ⇒ E_TUNNEL_PROTOCOL.
 * - The first error poisons the reader: every later `push`/`end` throws, and the key is wiped.
 */
export class TunnelReader {
  readonly #key: Uint8Array;
  readonly #aad: Uint8Array;
  readonly #dir: TunnelDir;
  #seq = 0;
  readonly #hdr = new Uint8Array(LEN_BYTES);
  #hdrFill = 0;
  #body: Uint8Array | null = null;
  #bodyFill = 0;
  #poison: PlrError["code"] | null = null;
  #ended = false;

  constructor(key: Uint8Array, th: Uint8Array, dir: 1 | 2) {
    const p = checkParams(key, th, dir);
    this.#key = p.key;
    this.#dir = p.dir;
    this.#aad = concatBytes(p.th, Uint8Array.of(p.dir));
  }

  /** Number of frames accepted so far (= expected seq of the next frame). */
  get seq(): number {
    return this.#seq;
  }

  /** True if a partial frame is buffered. */
  get pending(): boolean {
    return this.#hdrFill > 0 || this.#body !== null;
  }

  push(chunk: Uint8Array): TunnelFrame[] {
    this.#usable();
    try {
      if (!isBytes(chunk)) throw new PlrError("E_BAD_INPUT", "chunk must be bytes");
      const out: TunnelFrame[] = [];
      let off = 0;
      while (off < chunk.length) {
        if (this.#body === null) {
          const take = Math.min(LEN_BYTES - this.#hdrFill, chunk.length - off);
          this.#hdr.set(chunk.subarray(off, off + take), this.#hdrFill);
          this.#hdrFill += take;
          off += take;
          if (this.#hdrFill === LEN_BYTES) {
            const len = new DataView(this.#hdr.buffer).getUint32(0, false);
            if (len < TUNNEL.MIN_FRAME_LEN || len > TUNNEL.MAX_FRAME_LEN) {
              throw new PlrError("E_TUNNEL_PROTOCOL", "bad frame length");
            }
            this.#body = new Uint8Array(len);
            this.#bodyFill = 0;
            this.#hdrFill = 0;
          }
        } else {
          const take = Math.min(this.#body.length - this.#bodyFill, chunk.length - off);
          this.#body.set(chunk.subarray(off, off + take), this.#bodyFill);
          this.#bodyFill += take;
          off += take;
          if (this.#bodyFill === this.#body.length) {
            const ct = this.#body;
            this.#body = null;
            this.#bodyFill = 0;
            out.push(this.#open(ct));
          }
        }
      }
      return out;
    } catch (e) {
      throw this.#fail(e);
    }
  }

  /** Call when the transport ends. @throws PlrError E_TRUNCATED if a partial frame is buffered */
  end(): void {
    this.#usable();
    if (this.pending) throw this.#fail(new PlrError("E_TRUNCATED", "partial frame at end of stream"));
    this.#ended = true;
  }

  /** Zeroes the key and buffers; every later call throws. */
  wipe(): void {
    if (this.#poison === null) this.#poison = "E_TUNNEL_PROTOCOL";
    this.#clear();
  }

  #usable(): void {
    if (this.#poison !== null) throw new PlrError(this.#poison, "tunnel reader failed earlier");
    if (this.#ended) throw new PlrError("E_TUNNEL_PROTOCOL", "tunnel reader ended");
  }

  #open(ct: Uint8Array): TunnelFrame {
    if (this.#seq > MAX_SEQ) throw new PlrError("E_TUNNEL_PROTOCOL", "sequence exhausted");
    let pt: Uint8Array;
    try {
      pt = chacha20poly1305(this.#key, nonceFor(this.#dir, this.#seq), this.#aad).decrypt(ct);
    } catch {
      throw new PlrError("E_DECRYPT");
    }
    const type = pt[0]!;
    if (!frameAllowed(type, this.#dir, pt.length - 1)) {
      pt.fill(0);
      throw new PlrError("E_TUNNEL_PROTOCOL", "frame type or payload length not allowed");
    }
    this.#seq++;
    return { type, payload: pt.slice(1) };
  }

  #fail(e: unknown): PlrError {
    const err = isPlrError(e) ? e : new PlrError("E_TUNNEL_PROTOCOL");
    this.#poison = err.code;
    this.#clear();
    return err;
  }

  #clear(): void {
    this.#key.fill(0);
    this.#hdr.fill(0);
    this.#body?.fill(0);
    this.#body = null;
    this.#hdrFill = 0;
    this.#bodyFill = 0;
  }
}
