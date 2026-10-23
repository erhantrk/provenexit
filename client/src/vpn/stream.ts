/**
 * Client side of one PLR-VPN-v1 tunnel (SPEC-VPN §4) as a node `Duplex` ({@link VpnStream}).
 *
 * - Readable: authenticated s2c DATA in order; s2c FIN ⇒ clean EOF (`push(null)`). The transport ending or
 *   failing before the s2c FIN ⇒ the stream is destroyed with `PlrError("E_TRUNCATED")` — never a clean EOF.
 *   A frame that fails authentication / parsing ⇒ destroyed with `E_DECRYPT` / `E_TUNNEL_PROTOCOL`; nothing of
 *   that frame is delivered.
 * - Writable: each write becomes DATA frames of ≤ 16384 bytes; `end()` sends the c2s FIN.
 * - Backpressure both ways: a full readable buffer pauses the socket; a full socket buffer holds the write
 *   callback until `drain`.
 * - `receipt()`: after both FINs the exit sends RECEIPT; it is verified per SPEC-VPN §5 (Ed25519 under the
 *   attested key, `th` / `compose_hash` / `key_hash` equal ours, `ts_open_ms ≤ ts_close_ms`). Missing within the
 *   receipt timeout ⇒ rejects `E_TRUNCATED`.
 *
 * Nothing here logs; errors carry only a code.
 */
import { Duplex } from "node:stream";
import type { Socket } from "node:net";
import {
  FRAME,
  PlrError,
  TUNNEL,
  TunnelReader,
  TunnelWriter,
  equalBytes,
  fromHex,
  isPlrError,
  parseConnectErr,
  parseReceiptPayload,
  verifyVpnReceipt,
  type PlrErrorCode,
  type TunnelFrame,
  type VerifiedRouter,
  type VpnReceipt,
} from "@plr/shared";

export interface VpnReceiptResult {
  receipt: VpnReceipt;
  sig: string;
}

/** A proxied TCP connection through an attested exit (SPEC-VPN §9.2). Errors are `PlrError`s via `'error'`. */
export interface VpnStream extends Duplex {
  /** The exit's session receipt, verified per SPEC-VPN §5. @throws PlrError E_TRUNCATED / E_RECEIPT_SIG / E_RECEIPT_MISMATCH */
  receipt(): Promise<VpnReceiptResult>;
}

export interface TunnelStreamParams {
  socket: Socket;
  verified: VerifiedRouter;
  th: Uint8Array;
  kC2s: Uint8Array;
  kS2c: Uint8Array;
  /** Max wait for RECEIPT after both FINs (SPEC-VPN §4.3: ≤ 10 s). */
  receiptTimeoutMs: number;
  /** Socket inactivity limit (both directions). */
  idleTimeoutMs: number;
  /** Called once if the tunnel fails for a reason that should drop the cached attestation. */
  onFailure?: (code: PlrErrorCode) => void;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: PlrError) => void;
  settled: boolean;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: PlrError) => void;
  const d: Deferred<T> = {
    promise: new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    }),
    resolve: (v) => {
      if (d.settled) return;
      d.settled = true;
      resolve(v);
    },
    reject: (e) => {
      if (d.settled) return;
      d.settled = true;
      reject(e);
    },
    settled: false,
  };
  d.promise.catch(() => undefined); // never an unhandled rejection; callers get the same promise
  return d;
}

/** The receipt of a failed tunnel: authentication failures keep their code, everything else is a truncation. */
const receiptError = (err: PlrError): PlrError =>
  err.code === "E_DECRYPT" || err.code === "E_TUNNEL_PROTOCOL" ? err : new PlrError("E_TRUNCATED");

const plr = (e: unknown, fallback: PlrErrorCode): PlrError => (isPlrError(e) ? e : new PlrError(fallback));

/** Codes the exit may legitimately answer a CONNECT with; they say nothing about the exit's integrity. */
const BENIGN_CODES: ReadonlySet<PlrErrorCode> = new Set<PlrErrorCode>(["E_BAD_INPUT", "E_DNS", "E_EGRESS_DENIED", "E_CONNECT_FAILED"]);

export class TunnelStream extends Duplex implements VpnStream {
  readonly #socket: Socket;
  readonly #verified: VerifiedRouter;
  readonly #th: Uint8Array;
  readonly #reader: TunnelReader;
  readonly #writer: TunnelWriter;
  readonly #receiptTimeoutMs: number;
  readonly #onFailure: ((code: PlrErrorCode) => void) | undefined;
  /** `receipt`: the Duplex is done (both FINs, cleanly destroyed) but the socket waits for RECEIPT. */
  #state: "connecting" | "open" | "receipt" | "closed" = "connecting";
  #s2cFin = false;
  #c2sFin = false;
  #transportGone = false;
  #receiptTimer: NodeJS.Timeout | undefined;
  #pendingWrite: ((err?: Error | null) => void) | undefined;
  readonly #opened = deferred<void>();
  readonly #receipt = deferred<VpnReceiptResult>();

  constructor(p: TunnelStreamParams) {
    super({ allowHalfOpen: true, readableHighWaterMark: 64 * 1024, writableHighWaterMark: 64 * 1024 });
    this.#socket = p.socket;
    this.#verified = p.verified;
    this.#th = p.th.slice();
    this.#reader = new TunnelReader(p.kS2c, p.th, TUNNEL.DIR_S2C);
    this.#writer = new TunnelWriter(p.kC2s, p.th, TUNNEL.DIR_C2S);
    this.#receiptTimeoutMs = p.receiptTimeoutMs;
    this.#onFailure = p.onFailure;
    const s = this.#socket;
    s.setNoDelay(true);
    s.setTimeout(p.idleTimeoutMs, () => this.#transportClosed());
    s.on("data", (c: Buffer) => this.#onData(c));
    s.on("end", () => this.#onEnd());
    s.on("error", () => this.#transportClosed());
    s.on("close", () => this.#transportClosed());
    s.on("drain", () => this.#flushPendingWrite(null));
  }

  receipt(): Promise<VpnReceiptResult> {
    return this.#receipt.promise;
  }

  /**
   * Sends `hello ‖ CONNECT` and waits for CONNECT_OK (≤ `timeoutMs`). `head` = bytes the exit sent along with
   * the `101` response. @throws PlrError (the CONNECT_ERR code, or E_DECRYPT / E_TUNNEL_PROTOCOL / E_BAD_RESPONSE)
   */
  async open(hello: Uint8Array, connectPayload: Uint8Array, head: Uint8Array, timeoutMs: number): Promise<void> {
    const timer = setTimeout(() => this.#abort(new PlrError("E_TUNNEL_PROTOCOL", "no CONNECT reply")), timeoutMs);
    timer.unref?.();
    try {
      let connect: Uint8Array;
      try {
        connect = this.#writer.seal(FRAME.CONNECT, connectPayload);
      } catch (e) {
        throw plr(e, "E_BAD_INPUT");
      }
      if (!this.#socket.destroyed) this.#socket.write(Buffer.concat([hello, connect]));
      if (head.length > 0) this.#onData(head);
      if (this.#socket.destroyed) this.#transportClosed();
      await this.#opened.promise;
    } catch (e) {
      this.#abort(plr(e, "E_TUNNEL_PROTOCOL"));
      throw plr(e, "E_TUNNEL_PROTOCOL");
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------- inbound

  #done(): boolean {
    return this.#state === "closed" || this.#receipt.settled;
  }

  #onData(chunk: Uint8Array): void {
    if (this.#done()) return;
    let frames: TunnelFrame[];
    try {
      frames = this.#reader.push(chunk);
    } catch (e) {
      this.#abort(plr(e, "E_TUNNEL_PROTOCOL")); // E_DECRYPT / E_TUNNEL_PROTOCOL; nothing of that frame is delivered
      return;
    }
    for (const f of frames) {
      if (this.#done()) return; // an earlier frame of this chunk ended the tunnel
      try {
        this.#onFrame(f);
      } catch (e) {
        this.#abort(plr(e, "E_TUNNEL_PROTOCOL"));
        return;
      }
    }
  }

  #onFrame(f: TunnelFrame): void {
    const protocol = (): never => {
      throw new PlrError("E_TUNNEL_PROTOCOL", "unexpected frame");
    };
    if (this.#state === "receipt") {
      if (f.type !== FRAME.RECEIPT) protocol();
      this.#onReceipt(f.payload);
      return;
    }
    if (this.#state === "connecting") {
      if (f.type === FRAME.CONNECT_OK) {
        this.#state = "open";
        this.#opened.resolve();
        return;
      }
      if (f.type === FRAME.CONNECT_ERR) throw new PlrError(parseConnectErr(f.payload)); // E_TUNNEL_PROTOCOL if malformed
      return protocol();
    }
    switch (f.type) {
      case FRAME.DATA:
        if (this.#s2cFin) protocol();
        if (!this.push(Buffer.from(f.payload.buffer, f.payload.byteOffset, f.payload.byteLength))) this.#socket.pause();
        return;
      case FRAME.FIN:
        if (this.#s2cFin) protocol();
        this.#s2cFin = true;
        this.push(null);
        this.#maybeAwaitReceipt();
        return;
      case FRAME.RECEIPT:
        // The exit sends RECEIPT only after both FINs (SPEC-VPN §4.3 step 4).
        if (!this.#s2cFin || !this.#c2sFin) protocol();
        this.#onReceipt(f.payload);
        return;
      default:
        return protocol();
    }
  }

  #onReceipt(payload: Uint8Array): void {
    try {
      this.#receipt.resolve(this.#verifyReceipt(payload));
    } catch (e) {
      this.#receipt.reject(plr(e, "E_RECEIPT_SIG"));
    }
    this.#release(); // nothing may follow the receipt
  }

  #verifyReceipt(payload: Uint8Array): VpnReceiptResult {
    let p: { receipt: VpnReceipt; sig: string };
    try {
      p = parseReceiptPayload(payload);
    } catch {
      throw new PlrError("E_RECEIPT_SIG", "malformed receipt");
    }
    const r = p.receipt;
    if (!verifyVpnReceipt(r, p.sig, this.#verified.ed25519)) throw new PlrError("E_RECEIPT_SIG");
    const same = (hex: string, b: Uint8Array): boolean => equalBytes(fromHex(hex, 32), b);
    const ok =
      same(r.th, this.#th) &&
      same(r.compose_hash, this.#verified.composeHash) &&
      same(r.key_hash, this.#verified.keyHash) &&
      r.ts_open_ms <= r.ts_close_ms;
    if (!ok) throw new PlrError("E_RECEIPT_MISMATCH");
    return {
      receipt: { v: 1, th: r.th, compose_hash: r.compose_hash, key_hash: r.key_hash, seq: r.seq, ts_open_ms: r.ts_open_ms, ts_close_ms: r.ts_close_ms },
      sig: p.sig,
    };
  }

  #onEnd(): void {
    try {
      this.#reader.end(); // E_TRUNCATED if a partial frame is buffered
    } catch {
      /* handled below: the transport is gone either way */
    }
    this.#transportClosed();
  }

  /** Socket EOF, close, error or idle timeout. */
  #transportClosed(): void {
    if (this.#transportGone) return;
    this.#transportGone = true;
    if (this.#receipt.settled) return;
    if (this.#state === "connecting") {
      this.#abort(new PlrError("E_TUNNEL_PROTOCOL", "exit closed the tunnel before CONNECT reply"));
      return;
    }
    this.#receipt.reject(new PlrError("E_TRUNCATED", "no receipt"));
    // Before the authenticated s2c FIN, or with our own data not yet FIN'd: never a clean ending.
    if (this.#state === "open" && (!this.#s2cFin || !this.#c2sFin)) this.#fail(new PlrError("E_TRUNCATED"));
    else this.#release();
  }

  #maybeAwaitReceipt(): void {
    if (!this.#s2cFin || !this.#c2sFin || this.#receiptTimer !== undefined || this.#receipt.settled) return;
    this.#receiptTimer = setTimeout(() => {
      this.#receipt.reject(new PlrError("E_TRUNCATED", "receipt timeout"));
      this.#release();
    }, this.#receiptTimeoutMs);
    this.#receiptTimer.unref?.();
  }

  // ---------------------------------------------------------------- failure

  /** Fails the tunnel with `err`. Before CONNECT_OK nobody holds the stream: reject `open()` instead of emitting. */
  #abort(err: PlrError): void {
    if (this.#state === "connecting") {
      this.#state = "closed";
      if (!BENIGN_CODES.has(err.code)) this.#onFailure?.(err.code);
      this.#opened.reject(err);
      this.#receipt.reject(err);
      this.destroy();
      return;
    }
    this.#fail(err);
  }

  #fail(err: PlrError): void {
    if (this.#state === "closed") return;
    this.#onFailure?.(err.code);
    this.#receipt.reject(receiptError(err));
    if (this.#state === "receipt") this.#release(); // the Duplex already ended cleanly; only the receipt fails
    else this.destroy(err);
  }

  /** Drops the transport and wipes the tunnel keys. */
  #release(): void {
    clearTimeout(this.#receiptTimer);
    if (this.#state === "receipt") this.#state = "closed";
    this.#socket.destroy();
    this.#reader.wipe();
    this.#writer.wipe();
  }

  // ---------------------------------------------------------------- Duplex

  override _read(): void {
    if (this.#socket.isPaused()) this.#socket.resume();
  }

  override _write(chunk: Buffer, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    if (this.#transportGone || this.#state !== "open") {
      cb(new PlrError("E_TRUNCATED"));
      return;
    }
    let ok = true;
    try {
      for (let off = 0; off < chunk.length; off += TUNNEL.MAX_PAYLOAD) {
        const part = chunk.subarray(off, Math.min(off + TUNNEL.MAX_PAYLOAD, chunk.length));
        ok = this.#socket.write(this.#writer.seal(FRAME.DATA, part));
      }
    } catch (e) {
      cb(plr(e, "E_TUNNEL_PROTOCOL"));
      return;
    }
    if (ok) cb();
    else this.#pendingWrite = cb; // released on 'drain' (or on destroy)
  }

  override _final(cb: (err?: Error | null) => void): void {
    if (this.#transportGone || this.#state !== "open") {
      cb(new PlrError("E_TRUNCATED"));
      return;
    }
    try {
      this.#socket.write(this.#writer.seal(FRAME.FIN, new Uint8Array(0)));
    } catch (e) {
      cb(plr(e, "E_TUNNEL_PROTOCOL"));
      return;
    }
    this.#c2sFin = true;
    this.#maybeAwaitReceipt();
    cb();
  }

  override _destroy(err: Error | null, cb: (err?: Error | null) => void): void {
    this.#flushPendingWrite(err ?? new PlrError("E_TRUNCATED"));
    // A clean ending (both FINs exchanged) keeps the socket until the receipt arrives or times out.
    const awaitingReceipt = err === null && this.#state === "open" && this.#s2cFin && this.#c2sFin && !this.#receipt.settled && !this.#transportGone;
    if (awaitingReceipt) {
      this.#state = "receipt";
    } else {
      this.#state = "closed";
      this.#receipt.reject(isPlrError(err) ? receiptError(err) : new PlrError("E_TRUNCATED"));
      this.#release();
    }
    cb(err);
  }

  #flushPendingWrite(err: Error | null): void {
    const cb = this.#pendingWrite;
    this.#pendingWrite = undefined;
    cb?.(err);
  }
}
