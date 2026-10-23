/**
 * Client side of one PLR-VPN tunnel (SPEC-VPN §4, rev 2) as a node `Duplex` ({@link VpnStream}).
 *
 * - Handshake v2 (§4.1): `open()` sends `hello = u8(2) ‖ att_nonce ‖ epk_c` (fresh ephemeral), reads the exit's
 *   33-byte `server_hello` (it may already be in the bytes that arrived with the `101`, in any chunking),
 *   derives the keys with `finish()` and only then sends CONNECT. The ephemeral secret is zeroed by
 *   `finish()` / `abort()`, the derived keys right after the frame codecs copied them.
 * - Readable: authenticated s2c DATA in order; s2c FIN ⇒ clean EOF (`push(null)`). The transport ending or
 *   failing before the s2c FIN ⇒ the stream is destroyed with `PlrError("E_TRUNCATED")` — never a clean EOF.
 *   A frame that fails authentication / parsing ⇒ destroyed with `E_DECRYPT` / `E_TUNNEL_PROTOCOL`; nothing of
 *   that frame is delivered.
 * - Writable: each write becomes DATA frames of ≤ 16384 bytes; `end()` sends the c2s FIN.
 * - Backpressure both ways: a full readable buffer pauses the transport; a full transport buffer holds the
 *   write callback until `drain`.
 * - `receipt()`: after both FINs the exit sends RECEIPT; it is verified per SPEC-VPN §5 (Ed25519 under the
 *   attested key, `th` / `compose_hash` / `key_hash` equal ours, `ts_open_ms ≤ ts_close_ms`). Missing within the
 *   receipt timeout ⇒ rejects `E_TRUNCATED`.
 *
 * The transport is any `Duplex`: a TCP socket to the exit, or (two-hop, SPEC-VPN §10) the entry hop's own
 * {@link VpnStream}. `closeTransport(clean)` decides how it is let go (default: destroy); a two-hop inner tunnel
 * ends its entry tunnel gracefully so the entry's receipt can still arrive.
 *
 * Nothing here logs; errors carry only a code.
 */
import { Duplex } from "node:stream";
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
  tunnelClientStart,
  verifyVpnReceipt,
  type PlrErrorCode,
  type TunnelClientHandshake,
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

/** A two-hop connection (SPEC-VPN §10): `receipt()` is the exit's, `entryReceipt()` the entry tunnel's. */
export interface TwoHopStream extends VpnStream {
  entryReceipt(): Promise<VpnReceiptResult>;
}

export interface TunnelStreamParams {
  /** The byte stream to the exit, positioned right after the `101` response. */
  transport: Duplex;
  verified: VerifiedRouter;
  /** Nonce of the verified attestation (bound into the hello and `th`). */
  attNonce: Uint8Array;
  /** Max wait for RECEIPT after both FINs (SPEC-VPN §4.3: ≤ 10 s). */
  receiptTimeoutMs: number;
  /** Transport inactivity limit (no bytes in either direction). */
  idleTimeoutMs: number;
  /** Called once if the tunnel fails for a reason that should drop the cached attestation. */
  onFailure?: (code: PlrErrorCode) => void;
  /**
   * Lets go of the transport once the tunnel is over. `clean` = both FINs were exchanged and no tunnel error
   * occurred. Default: destroy the transport.
   */
  closeTransport?: (transport: Duplex, clean: boolean) => void;
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

/** A failed transport that is itself a tunnel (two-hop) passes its authentication failure on. */
const transportError = (e: unknown): PlrError =>
  isPlrError(e) && (e.code === "E_DECRYPT" || e.code === "E_TUNNEL_PROTOCOL") ? e : new PlrError("E_TRUNCATED");

const destroyTransport = (t: Duplex): void => {
  t.destroy();
};

type State = "handshake" | "connecting" | "open" | "receipt" | "closed";

export class TunnelStream extends Duplex implements VpnStream {
  readonly #transport: Duplex;
  readonly #verified: VerifiedRouter;
  readonly #attNonce: Uint8Array;
  readonly #receiptTimeoutMs: number;
  readonly #idleTimeoutMs: number;
  readonly #onFailure: ((code: PlrErrorCode) => void) | undefined;
  readonly #closeTransport: (t: Duplex, clean: boolean) => void;
  #th: Uint8Array | undefined;
  #reader: TunnelReader | undefined;
  #writer: TunnelWriter | undefined;
  #handshake: TunnelClientHandshake | undefined;
  /** Partial server_hello (≤ 33 bytes). */
  #serverHello = new Uint8Array(0);
  /** CONNECT payload, held only until it is sealed right after the handshake. */
  #connectPayload: Uint8Array | undefined;
  /** `receipt`: the Duplex is done (both FINs, cleanly destroyed) but the transport waits for RECEIPT. */
  #state: State = "handshake";
  #started = false;
  #s2cFin = false;
  #c2sFin = false;
  #failed = false;
  #transportGone = false;
  #released = false;
  #receiptTimer: NodeJS.Timeout | undefined;
  #idleTimer: NodeJS.Timeout | undefined;
  #pendingWrite: ((err?: Error | null) => void) | undefined;
  readonly #opened = deferred<void>();
  readonly #receipt = deferred<VpnReceiptResult>();

  constructor(p: TunnelStreamParams) {
    super({ allowHalfOpen: true, readableHighWaterMark: 64 * 1024, writableHighWaterMark: 64 * 1024 });
    this.#transport = p.transport;
    this.#verified = p.verified;
    this.#attNonce = p.attNonce.slice();
    this.#receiptTimeoutMs = p.receiptTimeoutMs;
    this.#idleTimeoutMs = p.idleTimeoutMs;
    this.#onFailure = p.onFailure;
    this.#closeTransport = p.closeTransport ?? destroyTransport;
  }

  receipt(): Promise<VpnReceiptResult> {
    return this.#receipt.promise;
  }

  /**
   * Runs handshake v2 and CONNECT, waiting for CONNECT_OK (≤ `timeoutMs` in total). `head` = bytes the exit
   * sent along with the `101` response. Callable once.
   * @throws PlrError (the CONNECT_ERR code, or E_DECRYPT / E_TUNNEL_PROTOCOL / E_BAD_INPUT)
   */
  async open(connectPayload: Uint8Array, head: Uint8Array, timeoutMs: number): Promise<void> {
    if (this.#started) throw new PlrError("E_TUNNEL_PROTOCOL", "tunnel already opened");
    this.#started = true;
    const timer = setTimeout(() => this.#abort(new PlrError("E_TUNNEL_PROTOCOL", "no CONNECT reply")), timeoutMs);
    timer.unref?.();
    try {
      this.#handshake = tunnelClientStart({ xp: this.#verified.x25519, ep: this.#verified.ed25519, attNonce: this.#attNonce });
      this.#connectPayload = connectPayload;
      this.#attach();
      if (!this.#transport.destroyed) {
        this.#touch();
        this.#transport.write(this.#handshake.hello);
      }
      if (head.length > 0) this.#onData(head);
      if (this.#transport.destroyed || this.#transport.readableEnded) this.#transportClosed();
      await this.#opened.promise;
    } catch (e) {
      this.#abort(plr(e, "E_TUNNEL_PROTOCOL"));
      throw plr(e, "E_TUNNEL_PROTOCOL");
    } finally {
      clearTimeout(timer);
      this.#connectPayload = undefined;
    }
  }

  #attach(): void {
    const t = this.#transport;
    const nd = (t as { setNoDelay?: (v: boolean) => unknown }).setNoDelay;
    if (typeof nd === "function") nd.call(t, true);
    this.#idleTimer = setTimeout(() => this.#onIdle(), this.#idleTimeoutMs);
    this.#idleTimer.unref?.();
    t.on("data", (c: Buffer) => this.#onData(c));
    t.on("end", () => this.#onEnd());
    t.on("error", (e: unknown) => this.#transportClosed(e));
    t.on("close", () => this.#transportClosed());
    t.on("drain", () => this.#flushPendingWrite(null));
  }

  /** Activity in either direction restarts the idle limit. */
  #touch(): void {
    this.#idleTimer?.refresh();
  }

  #onIdle(): void {
    if (this.#released) return;
    this.#transportClosed();
    this.#transport.destroy();
  }

  #writeTransport(b: Uint8Array): boolean {
    this.#touch();
    return this.#transport.write(b);
  }

  // ---------------------------------------------------------------- inbound

  #done(): boolean {
    return this.#state === "closed" || this.#receipt.settled;
  }

  #onData(chunk: Uint8Array): void {
    if (this.#done()) return;
    this.#touch();
    if (this.#state === "handshake") {
      try {
        chunk = this.#onServerHelloBytes(chunk);
      } catch (e) {
        this.#abort(plr(e, "E_TUNNEL_PROTOCOL"));
        return;
      }
      if (this.#state === "handshake" || chunk.length === 0) return;
    }
    let frames: TunnelFrame[];
    try {
      frames = this.#reader!.push(chunk);
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

  /**
   * Collects the 33-byte server_hello; once complete derives the keys, sends CONNECT and returns the bytes
   * that followed it (already tunnel frames). @throws PlrError E_TUNNEL_PROTOCOL / E_DECRYPT
   */
  #onServerHelloBytes(chunk: Uint8Array): Uint8Array {
    const hs = this.#handshake;
    if (hs === undefined) throw new PlrError("E_TUNNEL_PROTOCOL", "unexpected bytes");
    const need = TUNNEL.SERVER_HELLO_LEN - this.#serverHello.length;
    const take = chunk.subarray(0, need);
    const sh = new Uint8Array(this.#serverHello.length + take.length);
    sh.set(this.#serverHello, 0);
    sh.set(take, this.#serverHello.length);
    this.#serverHello = sh;
    if (sh[0] !== TUNNEL.VERSION) throw new PlrError("E_TUNNEL_PROTOCOL", "bad server hello"); // fail fast
    if (sh.length < TUNNEL.SERVER_HELLO_LEN) return new Uint8Array(0);
    this.#serverHello = new Uint8Array(0);
    this.#handshake = undefined;
    const keys = hs.finish(sh); // zeroes the ephemeral secret, also on failure
    try {
      this.#th = keys.th.slice();
      this.#reader = new TunnelReader(keys.kS2c, keys.th, TUNNEL.DIR_S2C);
      this.#writer = new TunnelWriter(keys.kC2s, keys.th, TUNNEL.DIR_C2S);
    } finally {
      keys.kC2s.fill(0);
      keys.kS2c.fill(0);
    }
    const payload = this.#connectPayload;
    this.#connectPayload = undefined;
    if (payload === undefined) throw new PlrError("E_TUNNEL_PROTOCOL", "no CONNECT");
    let connect: Uint8Array;
    try {
      connect = this.#writer.seal(FRAME.CONNECT, payload);
    } catch (e) {
      throw plr(e, "E_BAD_INPUT");
    }
    this.#state = "connecting";
    if (!this.#transport.destroyed) this.#writeTransport(connect);
    return chunk.subarray(take.length);
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
        if (!this.push(Buffer.from(f.payload.buffer, f.payload.byteOffset, f.payload.byteLength))) this.#transport.pause();
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
    const same = (hex: string, b: Uint8Array | undefined): boolean => b !== undefined && equalBytes(fromHex(hex, 32), b);
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
      this.#reader?.end(); // E_TRUNCATED if a partial frame is buffered
    } catch {
      /* handled below: the transport is gone either way */
    }
    this.#transportClosed();
  }

  /** Transport EOF, close, error or idle timeout. */
  #transportClosed(cause?: unknown): void {
    if (this.#transportGone) return;
    this.#transportGone = true;
    if (this.#receipt.settled) return;
    if (this.#state === "handshake" || this.#state === "connecting") {
      this.#abort(cause !== undefined ? transportError(cause) : new PlrError("E_TUNNEL_PROTOCOL", "exit closed the tunnel before CONNECT reply"));
      return;
    }
    this.#receipt.reject(new PlrError("E_TRUNCATED", "no receipt"));
    // Before the authenticated s2c FIN, or with our own data not yet FIN'd: never a clean ending.
    if (this.#state === "open" && (!this.#s2cFin || !this.#c2sFin)) this.#fail(cause !== undefined ? transportError(cause) : new PlrError("E_TRUNCATED"));
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
    if (this.#state === "handshake" || this.#state === "connecting") {
      this.#state = "closed";
      this.#failed = true;
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
    this.#failed = true;
    this.#onFailure?.(err.code);
    this.#receipt.reject(receiptError(err));
    if (this.#state === "receipt") this.#release(); // the Duplex already ended cleanly; only the receipt fails
    else this.destroy(err);
  }

  /** Lets go of the transport and wipes every secret (ephemeral, tunnel keys, partial hello). Idempotent. */
  #release(): void {
    clearTimeout(this.#receiptTimer);
    if (this.#state === "receipt") this.#state = "closed";
    if (this.#released) return;
    this.#released = true;
    clearTimeout(this.#idleTimer);
    this.#handshake?.abort();
    this.#handshake = undefined;
    this.#connectPayload = undefined;
    this.#serverHello.fill(0);
    this.#reader?.wipe();
    this.#writer?.wipe();
    const clean = !this.#failed && this.#s2cFin && this.#c2sFin;
    try {
      this.#closeTransport(this.#transport, clean);
    } catch {
      this.#transport.destroy();
    }
  }

  // ---------------------------------------------------------------- Duplex

  override _read(): void {
    if (this.#transport.isPaused()) this.#transport.resume();
  }

  override _write(chunk: Buffer, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    if (this.#transportGone || this.#state !== "open" || this.#writer === undefined) {
      cb(new PlrError("E_TRUNCATED"));
      return;
    }
    let ok = true;
    try {
      for (let off = 0; off < chunk.length; off += TUNNEL.MAX_PAYLOAD) {
        const part = chunk.subarray(off, Math.min(off + TUNNEL.MAX_PAYLOAD, chunk.length));
        ok = this.#writeTransport(this.#writer.seal(FRAME.DATA, part));
      }
    } catch (e) {
      cb(plr(e, "E_TUNNEL_PROTOCOL"));
      return;
    }
    if (ok) cb();
    else this.#pendingWrite = cb; // released on 'drain' (or on destroy)
  }

  override _final(cb: (err?: Error | null) => void): void {
    if (this.#transportGone || this.#state !== "open" || this.#writer === undefined) {
      cb(new PlrError("E_TRUNCATED"));
      return;
    }
    try {
      this.#writeTransport(this.#writer.seal(FRAME.FIN, new Uint8Array(0)));
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
    // A clean ending (both FINs exchanged) keeps the transport until the receipt arrives or times out.
    const awaitingReceipt = err === null && this.#state === "open" && this.#s2cFin && this.#c2sFin && !this.#receipt.settled && !this.#transportGone;
    if (awaitingReceipt) {
      this.#state = "receipt";
    } else {
      if (err !== null || this.#state === "handshake" || this.#state === "connecting") this.#failed = true;
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

/** Inner tunnel of a two-hop connection; carries the entry tunnel's receipt as well (SPEC-VPN §10 step 4). */
export class TwoHopTunnelStream extends TunnelStream implements TwoHopStream {
  readonly #outer: VpnStream;
  constructor(p: TunnelStreamParams & { outer: VpnStream }) {
    super(p);
    this.#outer = p.outer;
  }
  entryReceipt(): Promise<VpnReceiptResult> {
    return this.#outer.receipt();
  }
}
