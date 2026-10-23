/**
 * Exit side of one tunnel (SPEC-VPN §4.3), one per proxied TCP connection.
 *
 *   hello (≤ helloMs) → server_hello (fresh exit ephemeral, handshake v2) → CONNECT as c2s frame 0 (≤ connectMs)
 *   → resolve (DoH) + egress check + dial (≤ dialMs) → CONNECT_OK | CONNECT_ERR(code)+close
 *   → relay DATA / FIN both ways → both FIN'd → RECEIPT + close.
 *
 * Any protocol violation, authentication failure, client EOF before its FIN, or upstream error closes both
 * sockets immediately (no FIN, no RECEIPT). No frames for `idleMs` in either direction ⇒ close.
 *
 * Only an authenticated c2s FIN frame ever becomes a clean end of stream at the destination (`up.end()`). Every
 * other way a tunnel ends early aborts the upstream connection with a TCP RST ({@link abortUpstream}), so a
 * truncated, tampered or cut c2s stream can never be committed by an EOF-delimited protocol as complete.
 *
 * Replay protection and forward secrecy come from the handshake itself (SPEC-VPN §4.1): every tunnel mixes a
 * fresh exit ephemeral key into its keys, so a replayed hello gets a new `server_hello` and new keys, and every
 * replayed frame fails authentication before anything is dialled. No hello state is kept between tunnels.
 *
 * Bounded: the hello buffer is 65 bytes, the TunnelReader holds at most one frame, upstream bytes are sealed in
 * ≤ 16 384-byte DATA frames, and both directions apply backpressure (the producer is paused while the consumer's
 * buffer is full). Frames that arrive while dialing are queued (bounded) with the client socket paused.
 *
 * No retention: nothing here logs, and errors only become CONNECT_ERR codes. The destination exists only in the
 * dial call's arguments.
 */
import type net from "node:net";
import type { Duplex } from "node:stream";
import {
  FRAME, TUNNEL, TUNNEL_IDLE_TIMEOUT_MS, TUNNEL_STEP_TIMEOUT_MS, TunnelReader, TunnelWriter, encodeConnectErr, encodeReceiptPayload,
  isConnectErrCode, isPlrError, parseConnect, type ConnectErrCode, type EgressPolicy, type TunnelFrame,
} from "@plr/shared";
import type { Dialer, LookupAll } from "./egress.js";
import type { VpnKeys } from "./keys.js";
import type { VpnReceiptLog } from "./receipts.js";
import type { TimerHandle, Timers } from "./timers.js";

export interface TunnelTimeouts {
  /** Hello must arrive within this after the upgrade (SPEC-VPN §4.3: 10 s). */
  helloMs: number;
  /** CONNECT must arrive within this after the hello (10 s). */
  connectMs: number;
  /** Resolve + connect deadline (10 s). */
  dialMs: number;
  /** No frames in either direction for this long ⇒ close (300 s). */
  idleMs: number;
  /** After CONNECT_ERR / RECEIPT we end the socket; it is destroyed if still open after this. */
  lingerMs: number;
}

export const DEFAULT_TUNNEL_TIMEOUTS: Readonly<TunnelTimeouts> = Object.freeze({
  helloMs: TUNNEL_STEP_TIMEOUT_MS,
  connectMs: TUNNEL_STEP_TIMEOUT_MS,
  dialMs: TUNNEL_STEP_TIMEOUT_MS,
  idleMs: TUNNEL_IDLE_TIMEOUT_MS,
  lingerMs: 5_000,
});

/** Max bytes of c2s frames queued while the upstream connection is being dialed. */
export const MAX_PENDING_BYTES = 256 * 1024;

export interface TunnelContext {
  keys: VpnKeys;
  composeHash: Uint8Array;
  policy: EgressPolicy;
  receipts: VpnReceiptLog;
  dial: Dialer;
  /** The exit's only resolver (DoH from the measured compose). */
  lookup: LookupAll;
  timeouts: TunnelTimeouts;
  /** Timer source for every tunnel deadline (Node timers; tests drive a manual clock). */
  timers: Timers;
  now: () => number;
}

type State = "hello" | "connect" | "dialing" | "relay" | "closing" | "closed";

/**
 * Aborts an upstream connection with a TCP RST (never a FIN), so the destination sees an error rather than a
 * clean end of the request. Falls back to a plain destroy for non-TCP handles (test doubles).
 */
export function abortUpstream(s: net.Socket): void {
  s.on("error", () => undefined); // resetAndDestroy on a closed socket emits ERR_SOCKET_CLOSED
  if (s.destroyed) return;
  try {
    s.resetAndDestroy();
  } catch {
    s.destroy();
  }
}

export class ExitTunnel {
  readonly #sock: Duplex;
  readonly #ctx: TunnelContext;
  readonly #onClosed: () => void;
  readonly #abort = new AbortController();
  #state: State = "hello";
  readonly #hello = new Uint8Array(TUNNEL.HELLO_LEN);
  #helloFill = 0;
  #reader: TunnelReader | null = null;
  #writer: TunnelWriter | null = null;
  #th: Uint8Array | null = null;
  #upstream: net.Socket | null = null;
  #c2sFin = false;
  #s2cFin = false;
  #c2sBlocked = false;
  #s2cBlocked = false;
  #pending: TunnelFrame[] = [];
  #pendingBytes = 0;
  #stepTimer: TimerHandle | null = null;
  #idleTimer: TimerHandle | null = null;
  #lingerTimer: TimerHandle | null = null;
  readonly #tsOpen: number;

  /** Takes over an upgraded socket; `head` = bytes already read past the HTTP headers. */
  constructor(sock: Duplex, head: Uint8Array, ctx: TunnelContext, onClosed: () => void) {
    this.#sock = sock;
    this.#ctx = ctx;
    this.#onClosed = onClosed;
    this.#tsOpen = ctx.now();
    this.#stepTimer = ctx.timers.set(() => this.destroy(), ctx.timeouts.helloMs);
    this.#idleTimer = ctx.timers.set(() => this.destroy(), ctx.timeouts.idleMs);
    sock.on("data", (c: Buffer) => this.#onData(c));
    sock.on("end", () => this.#onClientEnd());
    sock.on("error", () => this.destroy());
    sock.on("close", () => this.destroy());
    if (head.length > 0) this.#onData(head);
  }

  get state(): State {
    return this.#state;
  }

  /** Closes everything immediately (no FIN, no RECEIPT; the upstream gets a RST). Idempotent. */
  destroy(): void {
    if (this.#state === "closed") return;
    this.#state = "closed";
    for (const t of [this.#stepTimer, this.#idleTimer, this.#lingerTimer]) t?.clear();
    this.#stepTimer = this.#idleTimer = this.#lingerTimer = null;
    this.#abort.abort();
    if (this.#upstream) abortUpstream(this.#upstream);
    this.#upstream = null;
    this.#sock.destroy();
    this.#reader?.wipe();
    this.#writer?.wipe();
    this.#hello.fill(0);
    this.#th?.fill(0);
    this.#pending = [];
    this.#pendingBytes = 0;
    this.#onClosed();
  }

  #open(): boolean {
    return this.#state !== "closed" && this.#state !== "closing";
  }

  #touch(): void {
    this.#idleTimer?.refresh();
  }

  #clearStep(): void {
    this.#stepTimer?.clear();
    this.#stepTimer = null;
  }

  // ------------------------------------------------------------------------------------- client → exit

  #onData(chunk: Uint8Array): void {
    if (!this.#open()) return;
    let rest = chunk;
    if (this.#state === "hello") {
      const take = Math.min(TUNNEL.HELLO_LEN - this.#helloFill, rest.length);
      this.#hello.set(rest.subarray(0, take), this.#helloFill);
      this.#helloFill += take;
      rest = rest.subarray(take);
      if (this.#helloFill < TUNNEL.HELLO_LEN) return;
      let k;
      try {
        // Handshake v2: fresh exit ephemeral per tunnel (zeroed once the keys are derived).
        k = this.#ctx.keys.tunnelAccept(this.#hello);
      } catch {
        return this.destroy(); // wrong version / malformed hello / low-order epk_c: nothing is sent
      } finally {
        this.#hello.fill(0);
      }
      k.attNonce.fill(0); // only bound into th; not needed any further
      this.#th = k.th;
      this.#reader = new TunnelReader(k.kC2s, k.th, TUNNEL.DIR_C2S);
      this.#writer = new TunnelWriter(k.kS2c, k.th, TUNNEL.DIR_S2C);
      k.kC2s.fill(0);
      k.kS2c.fill(0);
      this.#state = "connect";
      this.#clearStep();
      this.#stepTimer = this.#ctx.timers.set(() => this.destroy(), this.#ctx.timeouts.connectMs);
      // server_hello right after a valid hello, before any s2c frame (SPEC-VPN §4.1).
      this.#sock.write(k.serverHello);
      if (rest.length === 0) return;
    }
    let frames: TunnelFrame[];
    try {
      frames = this.#reader!.push(rest);
    } catch {
      return this.destroy(); // E_DECRYPT / E_TUNNEL_PROTOCOL: nothing of it is delivered
    }
    for (const f of frames) {
      if (!this.#open()) return;
      this.#onFrame(f);
    }
  }

  #onFrame(f: TunnelFrame): void {
    this.#touch();
    switch (this.#state) {
      case "connect":
        // Exactly one CONNECT, as c2s frame 0.
        if (f.type !== FRAME.CONNECT) return this.destroy();
        this.#clearStep();
        this.#state = "dialing";
        this.#sock.pause();
        return this.#dial(f.payload);
      case "dialing":
        if (f.type === FRAME.CONNECT) return this.destroy();
        this.#pendingBytes += f.payload.length + 1;
        if (this.#pendingBytes > MAX_PENDING_BYTES) return this.destroy();
        this.#pending.push(f);
        return;
      case "relay":
        return this.#relayFrame(f);
      default:
        return;
    }
  }

  #relayFrame(f: TunnelFrame): void {
    const up = this.#upstream;
    if (!up) return this.destroy();
    if (f.type === FRAME.DATA) {
      if (this.#c2sFin) return this.destroy(); // DATA after FIN
      if (!up.write(f.payload) && !this.#c2sBlocked) {
        // Backpressure: stop reading the client until the upstream drains (one listener at a time).
        this.#c2sBlocked = true;
        this.#sock.pause();
        up.once("drain", () => {
          this.#c2sBlocked = false;
          if (this.#state === "relay") this.#sock.resume();
        });
      }
      return;
    }
    if (f.type === FRAME.FIN) {
      if (this.#c2sFin) return this.destroy();
      this.#c2sFin = true;
      up.end(); // half-close the upstream write side
      return this.#maybeFinish();
    }
    this.destroy(); // a second CONNECT
  }

  #onClientEnd(): void {
    // The client may half-close its TCP side after its FIN frame; anything else is a truncated tunnel.
    if (!this.#open()) return;
    if (this.#state === "relay" && this.#c2sFin && !this.#reader?.pending) return;
    this.destroy();
  }

  // ------------------------------------------------------------------------------------- dial

  #dial(payload: Uint8Array): void {
    let dest: { host: string; port: number };
    try {
      dest = parseConnect(payload);
    } catch {
      return this.#connectError("E_BAD_INPUT");
    }
    this.#ctx
      .dial(dest, {
        policy: this.#ctx.policy,
        timeoutMs: this.#ctx.timeouts.dialMs,
        signal: this.#abort.signal,
        lookup: this.#ctx.lookup,
      })
      .then(
        (up) => this.#connected(up),
        (e: unknown) => {
          const c = isPlrError(e) && isConnectErrCode(e.code) ? e.code : "E_CONNECT_FAILED";
          this.#connectError(c);
        },
      );
  }

  #connectError(code: ConnectErrCode): void {
    if (this.#state !== "dialing") return;
    this.#send(FRAME.CONNECT_ERR, encodeConnectErr(code));
    this.#closeGracefully();
  }

  #connected(up: net.Socket): void {
    if (this.#state !== "dialing") {
      abortUpstream(up); // the tunnel ended while dialing: never a clean (empty) request upstream
      return;
    }
    this.#upstream = up;
    up.on("data", (c: Buffer) => this.#onUpstreamData(c));
    up.on("end", () => this.#onUpstreamEnd());
    up.on("error", () => this.destroy());
    up.on("finish", () => this.#maybeFinish()); // every c2s byte handed to the kernel
    up.on("close", () => {
      if (!this.#s2cFin || !up.writableFinished) this.destroy(); // closed without a clean EOF / flush
    });
    this.#state = "relay";
    this.#send(FRAME.CONNECT_OK, new Uint8Array(0));
    const queued = this.#pending;
    this.#pending = [];
    this.#pendingBytes = 0;
    for (const f of queued) {
      if (this.#state !== "relay") return;
      this.#relayFrame(f);
    }
    if (this.#state === "relay" && !up.writableNeedDrain) this.#sock.resume();
  }

  // ------------------------------------------------------------------------------------- upstream → client

  #onUpstreamData(chunk: Buffer): void {
    if (this.#state !== "relay" || this.#s2cFin) return;
    let ok = true;
    for (let off = 0; off < chunk.length; off += TUNNEL.MAX_PAYLOAD) {
      ok = this.#send(FRAME.DATA, chunk.subarray(off, Math.min(off + TUNNEL.MAX_PAYLOAD, chunk.length)));
      if (this.#state !== "relay") return;
    }
    if (!ok && !this.#s2cBlocked) {
      const up = this.#upstream!;
      this.#s2cBlocked = true;
      up.pause();
      this.#sock.once("drain", () => {
        this.#s2cBlocked = false;
        if (this.#state === "relay") up.resume();
      });
    }
  }

  #onUpstreamEnd(): void {
    if (this.#state !== "relay" || this.#s2cFin) return;
    this.#s2cFin = true;
    this.#send(FRAME.FIN, new Uint8Array(0));
    this.#maybeFinish();
  }

  #maybeFinish(): void {
    // Both FINs, and the upstream has taken every relayed c2s byte (its write side finished).
    if (this.#state !== "relay" || !this.#c2sFin || !this.#s2cFin || !this.#upstream?.writableFinished) return;
    const keys = this.#ctx.keys;
    const { receipt, sig } = this.#ctx.receipts.issue({
      th: this.#th!,
      composeHash: this.#ctx.composeHash,
      keyHash: keys.keyHash,
      tsOpenMs: this.#tsOpen,
      tsCloseMs: this.#ctx.now(),
      sign: (r) => keys.signVpnReceipt(r),
    });
    this.#send(FRAME.RECEIPT, encodeReceiptPayload({ receipt, sig }));
    this.#upstream?.destroy();
    this.#upstream = null;
    this.#closeGracefully();
  }

  // ------------------------------------------------------------------------------------- output

  /** Seals and writes one s2c frame. Returns the socket's backpressure signal. */
  #send(type: number, payload: Uint8Array): boolean {
    if (!this.#open() || !this.#writer) return false;
    this.#touch();
    return this.#sock.write(this.#writer.seal(type, payload));
  }

  /** Ends the socket after the last frame; destroyed if the peer does not finish within `lingerMs`. */
  #closeGracefully(): void {
    if (!this.#open()) return;
    this.#state = "closing";
    this.#clearStep();
    this.#idleTimer?.clear();
    this.#idleTimer = null;
    this.#abort.abort();
    this.#sock.end();
    this.#sock.resume(); // discard anything further, but notice the peer closing
    this.#lingerTimer = this.#ctx.timers.set(() => this.destroy(), this.#ctx.timeouts.lingerMs);
  }
}
