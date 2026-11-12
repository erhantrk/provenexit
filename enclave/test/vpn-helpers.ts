/**
 * Test-side VPN tunnel client (independent of @plr/client): HTTP upgrade, handshake v2 (hello → server_hello),
 * sealed frames; a manual clock for the tunnel deadlines; and event-driven waits (no fixed sleeps).
 */
import net from "node:net";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  FRAME, MemoryRegistry, fromHex, keyHash, MockRoot, MockTdxAttester, MockVerifier, TUNNEL, TunnelReader, TunnelWriter, encodeConnect, osMeasurement,
  mockOsReport, toHex, tunnelClientStart, verifyAttestation, type AttestationBundle, type TunnelFrame, type TunnelKeys, type VerifiedRouter,
} from "@plr/shared";
import { composeBytes, makeVpnCompose } from "../src/compose.js";
import type { LookupAll, Dialer } from "../src/vpn/egress.js";
import { createExit, type ExitServer } from "../src/vpn/exit.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { VpnReceiptLog } from "../src/vpn/receipts.js";
import type { TimerHandle, Timers } from "../src/vpn/timers.js";
import type { TunnelTimeouts } from "../src/vpn/tunnel.js";
import { WAIT_MS } from "./wait.js";

export { WAIT_MS, eventually } from "./wait.js";

export const vpnCompose = (allowLoopback: boolean, doh?: readonly string[]) =>
  composeBytes(makeVpnCompose({ bundleSha256: "22".repeat(32), nodeSha256: "33".repeat(32), allowLoopback, ...(doh ? { doh } : {}) }));

/**
 * A manual clock for the exit's tunnel deadlines: nothing fires until the test calls {@link advance}, so timeout
 * tests are deterministic whatever the machine load. Mirrors Node semantics (refresh re-arms, clear is final).
 */
export class ManualTimers implements Timers {
  #now = 0;
  #seq = 0;
  readonly #armed = new Map<number, { due: number; ms: number; fn: () => void; order: number }>();

  set(fn: () => void, ms: number): TimerHandle {
    const id = ++this.#seq;
    let cleared = false;
    const arm = () => this.#armed.set(id, { due: this.#now + ms, ms, fn, order: ++this.#seq });
    arm();
    return {
      refresh: () => { if (!cleared) arm(); },
      clear: () => { cleared = true; this.#armed.delete(id); },
    };
  }

  /** Armed timers. */
  get pending(): number {
    return this.#armed.size;
  }

  /** Moves the clock forward, firing (in due order) every timer that comes due on the way. */
  advance(ms: number): void {
    const target = this.#now + ms;
    for (;;) {
      let next: [number, { due: number; fn: () => void; order: number }] | null = null;
      for (const e of this.#armed) if (e[1].due <= target && (!next || e[1].due < next[1].due || (e[1].due === next[1].due && e[1].order < next[1].order))) next = e;
      if (!next) break;
      this.#armed.delete(next[0]);
      this.#now = next[1].due;
      next[1].fn();
    }
    this.#now = target;
  }
}

export interface TestExit {
  url: string;
  port: number;
  root: MockRoot;
  keys: VpnKeys;
  receipts: VpnReceiptLog;
  exit: ExitServer;
  composeBytes: Uint8Array;
  close(): Promise<void>;
}

/**
 * An in-process exit on 127.0.0.1:0. Without `lookup` it resolves through the DoH resolvers of its compose
 * (`doh`, default: the test resolver 127.0.0.1:18253 — nothing listens there in unit tests, so names fail E_DNS).
 */
export async function startTestExit(o: { allowLoopback?: boolean; doh?: readonly string[]; lookup?: LookupAll; dial?: Dialer; timeouts?: Partial<TunnelTimeouts>; timers?: Timers; maxTunnels?: number; allowedPorts?: readonly number[]; /** Measured compose override; default a plr-vpn test compose. */ composeBytes?: Uint8Array } = {}): Promise<TestExit> {
  const root = MockRoot.generate();
  const cb = o.composeBytes ?? vpnCompose(o.allowLoopback ?? true, o.doh);
  const attester = new MockTdxAttester({ root, composeBytes: cb });
  const keys = VpnKeys.generate();
  const receipts = new VpnReceiptLog();
  const exit = createExit({
    attester, keys, composeBytes: cb, receipts,
    ...(o.lookup ? { lookup: o.lookup } : {}),
    ...(o.dial ? { dial: o.dial } : {}),
    ...(o.timeouts ? { timeouts: o.timeouts } : {}),
    ...(o.maxTunnels !== undefined ? { maxTunnels: o.maxTunnels } : {}),
    ...(o.allowedPorts ? { allowedPorts: o.allowedPorts } : {}),
    ...(o.timers ? { timers: o.timers } : {}),
  });
  await new Promise<void>((ok) => exit.server.listen(0, "127.0.0.1", ok));
  const port = (exit.server.address() as net.AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`, port, root, keys, receipts, exit, composeBytes: cb,
    close: () => new Promise<void>((ok) => { exit.destroyTunnels(); exit.server.close(() => ok()); exit.server.closeAllConnections(); }),
  };
}

/** Verifies the exit's attestation against a MemoryRegistry that approves it. */
export async function attestExit(url: string, rootPub: Uint8Array): Promise<VerifiedRouter & { bundle: AttestationBundle; nonce: Uint8Array }> {
  const nonce = randomBytes(32);
  const res = await fetch(`${url}/v1/attestation?nonce=${toHex(nonce)}`);
  if (res.status !== 200) throw new Error(`attestation status ${res.status}`);
  const bundle = (await res.json()) as AttestationBundle;
  const composeHash = toHex(sha256(new TextEncoder().encode(bundle.app_compose)));
  const os = toHex(osMeasurement(mockOsReport()));
  const kh = toHex(keyHash(fromHex(bundle.x25519, 32), fromHex(bundle.ed25519, 32)));
  const registry = new MemoryRegistry({
    root: { kind: "MOCK", p256: toHex(rootPub) }, compose: [composeHash], os: [os],
    instances: { [kh]: { compose_hash: composeHash, os_measurement: os, x25519: bundle.x25519, ed25519: bundle.ed25519, operator: "op.test", org_id: null, registered_at_ms: Date.now(), expires_at_ms: Date.now() + 3_600_000, next_seq: 0 } },
  });
  const v = await verifyAttestation({ bundle, nonce, verifier: new MockVerifier(rootPub), registry, trustedRoot: rootPub });
  return { ...v, bundle, nonce };
}

/** Opens a raw upgraded socket to the exit (`/v1/tunnel`, `Upgrade: plr-vpn/1`); resolves once the 101 is read. */
export function upgrade(port: number, req = "GET /v1/tunnel HTTP/1.1\r\nHost: exit\r\nConnection: Upgrade\r\nUpgrade: plr-vpn/1\r\n\r\n"): Promise<{ sock: net.Socket; status: number; head: Buffer; raw: string }> {
  return new Promise((ok, fail) => {
    const sock = net.connect(port, "127.0.0.1");
    let buf = Buffer.alloc(0);
    sock.on("error", fail);
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      const i = buf.indexOf("\r\n\r\n");
      if (i < 0) return;
      sock.off("data", onData);
      sock.off("error", fail);
      sock.on("error", () => undefined); // the exit may reset a tunnel it refuses; tests observe "close"
      sock.pause();
      const raw = buf.toString("latin1");
      const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(raw)?.[1] ?? 0);
      ok({ sock, status, head: buf.subarray(i + 4), raw });
    };
    sock.on("data", onData);
    sock.on("connect", () => sock.write(req));
  });
}

/** A client end of one tunnel: sends sealed c2s frames, collects decrypted s2c frames. */
export class TestTunnel {
  readonly frames: TunnelFrame[] = [];
  error: string | null = null;
  closed = false;
  readonly th: Uint8Array;
  readonly #w: TunnelWriter;
  readonly #r: TunnelReader;
  #wake: (() => void) | null = null;

  constructor(readonly sock: net.Socket, keys: { th: Uint8Array; kC2s: Uint8Array; kS2c: Uint8Array }, head: Buffer) {
    this.th = keys.th;
    this.#w = new TunnelWriter(keys.kC2s, keys.th, TUNNEL.DIR_C2S);
    this.#r = new TunnelReader(keys.kS2c, keys.th, TUNNEL.DIR_S2C);
    const onData = (c: Uint8Array) => {
      try {
        this.frames.push(...this.#r.push(c));
      } catch (e) {
        this.error = (e as { code?: string }).code ?? "E_?";
      }
      this.#wake?.();
    };
    if (head.length) onData(head);
    sock.on("data", onData);
    sock.on("error", () => { this.closed = true; this.#wake?.(); });
    sock.on("close", () => { this.closed = true; this.#wake?.(); });
    sock.resume();
  }

  /** Upgrade + handshake v2: sends the hello, waits for the exit's server_hello, derives the keys. */
  static async open(port: number, v: { x25519: Uint8Array; ed25519: Uint8Array }, attNonce: Uint8Array = randomBytes(32)): Promise<TestTunnel> {
    const u = await upgrade(port);
    if (u.status !== 101) throw new Error(`upgrade status ${u.status}`);
    const hs = tunnelClientStart({ xp: v.x25519, ep: v.ed25519, attNonce });
    u.sock.write(hs.hello);
    const { bytes, rest } = await readExactly(u.sock, u.head, TUNNEL.SERVER_HELLO_LEN);
    return new TestTunnel(u.sock, hs.finish(bytes), rest);
  }

  send(type: number, payload: Uint8Array = new Uint8Array(0)): void {
    this.sock.write(this.seal(type, payload));
  }
  seal(type: number, payload: Uint8Array = new Uint8Array(0)): Uint8Array {
    return this.#w.seal(type, payload);
  }
  connect(host: string, port: number): void {
    this.send(FRAME.CONNECT, encodeConnect(host, port));
  }

  /** Waits (event-driven) until `pred` holds or the socket closed (then returns whether `pred` holds). */
  async until(pred: () => boolean, ms = WAIT_MS): Promise<boolean> {
    const end = Date.now() + ms;
    while (!pred() && !this.closed && Date.now() < end) {
      await new Promise<void>((r) => { this.#wake = r; setTimeout(r, 50); });
    }
    return pred();
  }

  async waitClosed(ms = WAIT_MS): Promise<boolean> {
    return this.until(() => this.closed, ms);
  }

  types(): number[] {
    return this.frames.map((f) => f.type);
  }
  data(): Buffer {
    return Buffer.concat(this.frames.filter((f) => f.type === FRAME.DATA).map((f) => f.payload));
  }
}

/**
 * Reads exactly `n` bytes from a paused socket (starting with `head`); `rest` = anything after them. Rejects if the
 * socket closes first or nothing arrives within `ms`. Leaves the socket paused with no data listener.
 */
export function readExactly(sock: net.Socket, head: Uint8Array, n: number, ms = WAIT_MS): Promise<{ bytes: Uint8Array; rest: Buffer }> {
  return new Promise((ok, fail) => {
    let buf = Buffer.from(head);
    const done = (err: Error | null) => {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("close", onClose);
      sock.pause();
      if (err) fail(err);
      else ok({ bytes: new Uint8Array(buf.subarray(0, n)), rest: buf.subarray(n) });
    };
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (buf.length >= n) done(null);
    };
    const onClose = () => done(Object.assign(new Error("closed before server_hello"), { code: "CLOSED" }));
    const timer = setTimeout(() => done(new Error("timeout waiting for bytes")), ms);
    if (buf.length >= n) return done(null);
    sock.on("data", onData);
    sock.on("close", onClose);
    sock.resume();
  });
}

/** A raw client handshake whose keys are known once the exit's server_hello is read. */
export async function handshake(sock: net.Socket, head: Uint8Array, v: { x25519: Uint8Array; ed25519: Uint8Array }, attNonce: Uint8Array): Promise<{ hello: Uint8Array; serverHello: Uint8Array; keys: TunnelKeys; rest: Buffer }> {
  const hs = tunnelClientStart({ xp: v.x25519, ep: v.ed25519, attNonce });
  sock.write(hs.hello);
  const { bytes, rest } = await readExactly(sock, head, TUNNEL.SERVER_HELLO_LEN);
  return { hello: hs.hello, serverHello: bytes, keys: hs.finish(bytes), rest };
}

/** Fake upstream TCP server on 127.0.0.1: echoes everything back, then ends when the client half-closes. */
export async function startEchoUpstream(): Promise<{ port: number; connections: () => number; received: () => Buffer; closed: () => number; close(): Promise<void> }> {
  let n = 0, closed = 0;
  const chunks: Buffer[] = [];
  const socks = new Set<net.Socket>();
  const server = net.createServer({ allowHalfOpen: true }, (s) => {
    n++;
    socks.add(s);
    s.on("data", (c: Buffer) => chunks.push(c));
    s.on("close", () => { closed++; socks.delete(s); });
    s.on("error", () => undefined);
    s.pipe(s);
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  return {
    port: (server.address() as net.AddressInfo).port,
    connections: () => n,
    received: () => Buffer.concat(chunks),
    closed: () => closed,
    close: () => new Promise<void>((ok) => { for (const s of socks) s.destroy(); server.close(() => ok()); }),
  };
}

/** A TCP port on 127.0.0.1 that nobody listens on. */
export async function deadPort(): Promise<number> {
  const s = net.createServer();
  await new Promise<void>((ok) => s.listen(0, "127.0.0.1", ok));
  const p = (s.address() as net.AddressInfo).port;
  await new Promise<void>((ok) => s.close(() => ok()));
  return p;
}

/**
 * Whether `text` mentions the number `n` as a standalone token (e.g. "port=59523", ":59523", `"port":59523`).
 * A plain substring search for a short number is a false positive waiting to happen: it also matches inside
 * random hex (key hashes, nonces) and ms timestamps (1792791459523 contains 59523). Alphanumeric neighbours
 * on either side therefore do not count as a mention.
 */
export function mentionsNumber(text: string, n: number): boolean {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("mentionsNumber: n must be a non-negative integer");
  return new RegExp(`(?<![0-9A-Za-z])${n}(?![0-9A-Za-z])`).test(text);
}
