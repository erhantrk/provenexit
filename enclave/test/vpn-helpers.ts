/** Test-side VPN tunnel client (independent of @plr/client): HTTP upgrade, hello, sealed frames. */
import net from "node:net";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  FRAME, MemoryRegistry, fromHex, keyHash, MockRoot, MockTdxAttester, MockVerifier, TUNNEL, TunnelReader, TunnelWriter, encodeConnect, osMeasurement,
  mockOsReport, toHex, tunnelClientInit, verifyAttestation, type AttestationBundle, type TunnelFrame, type VerifiedRouter,
} from "@plr/shared";
import { composeBytes, makeVpnCompose } from "../src/compose.js";
import type { LookupAll, Dialer } from "../src/vpn/egress.js";
import { createExit, type ExitServer } from "../src/vpn/exit.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { VpnReceiptLog } from "../src/vpn/receipts.js";
import type { HelloGuardOptions } from "../src/vpn/replay.js";
import type { TunnelTimeouts } from "../src/vpn/tunnel.js";

export const vpnCompose = (allowLoopback: boolean) =>
  composeBytes(makeVpnCompose({ bundleSha256: "22".repeat(32), nodeSha256: "33".repeat(32), allowLoopback }));

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

export async function startTestExit(o: { allowLoopback?: boolean; lookup?: LookupAll; dial?: Dialer; timeouts?: Partial<TunnelTimeouts>; maxTunnels?: number; replay?: HelloGuardOptions } = {}): Promise<TestExit> {
  const root = MockRoot.generate();
  const cb = vpnCompose(o.allowLoopback ?? true);
  const attester = new MockTdxAttester({ root, composeBytes: cb });
  const keys = VpnKeys.generate();
  const receipts = new VpnReceiptLog();
  const exit = createExit({
    attester, keys, composeBytes: cb, receipts,
    ...(o.lookup ? { lookup: o.lookup } : {}),
    ...(o.dial ? { dial: o.dial } : {}),
    ...(o.timeouts ? { timeouts: o.timeouts } : {}),
    ...(o.maxTunnels !== undefined ? { maxTunnels: o.maxTunnels } : {}),
    ...(o.replay ? { replay: o.replay } : {}),
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
    instances: { [kh]: { compose_hash: composeHash, os_measurement: os, x25519: bundle.x25519, ed25519: bundle.ed25519, operator: "op.test", registered_at_ms: Date.now(), expires_at_ms: Date.now() + 3_600_000, next_seq: 0 } },
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

  static async open(port: number, v: { x25519: Uint8Array; ed25519: Uint8Array }, attNonce: Uint8Array = randomBytes(32)): Promise<TestTunnel> {
    const u = await upgrade(port);
    if (u.status !== 101) throw new Error(`upgrade status ${u.status}`);
    const k = tunnelClientInit({ xp: v.x25519, ep: v.ed25519, attNonce });
    u.sock.write(k.hello);
    return new TestTunnel(u.sock, k, u.head);
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

  /** Waits until `pred` holds or the socket closed (then returns whether `pred` holds). */
  async until(pred: () => boolean, ms = 5000): Promise<boolean> {
    const end = Date.now() + ms;
    while (!pred() && !this.closed && Date.now() < end) {
      await new Promise<void>((r) => { this.#wake = r; setTimeout(r, 50); });
    }
    return pred();
  }

  async waitClosed(ms = 5000): Promise<boolean> {
    return this.until(() => this.closed, ms);
  }

  types(): number[] {
    return this.frames.map((f) => f.type);
  }
  data(): Buffer {
    return Buffer.concat(this.frames.filter((f) => f.type === FRAME.DATA).map((f) => f.payload));
  }
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
