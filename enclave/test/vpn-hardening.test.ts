/**
 * Regression tests for the adversarial review of PLR-VPN-v1:
 *   1. replayed tunnel hellos (same keys + nonces) are refused; hellos must name a nonce this exit attested to;
 *   2. a tunnel that ends without an authenticated c2s FIN aborts the destination with a RST, never a clean EOF;
 *   3. egress refuses host-only services in "public" space (Azure WireServer) and the exit's own addresses.
 */
import net from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  FRAME, TUNNEL, TunnelReader, TunnelWriter, egressIdentity, encodeConnect, tunnelClientInit, type EgressPolicy, type TunnelFrame,
} from "@plr/shared";
import { HOST_ONLY_PUBLIC_ADDRESSES, hostOnlyDenied, resolveEgress, type LookupAll } from "../src/vpn/egress.js";
import { HelloGuard } from "../src/vpn/replay.js";
import { TestTunnel, attestExit, startEchoUpstream, startTestExit, upgrade, type TestExit } from "./vpn-helpers.js";

const enc = (s: string) => new TextEncoder().encode(s);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const exits: TestExit[] = [];
async function exitWith(o: Parameters<typeof startTestExit>[0] = {}): Promise<TestExit> {
  const e = await startTestExit(o);
  exits.push(e);
  return e;
}
afterEach(async () => { for (const e of exits.splice(0)) await e.close(); });

/** A raw tunnel whose c2s bytes are recorded, so they can be replayed byte for byte on another connection. */
async function rawTunnel(port: number, k: { hello: Uint8Array; th: Uint8Array; kC2s: Uint8Array; kS2c: Uint8Array }) {
  const u = await upgrade(port);
  expect(u.status).toBe(101);
  const r = new TunnelReader(k.kS2c, k.th, TUNNEL.DIR_S2C);
  const frames: TunnelFrame[] = [];
  let error: string | null = null;
  let closed = false;
  const onData = (c: Uint8Array) => {
    try { frames.push(...r.push(c)); } catch (e) { error = (e as { code?: string }).code ?? "E_?"; }
  };
  if (u.head.length) onData(u.head);
  u.sock.on("data", onData);
  u.sock.on("close", () => { closed = true; });
  u.sock.on("error", () => undefined);
  u.sock.resume();
  return {
    sock: u.sock,
    frames,
    get error() { return error; },
    get closed() { return closed; },
    async until(pred: () => boolean, ms = 3000) {
      const end = Date.now() + ms;
      while (!pred() && Date.now() < end) await sleep(20);
      return pred();
    },
  };
}

describe("anti-replay of tunnel hellos (review finding: replayed hello ⇒ identical keys/nonces)", () => {
  let up: Awaited<ReturnType<typeof startEchoUpstream>>;
  beforeAll(async () => { up = await startEchoUpstream(); });
  afterAll(async () => { await up.close(); });

  it("a byte-for-byte replay of a victim's hello + CONNECT + DATA on a second connection is closed before anything is dialled", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const k = tunnelClientInit({ xp: v.x25519, ep: v.ed25519, attNonce: v.nonce });
    const w = new TunnelWriter(k.kC2s, k.th, TUNNEL.DIR_C2S);
    const recorded = Buffer.concat([k.hello, w.seal(FRAME.CONNECT, encodeConnect("127.0.0.1", up.port)), w.seal(FRAME.DATA, enc("POST /pay amount=100"))]);

    const victim = await rawTunnel(e.port, k);
    victim.sock.write(recorded);
    expect(await victim.until(() => victim.frames.length >= 2)).toBe(true); // CONNECT_OK + echoed DATA
    expect(victim.frames[0]!.type).toBe(FRAME.CONNECT_OK);
    const dialled = up.connections();

    const replay = await rawTunnel(e.port, k);
    replay.sock.write(recorded);
    expect(await replay.until(() => replay.closed)).toBe(true);
    expect(replay.frames).toEqual([]); // no CONNECT_OK, no s2c frame sealed under the victim's keys
    expect(up.connections()).toBe(dialled); // the destination was not contacted again
    // The victim's tunnel is unaffected.
    expect(victim.closed).toBe(false);
    victim.sock.destroy();
  });

  it("the replay is refused even while the victim's tunnel is already closed (keys remembered per live nonce)", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const k = tunnelClientInit({ xp: v.x25519, ep: v.ed25519, attNonce: v.nonce });
    const first = await rawTunnel(e.port, k);
    first.sock.write(k.hello);
    await sleep(100);
    first.sock.destroy();
    await sleep(100);
    const again = await rawTunnel(e.port, k);
    again.sock.write(Buffer.concat([k.hello, new TunnelWriter(k.kC2s, k.th, TUNNEL.DIR_C2S).seal(FRAME.CONNECT, encodeConnect("127.0.0.1", up.port))]));
    expect(await again.until(() => again.closed)).toBe(true);
    expect(again.frames).toEqual([]);
  });

  it("a hello naming a nonce the exit never attested to is refused", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const before = up.connections();
    const t = await TestTunnel.open(e.port, v, randomBytes(32));
    t.connect("127.0.0.1", up.port);
    expect(await t.waitClosed()).toBe(true);
    expect(t.types()).toEqual([]);
    expect(up.connections()).toBe(before);
  });

  it("an expired attestation nonce no longer opens tunnels; a fresh attestation does", async () => {
    const e = await exitWith({ replay: { nonceTtlMs: 300 } });
    const v = await attestExit(e.url, e.root.publicKey);
    await sleep(400);
    const old = await TestTunnel.open(e.port, v, v.nonce);
    old.connect("127.0.0.1", up.port);
    expect(await old.waitClosed()).toBe(true);
    expect(old.types()).toEqual([]);
    const v2 = await attestExit(e.url, e.root.publicKey);
    const t = await TestTunnel.open(e.port, v2, v2.nonce);
    t.connect("127.0.0.1", up.port);
    expect(await t.until(() => t.frames.length >= 1)).toBe(true);
    expect(t.types()).toEqual([FRAME.CONNECT_OK]);
    t.sock.destroy();
  });

  it("many tunnels under one cached attestation (fresh epk each) all work", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    for (let i = 0; i < 5; i++) {
      const t = await TestTunnel.open(e.port, v, v.nonce);
      t.connect("127.0.0.1", up.port);
      expect(await t.until(() => t.frames.length >= 1)).toBe(true);
      expect(t.types()).toEqual([FRAME.CONNECT_OK]);
      t.sock.destroy();
    }
  });

  it("bounded nonce table: unused nonces are evicted oldest first; when every nonce is in use, attestation is 503", async () => {
    const e = await exitWith({ replay: { maxNonces: 2 } });
    const a = await attestExit(e.url, e.root.publicKey);
    const b = await attestExit(e.url, e.root.publicKey);
    const c = await attestExit(e.url, e.root.publicKey); // evicts a (unused)
    const ta = await TestTunnel.open(e.port, a, a.nonce);
    expect(await ta.waitClosed()).toBe(true);
    for (const v of [b, c]) {
      const t = await TestTunnel.open(e.port, v, v.nonce);
      t.connect("127.0.0.1", up.port);
      expect(await t.until(() => t.frames.length >= 1)).toBe(true);
      t.sock.destroy();
    }
    const res = await fetch(`${e.url}/v1/attestation?nonce=${"ab".repeat(32)}`);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "E_UPSTREAM" });
  });

  it("HelloGuard: one admission per (nonce, epk), total bound, expiry frees memory", () => {
    let now = 0;
    const g = new HelloGuard({ nonceTtlMs: 1000, maxHellos: 3, clock: () => now });
    const n1 = randomBytes(32), n2 = randomBytes(32);
    const [k1, k2, k3, k4] = [randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32)];
    expect(g.admit(n1, k1)).toBe(false); // not issued
    expect(g.issue(n1)).toBe(true);
    expect(g.admit(n1, k1)).toBe(true);
    expect(g.admit(n1, k1)).toBe(false); // replay
    expect(g.issue(n1)).toBe(true); // re-issue keeps the remembered keys
    expect(g.admit(n1, k1)).toBe(false);
    expect(g.admit(n1, k2)).toBe(true);
    expect(g.issue(n2)).toBe(true);
    expect(g.admit(n2, k3)).toBe(true);
    expect(g.admit(n2, k4)).toBe(false); // total bound reached: fail closed
    expect(g.size).toEqual({ nonces: 2, hellos: 3 });
    now = 1001;
    expect(g.admit(n1, k4)).toBe(false); // expired
    expect(g.size).toEqual({ nonces: 0, hellos: 0 });
    expect(g.issue(new Uint8Array(31))).toBe(false);
    expect(g.admit(n1, new Uint8Array(31))).toBe(false);
  });
});

/** Destination that records how each connection ended: "end" (clean FIN) or the socket error code. */
async function startRecordingDest() {
  const outcomes: string[] = [];
  const received: Buffer[] = [];
  const socks = new Set<net.Socket>();
  const server = net.createServer({ allowHalfOpen: true }, (s) => {
    socks.add(s);
    let done = false;
    const record = (o: string) => { if (!done) { done = true; outcomes.push(o); } };
    s.on("data", (c: Buffer) => received.push(c));
    s.on("end", () => record("end"));
    s.on("error", (e: NodeJS.ErrnoException) => record(e.code ?? "error"));
    s.on("close", () => { record("close"); socks.delete(s); });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  return {
    port: (server.address() as net.AddressInfo).port,
    outcomes,
    received: () => Buffer.concat(received).toString(),
    close: () => new Promise<void>((ok) => { for (const s of socks) s.destroy(); server.close(() => ok()); }),
  };
}

describe("c2s truncation / tampering never reaches the destination as a clean EOF (review finding)", () => {
  let dest: Awaited<ReturnType<typeof startRecordingDest>>;
  beforeAll(async () => { dest = await startRecordingDest(); });
  afterAll(async () => { await dest.close(); });

  async function relayed(e: TestExit, body: string): Promise<TestTunnel> {
    const v = await attestExit(e.url, e.root.publicKey);
    const t = await TestTunnel.open(e.port, v, v.nonce);
    t.connect("127.0.0.1", dest.port);
    expect(await t.until(() => t.frames.length >= 1)).toBe(true);
    t.send(FRAME.DATA, enc(body));
    const end = Date.now() + 3000;
    while (!dest.received().includes(body) && Date.now() < end) await sleep(10);
    expect(dest.received()).toContain(body);
    return t;
  }
  async function nextOutcome(n: number): Promise<string> {
    const end = Date.now() + 3000;
    while (dest.outcomes.length <= n && Date.now() < end) await sleep(10);
    return dest.outcomes[n] ?? "TIMEOUT";
  }

  it("client TCP EOF before its FIN frame ⇒ destination gets ECONNRESET", async () => {
    const e = await exitWith();
    const n = dest.outcomes.length;
    const t = await relayed(e, "amount=100-cut");
    t.sock.end();
    expect(await nextOutcome(n)).toBe("ECONNRESET");
  });

  it("a tampered DATA frame after CONNECT_OK ⇒ destination gets ECONNRESET", async () => {
    const e = await exitWith();
    const n = dest.outcomes.length;
    const t = await relayed(e, "amount=100-tamper");
    const f = Buffer.from(t.seal(FRAME.DATA, enc("0000")));
    f[8]! ^= 1;
    t.sock.write(f);
    expect(await nextOutcome(n)).toBe("ECONNRESET");
  });

  it("idle timeout ⇒ destination gets ECONNRESET", async () => {
    const e = await exitWith({ timeouts: { idleMs: 300 } });
    const n = dest.outcomes.length;
    await relayed(e, "amount=100-idle");
    expect(await nextOutcome(n)).toBe("ECONNRESET");
  });

  it("control: an authenticated c2s FIN frame is a clean EOF at the destination", async () => {
    const e = await exitWith();
    const n = dest.outcomes.length;
    const t = await relayed(e, "amount=100-fin");
    t.send(FRAME.FIN);
    expect(await nextOutcome(n)).toBe("end");
    t.sock.destroy();
  });
});

describe("egress: host-only services in public space and the exit's own addresses (review finding)", () => {
  const prod: EgressPolicy = { allow_loopback: false, deny_private: true };
  const test: EgressPolicy = { allow_loopback: true, deny_private: true };
  const noLocal = () => [];
  const signal = new AbortController().signal;
  const outcome = (host: string, policy: EgressPolicy, lookup: LookupAll = async () => [], local: () => Iterable<string> = noLocal) =>
    resolveEgress({ host, port: 80 }, policy, lookup, signal, local).then((r) => r.address, (e: { code: string }) => e.code);

  it("egressIdentity canonicalises every spelling of the same IPv4 host", () => {
    for (const s of ["168.63.129.16", "::ffff:168.63.129.16", "::ffff:a83f:8110", "64:ff9b::a83f:8110", "2002:a83f:8110::1", "::168.63.129.16"]) {
      expect(egressIdentity(s), s).toBe("168.63.129.16");
    }
    expect(egressIdentity("2001:0DB8::0001")).toBe("2001:db8::1");
    expect(egressIdentity("not-an-ip")).toBeNull();
  });

  it("Azure WireServer 168.63.129.16 is refused in every spelling, as a literal and via DNS", async () => {
    expect(HOST_ONLY_PUBLIC_ADDRESSES).toContain("168.63.129.16");
    for (const h of ["168.63.129.16", "::ffff:168.63.129.16", "64:ff9b::a83f:8110", "2002:a83f:8110::"]) {
      expect(await outcome(h, prod), h).toBe("E_EGRESS_DENIED");
    }
    const lookup: LookupAll = async () => [{ address: "93.184.216.34", family: 4 }, { address: "168.63.129.16", family: 4 }];
    expect(await outcome("wire.example", prod, lookup)).toBe("E_EGRESS_DENIED");
    expect(await outcome("93.184.216.34", prod)).toBe("93.184.216.34"); // ordinary public address still allowed
  });

  it("the exit's own public interface addresses are refused (incl. embedded-IPv4 forms); loopback in a test build is not", async () => {
    const local = () => ["127.0.0.1", "::1", "203.0.114.7", "2a01:4f8::7", "fe80::1"];
    for (const h of ["203.0.114.7", "::ffff:203.0.114.7", "64:ff9b::cb00:7207", "2a01:4f8::7", "2a01:4f8:0::0:7"]) {
      expect(await outcome(h, prod, async () => [], local), h).toBe("E_EGRESS_DENIED");
    }
    expect(await outcome("self.example", prod, async () => [{ address: "2a01:4f8::7", family: 6 }], local)).toBe("E_EGRESS_DENIED");
    expect(await outcome("203.0.114.8", prod, async () => [], local)).toBe("203.0.114.8");
    expect(await outcome("127.0.0.1", test, async () => [], local)).toBe("127.0.0.1");
  });

  it("fails closed if the interfaces cannot be listed", async () => {
    const broken = () => { throw new Error("no ifaddrs"); };
    expect(hostOnlyDenied("93.184.216.34", broken)).toBe(true);
    expect(await outcome("93.184.216.34", prod, async () => [], broken)).toBe("E_EGRESS_DENIED");
    expect(hostOnlyDenied("127.0.0.1", broken)).toBe(false); // non-public classes are decided by egressAllowed
  });
});
