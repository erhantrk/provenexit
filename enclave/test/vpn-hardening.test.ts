/**
 * Regression tests for the adversarial reviews of PLR-VPN:
 *   1. handshake v2 (SPEC-VPN §4.1): a replayed hello meets a fresh exit ephemeral key, so replayed frames fail
 *      authentication and nothing is dialled; no hello state is needed (the interim HelloGuard is gone);
 *   2. a tunnel that ends without an authenticated c2s FIN aborts the destination with a RST, never a clean EOF;
 *   3. egress refuses host-only services in "public" space (Azure WireServer) and the exit's own addresses.
 * Timeouts are driven by a manual clock and every wait is event-driven (no fixed sleeps).
 */
import net from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { randomBytes } from "@noble/hashes/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  FRAME, TUNNEL, TunnelReader, TunnelWriter, egressIdentity, encodeConnect, encodeHello, parseServerHello, toHex, type EgressPolicy, type TunnelFrame,
} from "@plr/shared";
import { HOST_ONLY_PUBLIC_ADDRESSES, hostOnlyDenied, resolveEgress, type LookupAll } from "../src/vpn/egress.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { ManualTimers, TestTunnel, attestExit, eventually, handshake, readExactly, startEchoUpstream, startTestExit, upgrade, type TestExit } from "./vpn-helpers.js";

const enc = (s: string) => new TextEncoder().encode(s);

const exits: TestExit[] = [];
async function exitWith(o: Parameters<typeof startTestExit>[0] = {}): Promise<TestExit> {
  const e = await startTestExit(o);
  exits.push(e);
  return e;
}
afterEach(async () => { for (const e of exits.splice(0)) await e.close(); });

/** An upgraded socket that records every byte the exit sends and whether it closed. */
async function rawSocket(port: number) {
  const u = await upgrade(port);
  expect(u.status).toBe(101);
  const got: Buffer[] = [Buffer.from(u.head)];
  let closed = false;
  u.sock.on("data", (c: Buffer) => got.push(c));
  u.sock.on("close", () => { closed = true; });
  u.sock.on("error", () => undefined);
  u.sock.resume();
  return {
    sock: u.sock,
    received: () => Buffer.concat(got),
    get closed() { return closed; },
  };
}

describe("handshake v2: exit ephemeral key ⇒ replay protection + forward secrecy (SPEC-VPN §4.1)", () => {
  let up: Awaited<ReturnType<typeof startEchoUpstream>>;
  beforeAll(async () => { up = await startEchoUpstream(); });
  afterAll(async () => { await up.close(); });

  it("server_hello (version 2, 33 bytes) arrives right after a valid hello, before any frame is sent", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const u = await upgrade(e.port);
    const h = await handshake(u.sock, u.head, v, v.nonce);
    expect(h.serverHello.length).toBe(TUNNEL.SERVER_HELLO_LEN);
    expect(h.serverHello[0]).toBe(2);
    expect(h.rest.length).toBe(0);
    // ...and the derived keys are the exit's: a CONNECT sealed under them is answered.
    const r = new TunnelReader(h.keys.kS2c, h.keys.th, TUNNEL.DIR_S2C);
    const frames: TunnelFrame[] = [];
    u.sock.on("data", (c: Uint8Array) => frames.push(...r.push(c)));
    u.sock.resume();
    u.sock.write(new TunnelWriter(h.keys.kC2s, h.keys.th, TUNNEL.DIR_C2S).seal(FRAME.CONNECT, encodeConnect("127.0.0.1", up.port)));
    expect(await eventually(() => frames.length >= 1)).toBe(true);
    expect(frames[0]!.type).toBe(FRAME.CONNECT_OK);
    u.sock.destroy();
  });

  it("a byte-for-byte replay of a victim's hello + CONNECT + DATA gets a fresh server_hello, then closes; nothing is dialled", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const vu = await upgrade(e.port);
    const victim = await handshake(vu.sock, vu.head, v, v.nonce);
    const w = new TunnelWriter(victim.keys.kC2s, victim.keys.th, TUNNEL.DIR_C2S);
    const frames = Buffer.concat([w.seal(FRAME.CONNECT, encodeConnect("127.0.0.1", up.port)), w.seal(FRAME.DATA, enc("POST /pay amount=100"))]);
    const vr = new TunnelReader(victim.keys.kS2c, victim.keys.th, TUNNEL.DIR_S2C);
    const vFrames: TunnelFrame[] = [];
    vu.sock.on("data", (c: Uint8Array) => vFrames.push(...vr.push(c)));
    vu.sock.resume();
    vu.sock.write(frames);
    expect(await eventually(() => vFrames.length >= 2)).toBe(true); // CONNECT_OK + echoed DATA
    expect(vFrames[0]!.type).toBe(FRAME.CONNECT_OK);
    const dialled = up.connections();
    const receivedBefore = up.received().length;

    // The attacker recorded every c2s byte of the victim and replays them on a new connection.
    const replay = await rawSocket(e.port);
    replay.sock.write(Buffer.concat([victim.hello, frames]));
    expect(await eventually(() => replay.closed)).toBe(true);
    const sent = replay.received();
    expect(sent.length).toBe(TUNNEL.SERVER_HELLO_LEN); // only a server_hello: no CONNECT_OK / frame of any kind
    expect(parseServerHello(new Uint8Array(sent)).epkS).not.toEqual(parseServerHello(victim.serverHello).epkS);
    expect(up.connections()).toBe(dialled); // the destination was not contacted again
    expect(up.received().length).toBe(receivedBefore); // and no replayed byte reached it
    expect(e.receipts.size).toBe(0);
    // The victim's tunnel is unaffected.
    expect(vu.sock.destroyed).toBe(false);
    vu.sock.destroy();
  });

  it("replays after the victim's tunnel closed, and replays of a single frame, fail the same way", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const vu = await upgrade(e.port);
    const victim = await handshake(vu.sock, vu.head, v, v.nonce);
    const connect = new TunnelWriter(victim.keys.kC2s, victim.keys.th, TUNNEL.DIR_C2S).seal(FRAME.CONNECT, encodeConnect("127.0.0.1", up.port));
    vu.sock.destroy();
    const before = up.connections();
    for (const bytes of [Buffer.concat([victim.hello, connect]), Buffer.from(victim.hello)]) {
      const r = await rawSocket(e.port);
      r.sock.write(bytes);
      if (bytes.length > TUNNEL.HELLO_LEN) expect(await eventually(() => r.closed)).toBe(true);
      else {
        expect(await eventually(() => r.received().length >= TUNNEL.SERVER_HELLO_LEN)).toBe(true);
        r.sock.write(connect); // the recorded CONNECT, sent separately
        expect(await eventually(() => r.closed)).toBe(true);
      }
      expect(r.received().length).toBe(TUNNEL.SERVER_HELLO_LEN);
    }
    expect(up.connections()).toBe(before);
  });

  it("the same hello accepted twice yields unrelated tunnel keys (fresh exit ephemeral per tunnel)", () => {
    const keys = VpnKeys.generate();
    const hello = encodeHello(randomBytes(32), x25519.getPublicKey(x25519.utils.randomSecretKey()));
    const a = keys.tunnelAccept(hello), b = keys.tunnelAccept(hello);
    expect(toHex(a.serverHello)).not.toBe(toHex(b.serverHello));
    expect(toHex(a.th)).not.toBe(toHex(b.th));
    expect(toHex(a.kC2s)).not.toBe(toHex(b.kC2s));
    expect(toHex(a.kS2c)).not.toBe(toHex(b.kS2c));
  });

  it("no hello state: any number of tunnels (also under one cached attestation, and with a never-attested nonce) work", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    for (const nonce of [v.nonce, v.nonce, v.nonce, randomBytes(32)]) {
      const t = await TestTunnel.open(e.port, v, nonce);
      t.connect("127.0.0.1", up.port);
      expect(await t.until(() => t.frames.length >= 1)).toBe(true);
      expect(t.types()).toEqual([FRAME.CONNECT_OK]);
      t.sock.destroy();
    }
    // The nonce binds the client's own verification into th; the exit attests to any well-formed nonce.
    expect((await fetch(`${e.url}/v1/attestation?nonce=${"ab".repeat(32)}`)).status).toBe(200);
  });

  it("frames pipelined behind the hello but sealed for another tunnel are never delivered", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const before = up.connections();
    const t = await TestTunnel.open(e.port, v, v.nonce);
    // A client that does not wait for server_hello cannot know the keys: a guess (here: other keys) fails.
    const r = await rawSocket(e.port);
    r.sock.write(Buffer.concat([Buffer.from(encodeHello(v.nonce, x25519.getPublicKey(x25519.utils.randomSecretKey()))), Buffer.from(t.seal(FRAME.CONNECT, encodeConnect("127.0.0.1", up.port)))]));
    expect(await eventually(() => r.closed)).toBe(true);
    expect(r.received().length).toBe(TUNNEL.SERVER_HELLO_LEN);
    expect(up.connections()).toBe(before);
    t.sock.destroy();
  });

  it("readExactly helper: a server_hello split across reads is reassembled", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const u = await upgrade(e.port);
    const h = await handshake(u.sock, u.head, v, v.nonce);
    expect(h.serverHello.length).toBe(TUNNEL.SERVER_HELLO_LEN);
    await expect(readExactly(u.sock, new Uint8Array(0), 1, 50)).rejects.toThrow(); // nothing more is sent unprompted
    u.sock.destroy();
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
    expect(await eventually(() => dest.received().includes(body))).toBe(true);
    return t;
  }
  async function nextOutcome(n: number): Promise<string> {
    await eventually(() => dest.outcomes.length > n);
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

  it("idle timeout ⇒ destination gets ECONNRESET (manual clock)", async () => {
    const timers = new ManualTimers();
    const e = await exitWith({ timeouts: { idleMs: 300_000 }, timers });
    const n = dest.outcomes.length;
    await relayed(e, "amount=100-idle");
    expect(dest.outcomes.length).toBe(n);
    timers.advance(300_000);
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
