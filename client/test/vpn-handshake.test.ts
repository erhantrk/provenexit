// SPEC-VPN §4.1 handshake v2, client side: hello ‖ server_hello (any chunking, also inside the upgrade head),
// CONNECT only after server_hello, fresh ephemerals per tunnel, fail closed on malformed / low-order server_hello.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Duplex, PassThrough } from "node:stream";
import { x25519 } from "@noble/curves/ed25519.js";
import { PlrError, TUNNEL, FRAME, TunnelReader, TunnelWriter, encodeServerHello, parseHello, deriveTunnel, keyHash, type VerifiedRouter } from "@plr/shared";
import { VpnClient, TunnelStream, type VpnStream } from "../src/index.js";
import { startFakeExit, startDestination, type FakeExit, type FakeDestination } from "./fake-exit.js";

let X: FakeExit;
let D: FakeDestination;
const closers: (() => Promise<void>)[] = [];
beforeEach(async () => {
  X = await startFakeExit();
  D = await startDestination();
  closers.push(X.close, D.close);
});
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

const vpn = (o: { timeouts?: Record<string, number>; attestTtlMs?: number } = {}): VpnClient =>
  new VpnClient({ exitUrl: X.url, registry: X.registry, trustedRoot: X.root.publicKey, ...o });

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PlrError);
    return (e as PlrError).code;
  }
  return "NO_THROW";
}

function get(s: VpnStream, path: string): Promise<{ data: string; error: unknown }> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let done = false;
    const fin = (error: unknown): void => {
      if (!done) (done = true), ok({ data: Buffer.concat(chunks).toString("latin1"), error });
    };
    s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
    s.on("end", () => (s.end(), fin(null)));
    s.on("error", fin);
    s.on("close", () => fin(null));
    s.write(`GET ${path} HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n`);
  });
}

describe("handshake v2 over a real upgrade", () => {
  it("server_hello inside the upgrade head (same read as the 101) is processed; CONNECT follows", async () => {
    X.behaviour.serverHelloInHead = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    expect((await get(s, "/head")).data).toContain("dest-ok:/head");
    await s.receipt();
  });

  it("a server_hello dribbled one byte per read works", async () => {
    X.behaviour.dribbleServerHello = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    expect((await get(s, "/dribble")).data).toContain("dest-ok:/dribble");
    await s.receipt();
  });

  it("the client sends exactly the 65-byte hello and no CONNECT until server_hello arrives", async () => {
    X.behaviour.withholdServerHello = true;
    expect(await codeOf(vpn({ timeouts: { connectMs: 300 } }).connect("127.0.0.1", D.port))).toBe("E_TUNNEL_PROTOCOL");
    expect(X.stats.bytesWithoutServerHello).toBe(TUNNEL.HELLO_LEN);
    expect(X.stats.connects).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("every tunnel uses a fresh client ephemeral, and its receipt binds a distinct th", async () => {
    const c = vpn({ attestTtlMs: 600_000 });
    const ths: string[] = [];
    for (let i = 0; i < 3; i++) {
      const s = await c.connect("127.0.0.1", D.port);
      await get(s, `/f${i}`);
      ths.push((await s.receipt()).receipt.th);
    }
    expect(X.stats.attestations).toBe(1);
    const hellos = X.stats.hellos;
    expect(hellos).toHaveLength(3);
    expect(new Set(hellos.map((h) => h.slice(0, 66))).size).toBe(1); // same version + att_nonce (cached attestation)
    expect(new Set(hellos.map((h) => h.slice(66))).size).toBe(3); // three different epk_c
    expect(hellos[0]!.slice(0, 2)).toBe("02");
    expect(new Set(ths).size).toBe(3);
  });

  for (const [name, raw, code] of [
    ["version 1", Uint8Array.of(1, ...new Uint8Array(32).fill(9)), "E_TUNNEL_PROTOCOL"],
    ["version 3", Uint8Array.of(3, ...new Uint8Array(32).fill(9)), "E_TUNNEL_PROTOCOL"],
    ["low-order epk_s (all zero)", Uint8Array.of(2, ...new Uint8Array(32)), "E_DECRYPT"],
  ] as const) {
    it(`server_hello ${name} ⇒ ${code}; no CONNECT, cached attestation dropped`, async () => {
      X.behaviour.rawServerHello = raw;
      const c = vpn({ attestTtlMs: 600_000 });
      expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe(code);
      expect(X.stats.connects).toBe(0);
      delete X.behaviour.rawServerHello;
      await get(await c.connect("127.0.0.1", D.port), "/again");
      expect(X.stats.attestations).toBe(2);
    });
  }

  it("a server_hello that never completes ⇒ E_TUNNEL_PROTOCOL within the connect timeout", async () => {
    X.behaviour.rawServerHello = Uint8Array.of(2, 1, 2, 3);
    const c = vpn({ timeouts: { connectMs: 500 } });
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_TUNNEL_PROTOCOL");
  });

  it("frames glued to the server_hello are processed after the key derivation (DATA before CONNECT_OK ⇒ E_TUNNEL_PROTOCOL)", async () => {
    X.behaviour.dataAfterServerHello = true;
    expect(await codeOf(vpn().connect("127.0.0.1", D.port))).toBe("E_TUNNEL_PROTOCOL");
    expect(D.hits()).toBe(0);
  });
});

// ---------------------------------------------------------------- TunnelStream over an arbitrary Duplex

/** A Duplex pair: what the stream writes is readable on `peer`, what is written to `peer` reaches the stream. */
function pair(): { transport: Duplex; peer: Duplex } {
  const toStream = new PassThrough();
  const toPeer = new PassThrough();
  const mk = (r: PassThrough, w: PassThrough): Duplex =>
    new Duplex({
      allowHalfOpen: true,
      read() {
        r.resume();
      },
      write(c, _e, cb) {
        w.write(c, cb);
      },
      final(cb) {
        w.end();
        cb();
      },
      destroy(err, cb) {
        w.destroy();
        r.destroy();
        cb(err);
      },
      construct(cb) {
        r.on("data", (c: Buffer) => {
          if (!this.push(c)) r.pause();
        });
        r.on("end", () => this.push(null));
        cb();
      },
    });
  return { transport: mk(toStream, toPeer), peer: mk(toPeer, toStream) };
}

function exitKeys() {
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const ep = new Uint8Array(32).fill(7);
  const verified = { x25519: xp, ed25519: ep, keyHash: keyHash(xp, ep), composeHash: new Uint8Array(32).fill(1) } as unknown as VerifiedRouter;
  return { xs, xp, ep, verified };
}

describe("TunnelStream over a generic Duplex", () => {
  it("handshake + CONNECT_OK + DATA + FIN over a non-socket transport; idle limit applies to any transport", async () => {
    const { xs, xp, ep, verified } = exitKeys();
    const { transport, peer } = pair();
    const attNonce = new Uint8Array(32).fill(5);
    const s = new TunnelStream({ transport, verified, attNonce, receiptTimeoutMs: 200, idleTimeoutMs: 400 });
    // Exit side, driven by the peer end; the server_hello is sent before the hello is read (precomputed ephemeral).
    const ess = x25519.utils.randomSecretKey();
    const epkS = x25519.getPublicKey(ess);
    let buf = Buffer.alloc(0);
    let reader: TunnelReader | undefined;
    let writer: TunnelWriter | undefined;
    const got: number[] = [];
    peer.on("data", (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (reader === undefined) {
        if (buf.length < TUNNEL.HELLO_LEN) return;
        const { attNonce: n, epkC } = parseHello(new Uint8Array(buf.subarray(0, TUNNEL.HELLO_LEN)));
        expect(n).toEqual(attNonce);
        const k = deriveTunnel({ dh1: x25519.getSharedSecret(xs, epkC), dh2: x25519.getSharedSecret(ess, epkC), attNonce: n, epkC, epkS, xp, ep });
        reader = new TunnelReader(k.kC2s, k.th, TUNNEL.DIR_C2S);
        writer = new TunnelWriter(k.kS2c, k.th, TUNNEL.DIR_S2C);
        buf = buf.subarray(TUNNEL.HELLO_LEN);
      }
      for (const f of reader.push(new Uint8Array(buf))) {
        got.push(f.type);
        if (f.type === FRAME.CONNECT) peer.write(writer!.seal(FRAME.CONNECT_OK, new Uint8Array(0)));
        if (f.type === FRAME.DATA) {
          peer.write(writer!.seal(FRAME.DATA, f.payload));
          peer.write(writer!.seal(FRAME.FIN, new Uint8Array(0)));
        }
      }
      buf = Buffer.alloc(0);
    });
    await s.open(new TextEncoder().encode(JSON.stringify({ host: "a.test", port: 1 })), encodeServerHello(epkS), 2_000);
    const echoed = new Promise<string>((ok) => {
      let t = "";
      s.on("data", (c: Buffer) => (t += c.toString()));
      s.on("end", () => ok(t));
    });
    s.write("ping");
    expect(await echoed).toBe("ping");
    s.end();
    // No RECEIPT from this peer: the receipt promise rejects within the receipt timeout.
    expect(await codeOf(s.receipt())).toBe("E_TRUNCATED");
    expect(got).toEqual([FRAME.CONNECT, FRAME.DATA, FRAME.FIN]);
  });

  it("an idle transport (no server_hello ever) ends the open() within the timeout, E_TUNNEL_PROTOCOL", async () => {
    const { verified } = exitKeys();
    const { transport } = pair();
    const s = new TunnelStream({ transport, verified, attNonce: new Uint8Array(32), receiptTimeoutMs: 100, idleTimeoutMs: 150 });
    const t0 = Date.now();
    expect(await codeOf(s.open(Uint8Array.of(1), new Uint8Array(0), 5_000))).toBe("E_TUNNEL_PROTOCOL");
    expect(Date.now() - t0).toBeLessThan(2_000);
    expect(transport.destroyed).toBe(true);
  });

  it("a transport error that is itself a tunnel authentication failure is passed on (two-hop)", async () => {
    const { verified } = exitKeys();
    const { transport } = pair();
    const s = new TunnelStream({ transport, verified, attNonce: new Uint8Array(32), receiptTimeoutMs: 100, idleTimeoutMs: 5_000 });
    const p = s.open(Uint8Array.of(1), new Uint8Array(0), 5_000);
    transport.destroy(new PlrError("E_DECRYPT"));
    expect(await codeOf(p)).toBe("E_DECRYPT");
    expect(() => s.open(Uint8Array.of(1), new Uint8Array(0), 10)).rejects.toThrow(PlrError);
  });
});
