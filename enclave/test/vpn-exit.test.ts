import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { randomBytes } from "@noble/hashes/utils.js";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { FRAME, QUOTE, TUNNEL, fromHex, parseConnectErr, parseReceiptPayload, registrationNonce, registrationReportData, reportData, toHex, u32be, verifyVpnReceipt, vpnReceiptLeaf, merkleRoot, type EgressPolicy } from "@plr/shared";
import { ManualTimers, TestTunnel, attestExit, deadPort, eventually, mentionsNumber, handshake, startEchoUpstream, startTestExit, upgrade, type TestExit } from "./vpn-helpers.js";
import type { LookupAll } from "../src/vpn/egress.js";
import { composeBytes as composeBytesOf, makeComboCompose } from "../src/compose.js";

type Up = Awaited<ReturnType<typeof startEchoUpstream>>;
const enc = (s: string) => new TextEncoder().encode(s);

let up: Up;
beforeAll(async () => { up = await startEchoUpstream(); });
afterAll(async () => { await up.close(); });

const exits: TestExit[] = [];
async function exitWith(o: Parameters<typeof startTestExit>[0] = {}): Promise<TestExit> {
  const e = await startTestExit(o);
  exits.push(e);
  return e;
}
afterEach(async () => { for (const e of exits.splice(0)) await e.close(); });

async function openVerified(e: TestExit): Promise<TestTunnel> {
  const v = await attestExit(e.url, e.root.publicKey);
  return TestTunnel.open(e.port, v, v.nonce);
}

/** Opens a tunnel, CONNECTs, and returns the CONNECT_ERR code or "OK". */
async function connectOutcome(e: TestExit, host: string, port: number): Promise<string> {
  const t = await openVerified(e);
  t.connect(host, port);
  await t.until(() => t.frames.length > 0);
  const f = t.frames[0];
  if (!f) return "NO_FRAME";
  if (f.type === FRAME.CONNECT_OK) { t.sock.destroy(); return "OK"; }
  if (f.type !== FRAME.CONNECT_ERR) return `TYPE_${f.type}`;
  const code = parseConnectErr(f.payload);
  expect(await t.waitClosed()).toBe(true); // "then close"
  return code;
}

describe("exit HTTP API (SPEC-VPN §3)", () => {
  it("attestation is the SPEC §6.2 bundle with the VPN compose and verifies end to end", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    expect(v.bundle.v).toBe("PLR-v1");
    expect(v.bundle.app_compose).toBe(new TextDecoder().decode(e.composeBytes));
    expect(JSON.parse(v.bundle.app_compose).name).toBe("plr-vpn");
    expect(toHex(v.keyHash)).toBe(toHex(e.keys.keyHash));
  });

  // SPEC §5 rev 1.3: the interim refusal of registration-nonce values is gone. A session quote is
  // key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce), so it never equals a registration report_data (the
  // registration hijack would need a SHA-256 preimage), whatever nonce is asked for.
  it("a session quote for ANY nonce (even a registration nonce) never equals a registration report_data", async () => {
    const e = await exitWith();
    const regs = ["vpnregistry.test.near", "registry.test.near"].flatMap((c) => ["operator.test.near", "attacker.test.near"].map((op) => [c, op] as const));
    for (const n of [randomBytes(32), new Uint8Array(32).fill(0xff), ...regs.map(([c, op]) => registrationNonce(c, op))]) {
      const r = await fetch(`${e.url}/v1/attestation?nonce=${toHex(n)}`);
      expect(r.status).toBe(200);
      const rd = fromHex(((await r.json()) as { quote: string }).quote).subarray(QUOTE.OFF.REPORT_DATA, QUOTE.OFF.REPORT_DATA + 64);
      expect(toHex(rd)).toBe(toHex(reportData(e.keys.x25519, e.keys.ed25519, n)));
      for (const [c, op] of regs) expect(toHex(rd)).not.toBe(toHex(registrationReportData(e.keys.x25519, e.keys.ed25519, c, op)));
    }
    // Upper-case hex stays a malformed nonce.
    expect((await fetch(`${e.url}/v1/attestation?nonce=${toHex(randomBytes(32)).toUpperCase()}`)).status).toBe(400);
  });

  it("serves a plr-combo compose (SPEC-COMBO): attests the combo bytes, enforces the combo's VPN policy", async () => {
    const combo = composeBytesOf(makeComboCompose({
      router: { kind: "mock", modelSha256: "11".repeat(32), runtime: "node-mock-llm", runtimeSha256: "33".repeat(32), bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", nodeSha256: "33".repeat(32) },
      vpn: { bundleSha256: "44".repeat(32), nodeSha256: "33".repeat(32), allowLoopback: false },
    }));
    const e = await exitWith({ composeBytes: combo });
    const v = await attestExit(e.url, e.root.publicKey);
    expect(v.bundle.app_compose).toBe(new TextDecoder().decode(combo));
    expect(JSON.parse(v.bundle.app_compose).name).toBe("plr-combo");
    // Production policy of the combo: the router / LLM on loopback are unreachable from the exit.
    expect(await connectOutcome(e, "127.0.0.1", up.port)).toBe("E_EGRESS_DENIED");
  });

  it("healthz, proof, 404, and /v1/tunnel without a proper upgrade → 400 E_BAD_REQUEST", async () => {
    const e = await exitWith();
    expect(await (await fetch(`${e.url}/healthz`)).json()).toEqual({ ok: true });
    const p = await fetch(`${e.url}/v1/receipts/proof?seq=0`);
    expect(p.status).toBe(404);
    expect(await p.json()).toEqual({ error: "E_NOT_ANCHORED" });
    expect((await fetch(`${e.url}/v1/receipts/proof?seq=-1`)).status).toBe(400);
    expect((await fetch(`${e.url}/nope`)).status).toBe(404);
    const t = await fetch(`${e.url}/v1/tunnel`);
    expect(t.status).toBe(400);
    expect(await t.json()).toEqual({ error: "E_BAD_REQUEST" });
    expect((await fetch(`${e.url}/v1/tunnel`, { method: "POST", body: "x" })).status).toBe(400);
    const wrongToken = await upgrade(e.port, "GET /v1/tunnel HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    expect(wrongToken.status).toBe(400);
    expect(wrongToken.raw).toContain('{"error":"E_BAD_REQUEST"}');
    wrongToken.sock.destroy();
    const withQuery = await upgrade(e.port, "GET /v1/tunnel?x=1 HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: plr-vpn/1\r\n\r\n");
    expect(withQuery.status).toBe(400);
    withQuery.sock.destroy();
    const otherPath = await upgrade(e.port, "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: plr-vpn/1\r\n\r\n");
    expect(otherPath.status).toBe(404);
    otherPath.sock.destroy();
    const ok = await upgrade(e.port);
    expect(ok.status).toBe(101);
    expect(ok.raw.toLowerCase()).toContain("upgrade: plr-vpn/1");
    ok.sock.destroy();
  });

  it("refuses tunnels beyond maxTunnels with 503", async () => {
    const e = await exitWith({ maxTunnels: 1 });
    const a = await upgrade(e.port);
    expect(a.status).toBe(101);
    const b = await upgrade(e.port);
    expect(b.status).toBe(503);
    a.sock.destroy(); b.sock.destroy();
  });
});

describe("tunnel round trip (SPEC-VPN §4)", () => {
  it("CONNECT_OK, DATA both ways, FIN both ways, signed metadata-free RECEIPT, then close", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    for (const seq of [0, 1]) {
      const tBefore = Date.now();
      const t = await TestTunnel.open(e.port, v, v.nonce);
      t.connect("127.0.0.1", up.port);
      expect(await t.until(() => t.frames.length >= 1)).toBe(true);
      expect(t.types()).toEqual([FRAME.CONNECT_OK]);
      t.send(FRAME.DATA, enc("hello "));
      t.send(FRAME.DATA, enc("world"));
      expect(await t.until(() => t.data().toString() === "hello world")).toBe(true);
      t.send(FRAME.FIN);
      expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
      const types = t.types();
      expect(types[0]).toBe(FRAME.CONNECT_OK);
      expect(types.slice(-2)).toEqual([FRAME.FIN, FRAME.RECEIPT]);
      const { receipt, sig } = parseReceiptPayload(t.frames.at(-1)!.payload);
      expect(Object.keys(receipt).sort()).toEqual(["compose_hash", "key_hash", "seq", "th", "ts_close_ms", "ts_open_ms", "v"]);
      expect(verifyVpnReceipt(receipt, sig, v.ed25519)).toBe(true);
      expect(receipt.th).toBe(toHex(t.th));
      expect(receipt.key_hash).toBe(toHex(v.keyHash));
      expect(receipt.compose_hash).toBe(toHex(v.composeHash));
      expect(receipt.seq).toBe(seq);
      expect(receipt.ts_open_ms).toBeLessThanOrEqual(receipt.ts_close_ms);
      // Metadata-free: the key set is exact (above), every hex field is pinned to a known value and the two
      // timestamps are real wall-clock times of this tunnel, so the destination port can hide nowhere. (A plain
      // substring check on the JSON was flaky: a 13-digit ms timestamp contains a 5-digit port by chance, e.g.
      // ts_close_ms 1792791459523 vs port 59523.)
      expect(Object.values(receipt)).not.toContain(up.port);
      expect(receipt.ts_open_ms).toBeGreaterThanOrEqual(tBefore);
      expect(receipt.ts_close_ms).toBeLessThanOrEqual(Date.now());
      expect(await t.waitClosed()).toBe(true);
      expect(t.error).toBeNull();
    }
    expect(e.receipts.size).toBe(2);
    expect(e.receipts.pendingBatch()!.count).toBe(2);
  });

  it("relays large payloads in ≤ 16 384-byte frames, in order, both directions", async () => {
    const e = await exitWith();
    const t = await openVerified(e);
    t.connect("127.0.0.1", up.port);
    await t.until(() => t.frames.length >= 1);
    const big = nodeRandomBytes(300_000);
    for (let off = 0; off < big.length; off += TUNNEL.MAX_PAYLOAD) t.send(FRAME.DATA, big.subarray(off, off + TUNNEL.MAX_PAYLOAD));
    t.send(FRAME.FIN);
    expect(await t.until(() => t.types().includes(FRAME.RECEIPT), 15_000)).toBe(true);
    expect(t.data().equals(big)).toBe(true);
    for (const f of t.frames) expect(f.payload.length).toBeLessThanOrEqual(TUNNEL.MAX_PAYLOAD);
  });

  it("thousands of tiny frames in one write: delivered intact, bounded listeners (no leak warning)", async () => {
    const e = await exitWith();
    const t = await openVerified(e);
    t.connect("127.0.0.1", up.port);
    await t.until(() => t.frames.length >= 1);
    const warnings: string[] = [];
    const onWarn = (w: Error) => warnings.push(w.name);
    process.on("warning", onWarn);
    try {
      const parts: Uint8Array[] = [];
      for (let i = 0; i < 4000; i++) parts.push(t.seal(FRAME.DATA, Uint8Array.of(i & 0xff)));
      parts.push(t.seal(FRAME.FIN));
      t.sock.write(Buffer.concat(parts));
      expect(await t.until(() => t.types().includes(FRAME.RECEIPT), 15_000)).toBe(true);
      expect([...t.data()]).toEqual(Array.from({ length: 4000 }, (_, i) => i & 0xff));
      for (let i = 0; i < 3; i++) await new Promise((r) => setImmediate(r)); // let any process warning surface
    } finally {
      process.off("warning", onWarn);
    }
    expect(warnings).toEqual([]);
  });

  it("frames pipelined right after CONNECT (before CONNECT_OK) are delivered in order", async () => {
    const e = await exitWith();
    const t = await openVerified(e);
    t.sock.write(Buffer.concat([t.seal(FRAME.CONNECT, enc(JSON.stringify({ host: "127.0.0.1", port: up.port }))), t.seal(FRAME.DATA, enc("early")), t.seal(FRAME.FIN)]));
    expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
    expect(t.data().toString()).toBe("early");
  });

  it("upstream EOF first ⇒ s2c FIN; the client may keep sending until its own FIN, then RECEIPT", async () => {
    const net = await import("node:net");
    const got: Buffer[] = [];
    const srv = net.createServer({ allowHalfOpen: true }, (s) => {
      s.on("data", (c: Buffer) => got.push(c));
      s.on("error", () => undefined);
      s.end("greeting");
    });
    await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
    try {
      const e = await exitWith();
      const t = await openVerified(e);
      t.connect("127.0.0.1", (srv.address() as import("node:net").AddressInfo).port);
      expect(await t.until(() => t.types().includes(FRAME.FIN))).toBe(true);
      expect(t.data().toString()).toBe("greeting");
      t.send(FRAME.DATA, enc("after-fin"));
      t.send(FRAME.FIN);
      expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
      expect(Buffer.concat(got).toString()).toBe("after-fin");
    } finally {
      await new Promise<void>((ok) => srv.close(() => ok()));
    }
  });

  it("a destination name is resolved by the exit and dialled by IP", async () => {
    const asked: string[] = [];
    const lookup: LookupAll = async (h, signal) => { asked.push(h); expect(signal).toBeInstanceOf(AbortSignal); return [{ address: "127.0.0.1", family: 4 }]; };
    const e = await exitWith({ lookup });
    const t = await openVerified(e);
    t.connect("upstream.example", up.port);
    await t.until(() => t.frames.length >= 1);
    expect(t.types()).toEqual([FRAME.CONNECT_OK]);
    expect(asked).toEqual(["upstream.example"]);
    t.sock.destroy();
  });

  it("client EOF before its FIN ⇒ upstream torn down, no FIN/RECEIPT, no receipt issued", async () => {
    const e = await exitWith();
    const t = await openVerified(e);
    t.connect("127.0.0.1", up.port);
    await t.until(() => t.frames.length >= 1);
    const closedBefore = up.closed();
    t.send(FRAME.DATA, enc("x"));
    await t.until(() => t.data().length === 1);
    t.sock.end();
    expect(await t.waitClosed()).toBe(true);
    expect(await eventually(() => up.closed() > closedBefore)).toBe(true); // (aborted with a RST: see vpn-hardening.test.ts)
    expect(t.types()).not.toContain(FRAME.RECEIPT);
    expect(e.receipts.size).toBe(0);
    expect(await eventually(() => e.exit.tunnels === 0)).toBe(true);
  });

  it("receipt leaves are what the Merkle batch commits to", async () => {
    const e = await exitWith();
    const t = await openVerified(e);
    t.connect("127.0.0.1", up.port);
    await t.until(() => t.frames.length >= 1);
    t.send(FRAME.FIN);
    await t.until(() => t.types().includes(FRAME.RECEIPT));
    const { receipt } = parseReceiptPayload(t.frames.at(-1)!.payload);
    expect(toHex(e.receipts.pendingBatch()!.root)).toBe(toHex(merkleRoot([vpnReceiptLeaf(receipt)])));
  });
});

describe("CONNECT_ERR codes (SPEC-VPN §4.3 step 2)", () => {
  it("E_BAD_INPUT for an invalid destination (never contacted)", async () => {
    const e = await exitWith();
    const t = await openVerified(e);
    t.send(FRAME.CONNECT, enc(JSON.stringify({ host: "bad host!", port: 80 })));
    await t.until(() => t.frames.length >= 1);
    expect(parseConnectErr(t.frames[0]!.payload)).toBe("E_BAD_INPUT");
    for (const p of [{ host: "example.com", port: 0 }, { host: "2130706433", port: 80 }, { host: "01.2.3.4", port: 80 }, { host: "a.b", port: 80, x: 1 }]) {
      const u = await openVerified(e);
      u.send(FRAME.CONNECT, enc(JSON.stringify(p)));
      await u.until(() => u.frames.length >= 1);
      expect(parseConnectErr(u.frames[0]!.payload)).toBe("E_BAD_INPUT");
    }
  });

  it("E_DNS when resolution fails or returns nothing usable", async () => {
    const before = up.connections();
    for (const lookup of [
      (async () => { throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }); }) as LookupAll,
      (async () => []) as LookupAll,
      (async () => [{ address: "not-an-ip", family: 4 }]) as LookupAll,
    ]) {
      const e = await exitWith({ lookup });
      expect(await connectOutcome(e, "nx.example", up.port)).toBe("E_DNS");
    }
    expect(up.connections()).toBe(before);
  });

  it("E_DNS when resolution exceeds the dial deadline", async () => {
    const e = await exitWith({ lookup: () => new Promise(() => undefined), timeouts: { dialMs: 200 } });
    expect(await connectOutcome(e, "slow.example", up.port)).toBe("E_DNS");
  });

  it("E_CONNECT_FAILED for a closed port", async () => {
    const e = await exitWith();
    expect(await connectOutcome(e, "127.0.0.1", await deadPort())).toBe("E_CONNECT_FAILED");
  });
});

describe("egress policy (SPEC-VPN §6)", () => {
  it("production policy: loopback / private / link-local / metadata / reserved are refused before any dial", async () => {
    const lookup: LookupAll = async (h) =>
      h === "loop.example" ? [{ address: "127.0.0.1", family: 4 }]
        : h === "mixed.example" ? [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.7", family: 4 }]
        : h === "mapped.example" ? [{ address: "::ffff:127.0.0.1", family: 6 }]
        : [{ address: "93.184.216.34", family: 4 }];
    const e = await exitWith({ allowLoopback: false, lookup });
    const before = up.connections();
    for (const host of ["127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "224.0.0.1", "255.255.255.255", "fe80::1", "fc00::1", "64:ff9b::7f00:1", "2002:7f00:1::", "loop.example", "mixed.example", "mapped.example"]) {
      expect(await connectOutcome(e, host, up.port), host).toBe("E_EGRESS_DENIED");
    }
    expect(up.connections()).toBe(before);
  });

  it("RFC 6761: localhost / *.localhost are refused before any resolution, on either policy", async () => {
    const asked: string[] = [];
    const lookup: LookupAll = async (h) => { asked.push(h); return [{ address: "127.0.0.1", family: 4 }]; };
    for (const allowLoopback of [false, true]) {
      const e = await exitWith({ allowLoopback, lookup });
      for (const h of ["localhost", "LOCALHOST.", "x.localhost", "a.b.LocalHost"]) expect(await connectOutcome(e, h, up.port), h).toBe("E_EGRESS_DENIED");
    }
    expect(asked).toEqual([]);
    expect(await connectOutcome(await exitWith({ lookup }), "localhost.example", up.port)).toBe("OK"); // only the RFC 6761 names
    expect(asked).toEqual(["localhost.example"]);
  });

  it("test policy allows loopback only (private stays denied)", async () => {
    const e = await exitWith({ allowLoopback: true, lookup: async () => [{ address: "10.1.2.3", family: 4 }] });
    expect(await connectOutcome(e, "127.0.0.1", up.port)).toBe("OK");
    expect(await connectOutcome(e, "10.0.0.1", up.port)).toBe("E_EGRESS_DENIED");
    expect(await connectOutcome(e, "private.example", up.port)).toBe("E_EGRESS_DENIED");
  });
});

describe("protocol violations and timeouts close the tunnel (SPEC-VPN §4.2, §4.3)", () => {
  const nothingSent = (t: TestTunnel) => expect(t.types()).toEqual([]);

  const closed = (s: import("node:net").Socket) => new Promise<void>((r) => s.on("close", () => r()).resume());

  it("no hello within helloMs ⇒ close; partial hello ⇒ close (manual clock)", async () => {
    const timers = new ManualTimers();
    const e = await exitWith({ timeouts: { helloMs: 10_000 }, timers });
    const a = await upgrade(e.port);
    const b = await upgrade(e.port);
    b.sock.write(Buffer.alloc(30, 1));
    expect(await eventually(() => e.exit.tunnels === 2)).toBe(true);
    const aClosed = closed(a.sock), bClosed = closed(b.sock);
    timers.advance(9_999);
    expect(e.exit.tunnels).toBe(2); // not a millisecond early
    timers.advance(1);
    expect(e.exit.tunnels).toBe(0);
    await aClosed;
    await bClosed;
  });

  it("wrong version byte (incl. the removed v1), or a low-order epk ⇒ close with nothing sent (no server_hello)", async () => {
    const e = await exitWith();
    const v = await attestExit(e.url, e.root.publicKey);
    const valid = (await import("@plr/shared")).tunnelClientStart({ xp: v.x25519, ep: v.ed25519, attNonce: v.nonce }).hello;
    for (const hello of [
      Buffer.concat([Buffer.from([1]), Buffer.from(valid.subarray(1))]),
      Buffer.concat([Buffer.from([3]), Buffer.from(valid.subarray(1))]),
      Buffer.concat([Buffer.from([2]), Buffer.from(v.nonce), Buffer.alloc(32)]),
    ]) {
      const u = await upgrade(e.port);
      const got: Buffer[] = [];
      u.sock.on("data", (c: Buffer) => got.push(c));
      u.sock.write(hello);
      await closed(u.sock);
      expect(Buffer.concat([u.head, ...got]).length, String(hello[0])).toBe(0);
    }
  });

  it("no CONNECT within connectMs after the hello ⇒ close (manual clock)", async () => {
    const timers = new ManualTimers();
    const e = await exitWith({ timeouts: { connectMs: 10_000 }, timers });
    const t = await openVerified(e);
    timers.advance(9_999);
    expect(t.closed).toBe(false);
    expect(e.exit.tunnels).toBe(1);
    timers.advance(1);
    expect(await t.waitClosed()).toBe(true);
    nothingSent(t);
  });

  it("frame 0 that is not CONNECT, a second CONNECT, DATA after FIN ⇒ close without FIN/RECEIPT", async () => {
    const e = await exitWith();
    const a = await openVerified(e);
    a.send(FRAME.DATA, enc("x"));
    expect(await a.waitClosed()).toBe(true);
    nothingSent(a);

    const b = await openVerified(e);
    b.connect("127.0.0.1", up.port);
    await b.until(() => b.frames.length >= 1);
    b.connect("127.0.0.1", up.port);
    expect(await b.waitClosed()).toBe(true);
    expect(b.types()).toEqual([FRAME.CONNECT_OK]);

    const c = await openVerified(e);
    c.connect("127.0.0.1", up.port);
    await c.until(() => c.frames.length >= 1);
    c.send(FRAME.FIN);
    c.send(FRAME.DATA, enc("late"));
    expect(await c.waitClosed()).toBe(true);
    expect(c.types()).not.toContain(FRAME.RECEIPT);
    expect(e.receipts.size).toBe(0);
  });

  it("oversized / undersized frame lengths ⇒ close before CONNECT_OK", async () => {
    const e = await exitWith();
    for (const len of [TUNNEL.MAX_FRAME_LEN + 1, TUNNEL.MIN_FRAME_LEN - 1, 0xffffffff]) {
      const t = await openVerified(e);
      t.sock.write(u32be(len));
      expect(await t.waitClosed(), String(len)).toBe(true);
      nothingSent(t);
    }
  });

  it("a tampered or wrongly keyed frame ⇒ close, nothing relayed", async () => {
    const e = await exitWith();
    const before = up.connections();
    const t = await openVerified(e);
    const f = Buffer.from(t.seal(FRAME.CONNECT, enc(JSON.stringify({ host: "127.0.0.1", port: up.port }))));
    f[10]! ^= 1;
    t.sock.write(f);
    expect(await t.waitClosed()).toBe(true);
    nothingSent(t);
    // A valid handshake, frames keyed for another tunnel: authentication fails.
    const v = await attestExit(e.url, e.root.publicKey);
    const other = await TestTunnel.open(e.port, v, v.nonce);
    const u = await upgrade(e.port);
    await handshake(u.sock, u.head, v, v.nonce);
    u.sock.write(other.seal(FRAME.CONNECT, enc(JSON.stringify({ host: "127.0.0.1", port: up.port }))));
    await new Promise<void>((r) => u.sock.on("close", () => r()).resume());
    other.sock.destroy();
    expect(up.connections()).toBe(before);
  });

  it("idle limit: no frames in either direction ⇒ close without FIN/RECEIPT (manual clock)", async () => {
    const timers = new ManualTimers();
    const e = await exitWith({ timeouts: { idleMs: 300_000 }, timers });
    const t = await openVerified(e);
    t.connect("127.0.0.1", up.port);
    expect(await t.until(() => t.frames.length >= 1)).toBe(true);
    timers.advance(299_999);
    expect(t.closed).toBe(false);
    timers.advance(1);
    expect(await t.waitClosed()).toBe(true);
    expect(t.types()).toEqual([FRAME.CONNECT_OK]);
    expect(e.receipts.size).toBe(0);
  });

  it("activity (either direction) keeps a tunnel alive past the idle limit (manual clock)", async () => {
    const timers = new ManualTimers();
    const e = await exitWith({ timeouts: { idleMs: 1_000 }, timers });
    const t = await openVerified(e);
    t.connect("127.0.0.1", up.port);
    expect(await t.until(() => t.frames.length >= 1)).toBe(true);
    for (let i = 1; i <= 6; i++) {
      timers.advance(900);
      t.send(FRAME.DATA, enc("k"));
      expect(await t.until(() => t.data().length === i)).toBe(true); // c2s frame + echoed s2c frame both refresh it
    }
    expect(t.closed).toBe(false); // 5 400 ms of manual time, never 1 000 without a frame
    t.send(FRAME.FIN);
    expect(await t.until(() => t.types().includes(FRAME.RECEIPT))).toBe(true);
  });
});

describe("no retention (SPEC-VPN §1.3, §5)", () => {
  it("nothing about destinations or payloads reaches stdout/stderr, success or failure", async () => {
    const MARK = "dest-secret-" + toHex(randomBytes(6));
    const PORT_MARK = await deadPort();
    const lookup: LookupAll = async (h) => (h.startsWith("ok-") ? [{ address: "127.0.0.1", family: 4 }] : h.startsWith("lo-") ? [{ address: "10.9.9.9", family: 4 }] : Promise.reject(new Error(h)));
    const captured: string[] = [];
    const ow = process.stdout.write.bind(process.stdout), ew = process.stderr.write.bind(process.stderr);
    process.stdout.write = ((c: unknown, ...r: unknown[]) => { captured.push(String(c)); return (ow as (...a: unknown[]) => boolean)(c, ...r); }) as typeof process.stdout.write;
    process.stderr.write = ((c: unknown, ...r: unknown[]) => { captured.push(String(c)); return (ew as (...a: unknown[]) => boolean)(c, ...r); }) as typeof process.stderr.write;
    try {
      const e = await exitWith({ lookup });
      const t = await openVerified(e);
      t.connect(`ok-${MARK}.example`, up.port);
      await t.until(() => t.frames.length >= 1);
      t.send(FRAME.DATA, enc(MARK));
      t.send(FRAME.FIN);
      await t.until(() => t.types().includes(FRAME.RECEIPT));
      expect(t.data().toString()).toBe(MARK);
      expect(await connectOutcome(e, `lo-${MARK}.example`, up.port)).toBe("E_EGRESS_DENIED");
      expect(await connectOutcome(e, `nx-${MARK}.example`, up.port)).toBe("E_DNS");
      expect(await connectOutcome(e, "127.0.0.1", PORT_MARK)).toBe("E_CONNECT_FAILED");
      const bad = await openVerified(e);
      bad.send(FRAME.CONNECT, enc(JSON.stringify({ host: `${MARK} !`, port: 1 })));
      await bad.until(() => bad.frames.length >= 1);
      const { receipt } = parseReceiptPayload(t.frames.at(-1)!.payload);
      expect(JSON.stringify(receipt)).not.toContain(MARK);
    } finally {
      process.stdout.write = ow;
      process.stderr.write = ew;
    }
    const all = captured.join("");
    expect(all).not.toContain(MARK);
    expect(mentionsNumber(all, PORT_MARK)).toBe(false);
  });

  it("dial errors carry codes only (no host, address or port)", async () => {
    const { resolveEgress, connectIp, dialEgress } = await import("../src/vpn/egress.js");
    const policy: EgressPolicy = { allow_loopback: false, deny_private: true };
    const errs: unknown[] = [];
    const ac = new AbortController();
    await resolveEgress({ host: "secret-host.example", port: 4242 }, policy, async () => [{ address: "10.4.2.42", family: 4 }], ac.signal).catch((e) => errs.push(e));
    await resolveEgress({ host: "secret host", port: 4242 }, policy, async () => [], ac.signal).catch((e) => errs.push(e));
    await connectIp({ address: "secret-host.example", family: 4 }, 4242, ac.signal).catch((e) => errs.push(e));
    await dialEgress({ host: "127.0.0.1", port: 4242 }, { policy: { allow_loopback: true, deny_private: true }, lookup: async () => [], timeoutMs: 2000 }).catch((e) => errs.push(e));
    expect(errs.map((e) => (e as { code: string }).code)).toEqual(["E_EGRESS_DENIED", "E_BAD_INPUT", "E_CONNECT_FAILED", "E_CONNECT_FAILED"]);
    for (const e of errs) {
      const s = String((e as Error).message) + String((e as Error).stack);
      expect(s).not.toMatch(/secret|4242|10\.4\.2\.42/);
    }
  });

  it("the exit hands net.connect IP literals only (a hostname is refused without any lookup)", async () => {
    const { connectIp } = await import("../src/vpn/egress.js");
    const err = await connectIp({ address: "localhost", family: 4 }, up.port, new AbortController().signal).catch((e) => e);
    expect(err.code).toBe("E_CONNECT_FAILED");
    expect(fromHex("00", 1).length).toBe(1);
  });
});

describe("allowed destination ports (PLR_VPN_ALLOWED_PORTS)", () => {
  let e: TestExit | undefined;
  afterEach(async () => { await e?.close(); e = undefined; });
  it("dials only the listed ports; any other port gets E_EGRESS_DENIED before a dial", async () => {
    const up = await startEchoUpstream();
    try {
      e = await exitWith({ allowedPorts: [up.port] });
      expect(await connectOutcome(e, "127.0.0.1", up.port)).toBe("OK");
      let dialed = 0;
      await e.close();
      e = await exitWith({ allowedPorts: [80, 443], dial: async () => { dialed++; throw new Error("must not dial"); } });
      expect(await connectOutcome(e, "127.0.0.1", up.port)).toBe("E_EGRESS_DENIED");
      expect(dialed).toBe(0);
    } finally { await up.close(); }
  });
});
