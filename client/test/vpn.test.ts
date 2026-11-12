import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { connect as tcpConnect, type Socket } from "node:net";
import { lookup as realLookup } from "node:dns";
import { PlrError, verifyVpnReceipt, toHex, type RegistryReader } from "@plr/shared";
import { VpnClient, startVpn, type VpnStream } from "../src/index.js";
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

const lookups: string[] = [];
const spyLookup = ((host: string, ...rest: unknown[]) => {
  lookups.push(host);
  return (realLookup as (...a: unknown[]) => unknown)(host, ...rest);
}) as typeof realLookup;

function vpn(o: { url?: string; attestTtlMs?: number; registry?: RegistryReader; timeouts?: Record<string, number> } = {}): VpnClient {
  return new VpnClient({
    exitUrl: o.url ?? X.url,
    registry: o.registry ?? X.registry,
    trustedRoot: X.root.publicKey,
    lookup: spyLookup,
    ...(o.attestTtlMs !== undefined ? { attestTtlMs: o.attestTtlMs } : {}),
    ...(o.timeouts ? { timeouts: o.timeouts } : {}),
  });
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PlrError);
    return (e as PlrError).code;
  }
  return "NO_THROW";
}

/** HTTP/1.1 over a stream; collects until EOF / error; half-closes after the response EOF (⇒ c2s FIN ⇒ receipt). */
function httpOver(s: VpnStream | Socket, path: string, body?: string): Promise<{ data: string; error: unknown; ended: boolean }> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let done = false;
    let ended = false;
    const fin = (error: unknown): void => {
      if (!done) {
        done = true;
        ok({ data: Buffer.concat(chunks).toString("latin1"), error, ended });
      }
    };
    s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
    s.on("end", () => {
      ended = true;
      s.end();
      fin(null);
    });
    s.on("error", (e) => fin(e));
    s.on("close", () => fin(null));
    const m = body === undefined ? "GET" : "POST";
    s.write(`${m} ${path} HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n` + (body === undefined ? "\r\n" : `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`));
  });
}

describe("VpnClient — honest exit", () => {
  it("attests, tunnels an HTTP request, and verifies the session receipt (§5)", async () => {
    const c = vpn();
    const v = await c.attest();
    expect(v.rootKind).toBe("MOCK");
    expect(toHex(v.composeHash)).toBe(X.composeHash);
    const s = await c.connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/hello");
    expect(r.error).toBeNull();
    expect(r.ended).toBe(true);
    expect(r.data).toContain("dest-ok:/hello");
    const { receipt, sig } = await s.receipt();
    expect(receipt.compose_hash).toBe(X.composeHash);
    expect(receipt.key_hash).toBe(X.keyHash);
    expect(receipt.ts_open_ms).toBeLessThanOrEqual(receipt.ts_close_ms);
    expect(verifyVpnReceipt(receipt, sig, v.ed25519)).toBe(true);
    expect(Object.keys(receipt).sort()).toEqual(["compose_hash", "key_hash", "seq", "th", "ts_close_ms", "ts_open_ms", "v"]);
  });

  it("large bodies flow both ways intact; writes are framed ≤ 16384 bytes", async () => {
    const body = "z".repeat(300_000) + "END";
    const s = await vpn().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/echo", body);
    expect(r.error).toBeNull();
    expect(r.data.endsWith(body)).toBe(true);
    expect(X.stats.maxC2sPayload).toBe(16384);
    await s.receipt();
  });

  it("reuses a cached attestation (attestTtlMs) but opens one tunnel per connection", async () => {
    const c = vpn({ attestTtlMs: 600_000 });
    for (let i = 0; i < 3; i++) {
      const s = await c.connect("127.0.0.1", D.port);
      expect((await httpOver(s, `/n${i}`)).data).toContain(`dest-ok:/n${i}`);
    }
    expect(X.stats.attestations).toBe(1);
    expect(X.stats.tunnels).toBe(3);
  });

  it("attestTtlMs: 0 attests freshly for every connection; concurrent connects share one attestation", async () => {
    const c0 = vpn({ attestTtlMs: 0 });
    await httpOver(await c0.connect("127.0.0.1", D.port), "/a");
    await httpOver(await c0.connect("127.0.0.1", D.port), "/b");
    expect(X.stats.attestations).toBe(2);
    const c = vpn();
    const streams = await Promise.all([1, 2, 3].map(() => c.connect("127.0.0.1", D.port)));
    expect(X.stats.attestations).toBe(3);
    for (const s of streams) await httpOver(s, "/c");
  });

  it("backpressure: a paused reader keeps the client's buffer bounded while the exit is throttled by TCP", async () => {
    X.behaviour.blast = 16 * 1024 * 1024;
    const s = await vpn().connect("127.0.0.1", D.port);
    s.pause();
    await new Promise((r) => setTimeout(r, 400));
    expect(s.readableLength).toBeLessThan(1024 * 1024);
    expect(X.stats.blastSent).toBeLessThan(X.behaviour.blast);
    let n = 0;
    s.on("data", (c: Buffer) => (n += c.length));
    s.resume();
    await new Promise<void>((ok) => s.on("end", () => ok()));
    expect(n).toBe(16 * 1024 * 1024);
    s.end();
    await s.receipt();
  });

  it("verifyAnchored: E_NOT_ANCHORED until the batch is on-chain, then true; chain positions win", async () => {
    const c = vpn();
    const s1 = await c.connect("127.0.0.1", D.port);
    await httpOver(s1, "/x");
    const { receipt } = await s1.receipt();
    expect(await codeOf(c.verifyAnchored(receipt))).toBe("E_NOT_ANCHORED");
    X.anchorAll();
    expect(await c.verifyAnchored(receipt)).toBe(true);
    // A forged receipt (other th) is not in the anchored tree.
    expect(await codeOf(c.verifyAnchored({ ...receipt, th: "00".repeat(31) + "01" }))).toBe("E_ANCHOR_MISMATCH");
    expect(await codeOf(c.verifyAnchored({ ...receipt, seq: -1 } as never))).toBe("E_BAD_INPUT");
  });
});

describe("VpnClient — CONNECT_ERR is surfaced as its code", () => {
  for (const code of ["E_DNS", "E_EGRESS_DENIED", "E_CONNECT_FAILED", "E_BAD_INPUT"] as const) {
    it(code, async () => {
      X.behaviour.connectErr = code;
      expect(await codeOf(vpn().connect("127.0.0.1", D.port))).toBe(code);
      expect(D.hits()).toBe(0);
    });
  }
  it("real exit-side failures: unknown name → E_DNS, closed port → E_CONNECT_FAILED", async () => {
    expect(await codeOf(vpn().connect("nowhere.test", 80))).toBe("E_DNS");
    const dead = await startDestination();
    const port = dead.port;
    await dead.close();
    expect(await codeOf(vpn().connect("127.0.0.1", port))).toBe("E_CONNECT_FAILED");
  });
  it("a CONNECT_ERR with a code outside the allowed set, or any non-reply frame → E_TUNNEL_PROTOCOL", async () => {
    X.behaviour.rawConnectErr = new TextEncoder().encode(JSON.stringify({ code: "E_COMPOSE_NOT_ALLOWED" }));
    expect(await codeOf(vpn().connect("127.0.0.1", D.port))).toBe("E_TUNNEL_PROTOCOL");
    delete X.behaviour.rawConnectErr;
    X.behaviour.dataBeforeOk = true;
    expect(await codeOf(vpn().connect("127.0.0.1", D.port))).toBe("E_TUNNEL_PROTOCOL");
  });
  it("tunnel endpoint refusing the upgrade → E_TUNNEL_PROTOCOL; exit unreachable → E_BAD_RESPONSE", async () => {
    const c = vpn();
    await c.attest();
    X.behaviour.upgradeStatus = 400;
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_TUNNEL_PROTOCOL");
    const url = X.url;
    await X.close();
    expect(await codeOf(vpn({ url }).connect("127.0.0.1", D.port))).toBe("E_BAD_RESPONSE");
  });
});

describe("VpnClient — verification before every connection (§7)", () => {
  it("revocation between connections applies to the very next one, even with a cached attestation", async () => {
    const c = vpn({ attestTtlMs: 600_000 });
    await httpOver(await c.connect("127.0.0.1", D.port), "/before");
    const tunnels = X.stats.tunnels;
    X.registry.revokeCompose(X.composeHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(X.stats.tunnels).toBe(tunnels);
    X.registry.allowCompose(X.composeHash);
    X.registry.revokeOs(X.osHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_OS_NOT_ALLOWED");
    X.registry.allowOs(X.osHash);
    X.registry.removeInstance(X.keyHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_INSTANCE_NOT_REGISTERED");
    X.registry.putInstance(X.keyHash, { ...X.record, ed25519: "11".repeat(32) });
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_INSTANCE_NOT_REGISTERED");
    X.registry.putInstance(X.keyHash, { ...X.record, expires_at_ms: Date.now() - 1 });
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_INSTANCE_NOT_REGISTERED");
    expect(X.stats.tunnels).toBe(tunnels);
    X.registry.putInstance(X.keyHash, X.record);
    expect((await httpOver(await c.connect("127.0.0.1", D.port), "/after")).data).toContain("dest-ok:/after");
    expect(D.received()).not.toContain("GET / HTTP"); // only the two allowed requests reached it
    expect(D.hits()).toBe(2);
  });

  it("the cached attestation is re-checked with live registry calls (cache hit still calls the registry)", async () => {
    const calls: string[] = [];
    const reg = X.registry;
    const tracing: RegistryReader = {
      chain: reg.chain,
      contractId: reg.contractId,
      getRoot: () => (calls.push("getRoot"), reg.getRoot()),
      isComposeAllowed: (h) => (calls.push("isComposeAllowed"), reg.isComposeAllowed(h)),
      isOsAllowed: (h) => (calls.push("isOsAllowed"), reg.isOsAllowed(h)),
      getInstance: (k) => (calls.push("getInstance"), reg.getInstance(k)),
      getAnchor: (i) => reg.getAnchor(i),
    };
    const c = vpn({ registry: tracing, attestTtlMs: 600_000 });
    await c.attest();
    calls.length = 0;
    await httpOver(await c.connect("127.0.0.1", D.port), "/r");
    expect(calls).toEqual(["isComposeAllowed", "isOsAllowed", "getInstance"]);
    expect(X.stats.attestations).toBe(1);
  });

  it("registry failure on the per-connection re-check → E_REGISTRY_UNAVAILABLE, nothing contacted", async () => {
    let down = false;
    const reg = X.registry;
    const flaky: RegistryReader = {
      chain: reg.chain,
      contractId: reg.contractId,
      getRoot: () => reg.getRoot(),
      isComposeAllowed: (h) => (down ? Promise.reject(new Error("rpc down")) : reg.isComposeAllowed(h)),
      isOsAllowed: (h) => reg.isOsAllowed(h),
      getInstance: (k) => reg.getInstance(k),
      getAnchor: (i) => reg.getAnchor(i),
    };
    const c = vpn({ registry: flaky, attestTtlMs: 600_000 });
    await c.attest();
    down = true;
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_REGISTRY_UNAVAILABLE");
    expect(X.stats.tunnels).toBe(0);
  });

  it("MITM key → E_REPORT_DATA_KEYS; wrong build → E_COMPOSE_NOT_ALLOWED; no tunnel", async () => {
    X.behaviour.mitmKey = true;
    expect(await codeOf(vpn().connect("127.0.0.1", D.port))).toBe("E_REPORT_DATA_KEYS");
    X.behaviour.mitmKey = false;
    X.registry.revokeCompose(X.composeHash);
    expect(await codeOf(vpn().attest())).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(X.stats.tunnels).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("replayed attestation → E_NONCE on the next fresh attestation; no tunnel", async () => {
    X.behaviour.replayAttestation = true;
    await vpn().attest();
    expect(await codeOf(vpn().connect("127.0.0.1", D.port))).toBe("E_NONCE");
    expect(X.stats.tunnels).toBe(0);
  });

  it("rev 1.3: raw-nonce (pre-1.3) or registration-purpose quotes → E_NONCE; no tunnel", async () => {
    for (const purpose of ["raw-nonce", "registration"] as const) {
      X.behaviour.quotePurpose = purpose;
      expect(await codeOf(vpn().connect("127.0.0.1", D.port)), purpose).toBe("E_NONCE");
    }
    expect(X.stats.tunnels).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("invalid destinations are refused locally before any network traffic (E_BAD_INPUT)", async () => {
    const c = vpn();
    for (const [h, p] of [["bad host!", 80], ["01.2.3.4", 80], ["2130706433", 80], ["a..b", 80], ["x".repeat(254), 80], ["ok.test", 0], ["ok.test", 65536], ["ok.test", 1.5]] as const)
      expect(await codeOf(c.connect(h, p)), `${h}:${p}`).toBe("E_BAD_INPUT");
    expect(await codeOf(c.connect(42 as never, 80))).toBe("E_BAD_INPUT");
    expect(X.stats.attestations).toBe(0);
  });
});

describe("VpnStream — tamper and truncation", () => {
  it("a flipped ciphertext byte in the first DATA frame ⇒ E_DECRYPT, nothing delivered", async () => {
    X.behaviour.tamperFirstData = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/tamper");
    expect(r.error).toBeInstanceOf(PlrError);
    expect((r.error as PlrError).code).toBe("E_DECRYPT");
    expect(r.data).toBe("");
    expect(await codeOf(s.receipt())).toBe("E_DECRYPT");
  });

  it("the socket ending before s2c FIN ⇒ E_TRUNCATED, never a clean EOF", async () => {
    X.behaviour.truncateAfterFirstData = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/truncate-" + "y".repeat(40_000));
    expect(r.ended).toBe(false);
    expect((r.error as PlrError).code).toBe("E_TRUNCATED");
    expect(await codeOf(s.receipt())).toBe("E_TRUNCATED");
  });

  it("a partial frame at socket end ⇒ E_TRUNCATED", async () => {
    X.behaviour.cutMidFrame = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/cut");
    expect(r.ended).toBe(false);
    expect((r.error as PlrError).code).toBe("E_TRUNCATED");
  });

  it("a failed tunnel drops the cached attestation (fail closed)", async () => {
    const c = vpn({ attestTtlMs: 600_000 });
    X.behaviour.tamperFirstData = true;
    await httpOver(await c.connect("127.0.0.1", D.port), "/t");
    X.behaviour.tamperFirstData = false;
    await httpOver(await c.connect("127.0.0.1", D.port), "/u");
    expect(X.stats.attestations).toBe(2);
  });
});

describe("VpnStream — receipts", () => {
  it("missing receipt after both FINs ⇒ clean data, receipt() rejects E_TRUNCATED", async () => {
    X.behaviour.noReceipt = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/nr");
    expect(r.error).toBeNull();
    expect(r.data).toContain("dest-ok:/nr");
    expect(await codeOf(s.receipt())).toBe("E_TRUNCATED");
  });
  it("wrong signer ⇒ E_RECEIPT_SIG", async () => {
    X.behaviour.wrongSigner = true;
    const s = await vpn().connect("127.0.0.1", D.port);
    await httpOver(s, "/ws");
    expect(await codeOf(s.receipt())).toBe("E_RECEIPT_SIG");
  });
  for (const [name, f] of [
    ["th", (r: { th: string }) => ({ ...r, th: "ab".repeat(32) })],
    ["compose_hash", (r: { compose_hash: string }) => ({ ...r, compose_hash: "ab".repeat(32) })],
    ["key_hash", (r: { key_hash: string }) => ({ ...r, key_hash: "ab".repeat(32) })],
  ] as const) {
    it(`a correctly signed receipt with another ${name} ⇒ E_RECEIPT_MISMATCH`, async () => {
      X.behaviour.mutateReceipt = f as never;
      const s = await vpn().connect("127.0.0.1", D.port);
      await httpOver(s, "/m");
      expect(await codeOf(s.receipt())).toBe("E_RECEIPT_MISMATCH");
    });
  }
});

// ---------------------------------------------------------------- SOCKS5

/** Raw SOCKS client: sends `bytes`, resolves with everything received until close (or `until` bytes). */
function rawSocks(port: number, bytes: Uint8Array[], until?: number): Promise<{ data: Buffer; sock: Socket }> {
  return new Promise((ok, fail) => {
    const sock = tcpConnect(port, "127.0.0.1");
    let data = Buffer.alloc(0);
    const done = (): void => ok({ data, sock });
    sock.on("error", (e) => (until === undefined ? done() : fail(e)));
    sock.on("connect", () => {
      for (const b of bytes) sock.write(b);
    });
    sock.on("data", (c: Buffer) => {
      data = Buffer.concat([data, c]);
      if (until !== undefined && data.length >= until) done();
    });
    sock.on("close", done);
  });
}

const greeting = Uint8Array.of(5, 1, 0);
const domainReq = (host: string, port: number, cmd = 1): Uint8Array => {
  const h = Buffer.from(host, "latin1");
  return Uint8Array.from([5, cmd, 0, 3, h.length, ...h, port >> 8, port & 0xff]);
};
const ipv4Req = (ip: number[], port: number): Uint8Array => Uint8Array.from([5, 1, 0, 1, ...ip, port >> 8, port & 0xff]);

describe("startVpn — SOCKS5 front end", () => {
  async function proxy(c: VpnClient = vpn()) {
    const p = await startVpn({ port: 0, client: c });
    closers.push(p.close);
    return p;
  }

  it("serves socks5h on loopback; remote DNS: the client never resolves the destination", async () => {
    X.dns.set("dest.test", "127.0.0.1");
    lookups.length = 0;
    const exitPort = new URL(X.url).port;
    const p = await proxy(vpn({ url: `http://localhost:${exitPort}` }));
    expect(p.url).toBe(`socks5h://127.0.0.1:${p.port}`);
    const { data, sock } = await rawSocks(p.port, [greeting, domainReq("dest.test", D.port)], 12);
    expect([...data.subarray(0, 12)]).toEqual([5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const r = await httpOver(sock, "/socks");
    expect(r.data).toContain("dest-ok:/socks");
    expect(lookups).toContain("localhost"); // the exit URL host goes through o.lookup
    expect(lookups).not.toContain("dest.test");
  });

  it("IPv4 ATYP and pipelined greeting + request + payload in one write", async () => {
    const p = await proxy();
    const req = Buffer.from(`GET /pipelined HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n`);
    const { data } = await rawSocks(p.port, [Buffer.concat([greeting, ipv4Req([127, 0, 0, 1], D.port), req])]);
    expect([...data.subarray(0, 12)]).toEqual([5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect(data.toString("latin1")).toContain("dest-ok:/pipelined");
  });

  it("verification failure → REP 0x02 and nothing is contacted", async () => {
    X.registry.revokeCompose(X.composeHash);
    const p = await proxy();
    const { data } = await rawSocks(p.port, [greeting, domainReq("dest.test", D.port)]);
    expect([...data]).toEqual([5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect(X.stats.tunnels).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("CONNECT_ERR codes map per §8: E_EGRESS_DENIED → 2, E_DNS → 4, E_CONNECT_FAILED → 5, bad name → 1", async () => {
    const p = await proxy();
    const rep = async (host: string): Promise<number> => (await rawSocks(p.port, [greeting, domainReq(host, D.port)])).data[3]!;
    X.behaviour.connectErr = "E_EGRESS_DENIED";
    expect(await rep("a.test")).toBe(2);
    X.behaviour.connectErr = "E_DNS";
    expect(await rep("a.test")).toBe(4);
    X.behaviour.connectErr = "E_CONNECT_FAILED";
    expect(await rep("a.test")).toBe(5);
    delete X.behaviour.connectErr;
    expect(await rep("bad host!")).toBe(1);
    expect(D.hits()).toBe(0);
  });

  it("unsupported command → 0x07, unknown ATYP → 0x08, no acceptable method → 0xFF", async () => {
    const p = await proxy();
    expect([...(await rawSocks(p.port, [greeting, domainReq("a.test", 80, 2)])).data]).toEqual([5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect([...(await rawSocks(p.port, [greeting, Uint8Array.of(5, 1, 0, 9, 1, 2, 3, 4, 0, 80)])).data]).toEqual([5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect([...(await rawSocks(p.port, [Uint8Array.of(5, 1, 2)])).data]).toEqual([5, 0xff]);
    expect(X.stats.attestations).toBe(0);
  });

  it("malformed / oversized / slow handshakes are closed without contacting anything", async () => {
    const p = await startVpn({ port: 0, client: vpn(), handshakeTimeoutMs: 300 });
    closers.push(p.close);
    expect((await rawSocks(p.port, [Uint8Array.of(4, 1, 0)])).data.length).toBe(0); // SOCKS4
    expect((await rawSocks(p.port, [Uint8Array.of(5, 0)])).data.length).toBe(0); // NMETHODS 0
    expect([...(await rawSocks(p.port, [greeting, Uint8Array.of(5, 1, 1, 1, 1, 2, 3, 4, 0, 80)])).data]).toEqual([5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0]); // RSV ≠ 0
    expect([...(await rawSocks(p.port, [greeting, Uint8Array.of(5, 1, 0, 3, 0, 0, 80)])).data]).toEqual([5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0]); // empty domain
    expect((await rawSocks(p.port, [new Uint8Array(2000).fill(5)])).data.length).toBeLessThanOrEqual(2);
    const t0 = Date.now();
    expect([...(await rawSocks(p.port, [greeting])).data]).toEqual([5, 0]); // then silence ⇒ closed by the timeout
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(X.stats.attestations).toBe(0);
  });

  it("a tunnel failure resets the SOCKS connection (no clean EOF)", async () => {
    X.behaviour.truncateAfterFirstData = true;
    const p = await proxy();
    const { sock } = await rawSocks(p.port, [greeting, domainReq("127.0.0.1", D.port)], 12);
    const r = await httpOver(sock, "/trunc");
    expect(r.ended).toBe(false);
    expect(r.error).toBeInstanceOf(Error);
    expect((r.error as NodeJS.ErrnoException).code).toBe("ECONNRESET");
  });

  it("binds to loopback literals only", async () => {
    for (const host of ["0.0.0.0", "::", "192.168.1.1", "localhost", "example.com"])
      expect(await codeOf(startVpn({ port: 0, host, client: vpn() })), host).toBe("E_BAD_INPUT");
    expect(await codeOf(startVpn({ port: 0, client: {} as never }))).toBe("E_BAD_INPUT");
  });

  it("close() tears down live tunnels", async () => {
    const p = await startVpn({ port: 0, client: vpn() });
    const { sock } = await rawSocks(p.port, [greeting, domainReq("127.0.0.1", D.port)], 12);
    const closed = new Promise<void>((ok) => sock.on("close", () => ok()));
    await p.close();
    await closed;
  });
});

describe("VpnClient — options", () => {
  it("rejects bad exit URLs, roots, ttl and lookup", () => {
    const base = { exitUrl: X.url, registry: X.registry, trustedRoot: X.root.publicKey };
    const code = (f: () => unknown): string => {
      try {
        f();
      } catch (e) {
        return (e as PlrError).code;
      }
      return "NO_THROW";
    };
    expect(code(() => new VpnClient({ ...base, exitUrl: "ftp://x" }))).toBe("E_BAD_INPUT");
    expect(code(() => new VpnClient({ ...base, exitUrl: "http://u:p@x" }))).toBe("E_BAD_INPUT");
    expect(code(() => new VpnClient({ ...base, exitUrl: "http://x/?q=1" }))).toBe("E_BAD_INPUT");
    expect(code(() => new VpnClient({ ...base, trustedRoot: new Uint8Array(64) }))).toBe("E_ROOT_UNTRUSTED");
    expect(code(() => new VpnClient({ ...base, attestTtlMs: -1 }))).toBe("E_BAD_INPUT");
    expect(code(() => new VpnClient({ ...base, attestTtlMs: 1.5 }))).toBe("E_BAD_INPUT");
    expect(code(() => new VpnClient({ ...base, lookup: "dns" as never }))).toBe("E_BAD_INPUT");
    expect(new VpnClient({ ...base, exitUrl: X.url + "/" }).exitUrl).toBe(X.url);
  });
});
