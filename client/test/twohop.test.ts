// SPEC-VPN §10 two-hop routing, client side, against two in-process fake exits sharing one root + registry.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { connect as tcpConnect, type Socket } from "node:net";
import { lookup as realLookup } from "node:dns";
import { PlrError, verifyVpnReceipt, type RegistryReader } from "@plr/shared";
import { TwoHopClient, startVpn, type TwoHopStream, type VpnStream } from "../src/index.js";
import { startFakeExit, startDestination, type FakeExit, type FakeDestination } from "./fake-exit.js";

let E: FakeExit; // entry, operator "entry-op.test.near" → org-a
let X: FakeExit; // exit, operator "exit-op.test.near" → org-b
let D: FakeDestination;
let exitUrl: string; // by NAME: only the entry can resolve it (its fake DNS)
const closers: (() => Promise<void>)[] = [];
const lookups: string[] = [];
const spyLookup = ((host: string, ...rest: unknown[]) => {
  lookups.push(host);
  return (realLookup as (...a: unknown[]) => unknown)(host, ...rest);
}) as typeof realLookup;

beforeEach(async () => {
  E = await startFakeExit({ operator: "entry-op.test.near" });
  X = await startFakeExit({ root: E.root, registry: E.registry, operator: "exit-op.test.near", bundleSha: "55".repeat(32) });
  D = await startDestination();
  closers.push(E.close, X.close, D.close);
  E.registry.approveOperator("entry-op.test.near", "org-a");
  E.registry.approveOperator("exit-op.test.near", "org-b");
  E.dns.set("exit.hop.test", "127.0.0.1");
  X.dns.set("dest.hop.test", "127.0.0.1");
  exitUrl = `http://exit.hop.test:${new URL(X.url).port}`;
  lookups.length = 0;
});
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

function two(o: { attestTtlMs?: number; registry?: RegistryReader; entryUrl?: string; exitUrl?: string; timeouts?: Record<string, number> } = {}): TwoHopClient {
  return new TwoHopClient({
    entryUrl: o.entryUrl ?? E.url,
    exitUrl: o.exitUrl ?? exitUrl,
    registry: o.registry ?? E.registry,
    trustedRoot: E.root.publicKey,
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

function httpOver(s: VpnStream | Socket, path: string, body?: string): Promise<{ data: string; error: unknown; ended: boolean }> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let done = false;
    let ended = false;
    const fin = (error: unknown): void => {
      if (!done) (done = true), ok({ data: Buffer.concat(chunks).toString("latin1"), error, ended });
    };
    s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
    s.on("end", () => {
      ended = true;
      s.end();
      fin(null);
    });
    s.on("error", fin);
    s.on("close", () => fin(null));
    const m = body === undefined ? "GET" : "POST";
    s.write(`${m} ${path} HTTP/1.1\r\nHost: d\r\nConnection: close\r\n` + (body === undefined ? "\r\n" : `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`));
  });
}

describe("TwoHopClient — honest hops", () => {
  it("attest(): both hops verified, orgs reported; the exit attestation came through the entry", async () => {
    const a = await two().attest();
    expect(a.entryOrg).toBe("org-a");
    expect(a.exitOrg).toBe("org-b");
    expect(a.entry.rootKind).toBe("MOCK");
    expect(Buffer.from(a.exit.x25519).toString("hex")).toBe(X.record.x25519);
    expect(Buffer.from(a.entry.x25519).toString("hex")).toBe(E.record.x25519);
    expect(X.stats.attestations).toBe(1);
    expect(E.stats.destinations).toEqual([`exit.hop.test:${new URL(X.url).port}`]);
    expect(lookups).not.toContain("exit.hop.test"); // the exit's name is resolved by the entry only
  });

  it("connect(): nested tunnel end to end; both receipts verify; the entry saw only the exit's address", async () => {
    const c = two();
    const a = await c.attest();
    const s: TwoHopStream = await c.connect("dest.hop.test", D.port);
    const r = await httpOver(s, "/two-secret");
    expect(r.error).toBeNull();
    expect(r.ended).toBe(true);
    expect(r.data).toContain("dest-ok:/two-secret");
    const { receipt, sig } = await s.receipt();
    expect(receipt.key_hash).toBe(X.keyHash);
    expect(verifyVpnReceipt(receipt, sig, a.exit.ed25519)).toBe(true);
    const e = await s.entryReceipt();
    expect(e.receipt.key_hash).toBe(E.keyHash);
    expect(verifyVpnReceipt(e.receipt, e.sig, a.entry.ed25519)).toBe(true);
    expect(e.receipt.th).not.toBe(receipt.th);
    // Separation: the entry only ever CONNECTed to the exit, the exit to the destination.
    expect(new Set(E.stats.destinations)).toEqual(new Set([`exit.hop.test:${new URL(X.url).port}`]));
    expect(X.stats.destinations).toEqual([`dest.hop.test:${D.port}`]);
    expect(lookups).not.toContain("dest.hop.test");
    expect(lookups).not.toContain("exit.hop.test");
    expect(lookups.every((h) => h === "127.0.0.1")).toBe(true);
  });

  it("large bodies both ways through both tunnels", async () => {
    const body = "q".repeat(200_000) + "END";
    const s = await two().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/echo", body);
    expect(r.error).toBeNull();
    expect(r.data.endsWith(body)).toBe(true);
    await s.receipt();
    await s.entryReceipt();
  });

  it("cached attestations: one attestation per hop, one entry tunnel per connection (+1 for the exit attestation)", async () => {
    const c = two({ attestTtlMs: 600_000 });
    for (let i = 0; i < 3; i++) expect((await httpOver(await c.connect("127.0.0.1", D.port), `/c${i}`)).data).toContain(`dest-ok:/c${i}`);
    expect(E.stats.attestations).toBe(1);
    expect(X.stats.attestations).toBe(1);
    expect(E.stats.tunnels).toBe(4);
    expect(X.stats.tunnels).toBe(3);
  });

  it("per-connection re-checks hit the registry for BOTH hops even on cache hits", async () => {
    const calls: string[] = [];
    const reg = E.registry;
    const tracing: RegistryReader = {
      chain: reg.chain,
      contractId: reg.contractId,
      getRoot: () => reg.getRoot(),
      isComposeAllowed: (h) => (calls.push("isComposeAllowed"), reg.isComposeAllowed(h)),
      isOsAllowed: (h) => (calls.push("isOsAllowed"), reg.isOsAllowed(h)),
      getInstance: (k) => (calls.push(`getInstance:${k === E.keyHash ? "entry" : k === X.keyHash ? "exit" : "?"}`), reg.getInstance(k)),
      getAnchor: (i) => reg.getAnchor(i),
    };
    const c = two({ registry: tracing, attestTtlMs: 600_000 });
    await c.attest();
    calls.length = 0;
    await httpOver(await c.connect("127.0.0.1", D.port), "/r");
    expect(calls).toEqual(["isComposeAllowed", "isOsAllowed", "getInstance:entry", "isComposeAllowed", "isOsAllowed", "getInstance:exit"]);
  });

  it("works behind the SOCKS5 front end (startVpn accepts any connect()-capable client)", async () => {
    const p = await startVpn({ port: 0, client: two() });
    closers.push(p.close);
    const got = await new Promise<string>((ok, fail) => {
      const sock = tcpConnect(p.port, "127.0.0.1");
      let buf = Buffer.alloc(0);
      sock.on("error", fail);
      sock.on("connect", () => {
        const h = Buffer.from("dest.hop.test");
        sock.write(Buffer.concat([Buffer.from([5, 1, 0, 5, 1, 0, 3, h.length]), h, Buffer.from([D.port >> 8, D.port & 0xff])]));
        sock.write("GET /socks-two HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n");
      });
      sock.on("data", (c: Buffer) => (buf = Buffer.concat([buf, c])));
      sock.on("end", () => (sock.end(), ok(buf.toString("latin1"))));
    });
    expect([...Buffer.from(got, "latin1").subarray(0, 12)]).toEqual([5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect(got).toContain("dest-ok:/socks-two");
  });
});

describe("TwoHopClient — operator organizations", () => {
  it("same organization on both hops ⇒ E_SAME_OPERATOR; nothing reaches the exit's tunnel or the destination", async () => {
    E.registry.approveOperator("exit-op.test.near", "org-a");
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_SAME_OPERATOR");
    expect(await codeOf(two().attest())).toBe("E_SAME_OPERATOR");
    expect(X.stats.tunnels).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("unapproved entry operator ⇒ E_OPERATOR_UNAPPROVED before the exit is contacted at all", async () => {
    E.registry.revokeOperator("entry-op.test.near");
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_OPERATOR_UNAPPROVED");
    expect(E.stats.tunnels).toBe(0);
    expect(X.stats.attestations).toBe(0);
  });

  it("unapproved exit operator ⇒ E_OPERATOR_UNAPPROVED; never-approved operator (org_id null) likewise", async () => {
    E.registry.revokeOperator("exit-op.test.near");
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_OPERATOR_UNAPPROVED");
    E.registry.putInstance(X.keyHash, { ...X.record, operator: "stranger.test.near" });
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_OPERATOR_UNAPPROVED");
    expect(X.stats.tunnels).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("an org change or revocation applies to the very next connection, even with cached attestations", async () => {
    const c = two({ attestTtlMs: 600_000 });
    expect((await httpOver(await c.connect("127.0.0.1", D.port), "/1")).data).toContain("dest-ok:/1");
    E.registry.approveOperator("exit-op.test.near", "org-a");
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_SAME_OPERATOR");
    E.registry.approveOperator("exit-op.test.near", "org-b");
    E.registry.revokeOperator("entry-op.test.near");
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_OPERATOR_UNAPPROVED");
    E.registry.approveOperator("entry-op.test.near", "org-a");
    E.registry.removeInstance(X.keyHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_INSTANCE_NOT_REGISTERED");
    E.registry.putInstance(X.keyHash, X.record);
    E.registry.removeInstance(E.keyHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_INSTANCE_NOT_REGISTERED");
    E.registry.putInstance(E.keyHash, E.record);
    expect((await httpOver(await c.connect("127.0.0.1", D.port), "/2")).data).toContain("dest-ok:/2");
    expect(D.hits()).toBe(2);
  });
});

describe("TwoHopClient — attacks and failures", () => {
  it("a MITM'd exit attestation (key swap) is refused through the entry: E_REPORT_DATA_KEYS", async () => {
    X.behaviour.mitmKey = true;
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_REPORT_DATA_KEYS");
    expect(X.stats.tunnels).toBe(0);
  });

  it("a replayed exit attestation ⇒ E_NONCE", async () => {
    X.behaviour.replayAttestation = true;
    await two().attest();
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_NONCE");
  });

  it("an exit build that is not allowed ⇒ E_COMPOSE_NOT_ALLOWED through the entry; a revoked entry build likewise", async () => {
    E.registry.revokeCompose(X.composeHash);
    expect(await codeOf(two().connect("127.0.0.1", D.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(X.stats.tunnels).toBe(0);
    E.registry.allowCompose(X.composeHash);
    const c = two({ attestTtlMs: 600_000 });
    await c.attest();
    E.registry.revokeCompose(E.composeHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    E.registry.allowCompose(E.composeHash);
    E.registry.revokeCompose(X.composeHash);
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_COMPOSE_NOT_ALLOWED");
    expect(D.hits()).toBe(0);
  });

  it("exit tampering with the inner tunnel ⇒ E_DECRYPT on the stream, entry receipt does not verify", async () => {
    X.behaviour.tamperFirstData = true;
    const s = await two().connect("127.0.0.1", D.port);
    const r = await httpOver(s, "/t");
    expect((r.error as PlrError).code).toBe("E_DECRYPT");
    expect(r.data).toBe("");
    expect(await codeOf(s.receipt())).toBe("E_DECRYPT");
    expect(await codeOf(s.entryReceipt())).toBe("E_TRUNCATED");
  });

  it("entry tampering with the outer tunnel ⇒ the stream fails with E_DECRYPT, nothing delivered", async () => {
    E.behaviour.tamperFirstData = true;
    const c = two({ attestTtlMs: 600_000 });
    // The first s2c DATA of the entry tunnel carries the exit's HTTP response: the attestation fetch fails E_DECRYPT.
    expect(await codeOf(c.attest())).toBe("E_DECRYPT");
    E.behaviour.tamperFirstData = false;
    await c.attest();
    E.behaviour.tamperFirstData = true;
    // Same for the `101` of the inner upgrade: the connection is refused before any CONNECT to the destination.
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_DECRYPT");
    expect(X.stats.connects).toBe(0);
    expect(D.hits()).toBe(0);
  });

  it("the entry truncating the outer tunnel ⇒ never a clean EOF", async () => {
    const c = two({ attestTtlMs: 600_000 });
    await c.attest();
    E.behaviour.truncateAfterFirstData = true;
    const r = await c.connect("127.0.0.1", D.port).then(
      (s) => httpOver(s, "/trunc"),
      (e: unknown) => ({ data: "", error: e, ended: false }),
    );
    expect(r.ended).toBe(false);
    expect(r.error).toBeInstanceOf(PlrError);
    expect(["E_TRUNCATED", "E_TUNNEL_PROTOCOL"]).toContain((r.error as PlrError).code);
  });

  it("CONNECT_ERR codes surface from either hop: entry cannot reach the exit ⇒ its code; exit cannot reach the destination ⇒ its code", async () => {
    const c = two({ attestTtlMs: 600_000 });
    await c.attest();
    X.behaviour.connectErr = "E_EGRESS_DENIED";
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_EGRESS_DENIED");
    delete X.behaviour.connectErr;
    expect(await codeOf(c.connect("nowhere.hop.test", 80))).toBe("E_DNS");
    E.behaviour.connectErr = "E_CONNECT_FAILED";
    expect(await codeOf(c.connect("127.0.0.1", D.port))).toBe("E_CONNECT_FAILED");
    expect(await codeOf(two().attest())).toBe("E_CONNECT_FAILED");
    delete E.behaviour.connectErr;
    expect((await httpOver(await c.connect("127.0.0.1", D.port), "/ok")).data).toContain("dest-ok:/ok");
  });

  it("an unreachable exit (entry's DNS does not know it) ⇒ E_DNS from the entry", async () => {
    expect(await codeOf(two({ exitUrl: "http://unknown.hop.test:1" }).attest())).toBe("E_DNS");
    expect(lookups).not.toContain("unknown.hop.test");
  });

  it("an unreachable entry ⇒ E_BAD_RESPONSE; invalid destinations are refused locally", async () => {
    const c = two();
    for (const [h, p] of [["bad host!", 80], ["01.2.3.4", 80], ["ok.test", 0]] as const) expect(await codeOf(c.connect(h, p))).toBe("E_BAD_INPUT");
    expect(E.stats.attestations).toBe(0);
    const url = E.url;
    await E.close();
    expect(await codeOf(two({ entryUrl: url }).connect("127.0.0.1", D.port))).toBe("E_BAD_RESPONSE");
  });

  it("validates its options", () => {
    const code = (f: () => unknown): string => {
      try {
        f();
      } catch (e) {
        return (e as PlrError).code;
      }
      return "NO_THROW";
    };
    const base = { entryUrl: E.url, exitUrl: X.url, registry: E.registry, trustedRoot: E.root.publicKey };
    expect(code(() => new TwoHopClient({ ...base, entryUrl: "ftp://x" }))).toBe("E_BAD_INPUT");
    expect(code(() => new TwoHopClient({ ...base, exitUrl: "http://u:p@x" }))).toBe("E_BAD_INPUT");
    expect(code(() => new TwoHopClient({ ...base, exitUrl: "http://bad_host:80" }))).toBe("E_BAD_INPUT");
    expect(code(() => new TwoHopClient({ ...base, trustedRoot: new Uint8Array(64) }))).toBe("E_ROOT_UNTRUSTED");
    expect(code(() => new TwoHopClient({ ...base, attestTtlMs: -1 }))).toBe("E_BAD_INPUT");
    expect(code(() => new TwoHopClient(null as never))).toBe("E_BAD_INPUT");
    expect(new TwoHopClient({ ...base, exitUrl: X.url + "/" }).exitUrl).toBe(X.url);
  });

  it("verifyAnchored works for the exit (proof fetched through the entry) and the entry", async () => {
    const c = two();
    const s = await c.connect("127.0.0.1", D.port);
    await httpOver(s, "/a");
    const { receipt } = await s.receipt();
    const e = await s.entryReceipt();
    expect(await codeOf(c.verifyAnchored(receipt))).toBe("E_NOT_ANCHORED");
    X.anchorAll();
    expect(await c.verifyAnchored(receipt)).toBe(true);
    E.anchorAll();
    expect(await c.verifyAnchored(e.receipt, "entry")).toBe(true);
  });
});
