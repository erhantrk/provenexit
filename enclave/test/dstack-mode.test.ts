// T12: dstack mode (SPEC-TDX §4.4) — the same exit routes publish INTEL attestations with Intel collateral,
// served from a fake attester whose quote has the INTEL wire format and whose event log follows the dstack rules.
// The wiring (collateral in the registration args, the NEAR method name it selects, selfCheckQuote's INTEL branch,
// CollateralCache and DstackAttester) is exercised at the bottom of the file.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createSocketServer, type AddressInfo } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  INTEL_QE_VENDOR_ID, PlrError, canonicalCollateral, encodeQuote, fromHex, makeEvent, mockOsReport, parseQuote,
  replayRtmr3, reportData, toHex, utf8, verifyEventLog, verifyEventLogDstack,
  type Attester, type CollateralJson, type TdReport, type TdxEvent,
} from "@plr/shared";
import { Anchorer } from "../src/anchor.js";
import { CollateralCache } from "../src/attest/collateral-cache.js";
import { DstackAttester } from "../src/attest/dstack-attester.js";
import { selfCheckQuote } from "../src/boot.js";
import { composeBytes, makeVpnCompose, vpnPolicyOf } from "../src/compose.js";
import { RouterKeys } from "../src/keys.js";
import { Logger } from "../src/log.js";
import { NearRegistryWriter } from "../src/near.js";
import type { RegisterArgs, RegistryWriter, AnchorView, AnchorArgs } from "../src/registry-writer.js";
import { ReceiptLog } from "../src/receipts.js";
import { loadExitConfig } from "../src/vpn/config.js";
import { createExit } from "../src/vpn/exit.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { VpnReceiptLog } from "../src/vpn/receipts.js";

// Recording fakes for the two modules whose real counterparts need a PCCS or a live NEAR RPC.
const nearCalls = vi.hoisted(() => [] as {
  contractId: string;
  methodName: string;
  args: Record<string, unknown>;
  gas: bigint;
  deposit: bigint;
}[]);

vi.mock("near-api-js", () => {
  class Account {
    constructor(readonly accountId: string, readonly provider: unknown, readonly signer: unknown) {}
    async callFunction(p: { contractId: string; methodName: string; args: Record<string, unknown>; gas: bigint; deposit: bigint }) {
      nearCalls.push(p);
      return null;
    }
  }
  class JsonRpcProvider {
    constructor(readonly options: unknown) {}
  }
  class KeyPairSigner {
    static fromSecretKey(_key: string) {
      return {};
    }
  }
  return { Account, JsonRpcProvider, KeyPairSigner };
});

const dcap = vi.hoisted(() => ({
  calls: [] as { url: string; quote: number[] }[],
  result: null as unknown,
  fail: null as Error | null,
}));

vi.mock("@phala/dcap-qvl", () => ({
  default: {
    async getCollateral(url: string, quote: Buffer) {
      dcap.calls.push({ url, quote: [...quote] });
      if (dcap.fail) throw dcap.fail;
      return dcap.result;
    },
  },
}));

const enc = (s: string) => new TextEncoder().encode(s);
const EMPTY = new Uint8Array(0);

const IMAGE = `ghcr.io/erhantrk/provenexit-exit@sha256:${"0123456789abcdef".repeat(4)}`;
const DOCKER_COMPOSE = `services:
  exit:
    image: ${IMAGE}
    restart: always
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    logging:
      driver: none
    ports:
      - "18200:18200"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      PLR_ATTESTER: dstack
      PLR_VPN_POLICY_PATH: /app/vpn-policy.json
`;

/** The SPEC-TDX §1.4 app-compose (values illustrative, as in the policy tests). */
const APP_COMPOSE = JSON.stringify({
  manifest_version: 2,
  name: "provenexit-exit",
  runner: "docker-compose",
  docker_compose_file: DOCKER_COMPOSE,
  kms_enabled: true,
  gateway_enabled: true,
  public_logs: false,
  public_sysinfo: false,
  allowed_envs: ["PLR_OPERATOR_KEY"],
  no_instance_id: false,
  secure_time: false,
});
const APP_COMPOSE_BYTES = enc(APP_COMPOSE);
const APP_COMPOSE_HASH = sha256(APP_COMPOSE_BYTES);

/** The synthetic dstack log of SPEC-TDX §1.3 TV-E2 (built with `makeEvent`, as in T09). */
const EVENT_LOG: TdxEvent[] = [
  makeEvent("key-provider", enc("{}")),
  makeEvent("system-preparing", EMPTY),
  makeEvent("app-id", new Uint8Array(20).fill(0x11)),
  makeEvent("compose-hash", APP_COMPOSE_HASH),
  makeEvent("instance-id", new Uint8Array(20).fill(0x22)),
  makeEvent("boot-mr-done", EMPTY),
  makeEvent("system-ready", EMPTY),
];
const RTMR3 = replayRtmr3(EVENT_LOG);

/** The dcap-qvl sample collateral (SPEC-TDX §1.2), i.e. the real wire form the exit serves. */
const COLLATERAL: CollateralJson = canonicalCollateral(
  JSON.parse(readFileSync(new URL("../../packages/shared/test/vectors/dcap/tdx_quote_collateral.json", import.meta.url), "utf8")),
);

interface FakeAttester extends Attester {
  appCompose(): Promise<string>;
}

/** A dstack stand-in: an INTEL-format quote over the asked report_data, and the measured app-compose. */
function fakeAttester(): FakeAttester {
  return {
    async getQuote(rd: Uint8Array) {
      const base = mockOsReport();
      const report: TdReport = { ...base, reportData: rd, rtmr: [base.rtmr[0], base.rtmr[1], base.rtmr[2], RTMR3] };
      return { quote: encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, report, randomBytes(64)), eventLog: EVENT_LOG };
    },
    async appCompose() {
      return APP_COMPOSE;
    },
  };
}

/** An exit in dstack mode: `composeBytes` is the dstack app-compose, the enforced policy comes from the image. */
async function startDstackExit(o: { collateral: (quote: Uint8Array) => Promise<CollateralJson> }) {
  const keys = VpnKeys.generate();
  const policy = vpnPolicyOf(composeBytes(makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback: true })));
  const exit = createExit({
    attester: fakeAttester(),
    keys,
    composeBytes: APP_COMPOSE_BYTES,
    policy,
    receipts: new VpnReceiptLog(),
    rootKind: "INTEL",
    collateral: o.collateral,
  });
  await new Promise<void>((ok) => exit.server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${(exit.server.address() as AddressInfo).port}`;
  return {
    url,
    keys,
    close: () =>
      new Promise<void>((ok) => {
        exit.destroyTunnels();
        exit.server.close(() => ok());
        exit.server.closeAllConnections();
      }),
  };
}

describe("exit in dstack mode (SPEC-TDX §1.5, §4.4)", () => {
  it("GET /v1/attestation publishes root_kind INTEL, the app-compose and the collateral", async () => {
    const asked: Uint8Array[] = [];
    const e = await startDstackExit({
      collateral: async (q) => {
        asked.push(q.slice());
        return COLLATERAL;
      },
    });
    try {
      const nonce = randomBytes(32);
      const res = await fetch(`${e.url}/v1/attestation?nonce=${toHex(nonce)}`);
      expect(res.status).toBe(200);
      const b = (await res.json()) as Record<string, unknown>;

      expect(b.v).toBe("PLR-v1");
      expect(b.root_kind).toBe("INTEL");
      expect(b.app_compose).toBe(APP_COMPOSE);
      expect(b.x25519).toBe(toHex(e.keys.x25519));
      expect(b.ed25519).toBe(toHex(e.keys.ed25519));

      // The collateral is the canonical wire form: every field a string, the binary ones lowercase hex.
      expect(b.collateral).toEqual(COLLATERAL);
      const collateral = b.collateral as Record<string, string>;
      expect(collateral.root_ca_crl).toMatch(/^(?:[0-9a-f]{2})+$/);
      expect(Object.keys(collateral).sort()).toEqual(Object.keys(COLLATERAL).sort());

      // The quote is an INTEL-format TDX v4 quote over this session's report_data, and the log is a dstack log.
      const quoteHex = b.quote as string;
      const parsed = parseQuote(fromHex(quoteHex), "INTEL");
      expect(toHex(parsed.report.reportData)).toBe(toHex(reportData(e.keys.x25519, e.keys.ed25519, nonce)));
      const boot = verifyEventLogDstack(b.event_log as TdxEvent[], parsed.report.rtmr[3]);
      expect(toHex(boot.composeHash)).toBe(toHex(APP_COMPOSE_HASH));

      // The collateral provider saw exactly the served quote.
      expect(asked).toHaveLength(1);
      expect(toHex(asked[0]!)).toBe(quoteHex);
    } finally {
      await e.close();
    }
  });

  it("a collateral failure is 503 E_UPSTREAM, never a partial bundle", async () => {
    const e = await startDstackExit({ collateral: async () => Promise.reject(new Error("pccs down")) });
    try {
      const res = await fetch(`${e.url}/v1/attestation?nonce=${toHex(randomBytes(32))}`);
      expect(res.status).toBe(503);
      expect(await res.json()).toEqual({ error: "E_UPSTREAM" });
    } finally {
      await e.close();
    }
  });
});

describe("loadExitConfig: PLR_ATTESTER selects mock (default) or dstack", () => {
  const mockEnv = { PLR_TDX_SOCKET: "/tmp/q.sock", PLR_APP_COMPOSE_PATH: "/tmp/c.json" };

  it("mock is the default and keeps the existing requirements", () => {
    const c = loadExitConfig(mockEnv);
    expect([c.attester, c.tdxSocket, c.composePath, c.policyPath, c.pccsUrl]).toEqual([
      "mock", "/tmp/q.sock", "/tmp/c.json", null, "https://pccs.phala.network",
    ]);
    expect(() => loadExitConfig({ PLR_APP_COMPOSE_PATH: "/tmp/c.json" })).toThrow(/PLR_TDX_SOCKET/);
    expect(() => loadExitConfig({ PLR_TDX_SOCKET: "/tmp/q.sock" })).toThrow(/PLR_APP_COMPOSE_PATH/);
  });

  it("dstack mode needs PLR_VPN_POLICY_PATH, not the mock socket or compose path", () => {
    const c = loadExitConfig({ PLR_ATTESTER: "dstack", PLR_VPN_POLICY_PATH: "/app/vpn-policy.json" });
    expect([c.attester, c.policyPath, c.tdxSocket, c.composePath, c.pccsUrl]).toEqual([
      "dstack", "/app/vpn-policy.json", null, null, "https://pccs.phala.network",
    ]);
    expect(loadExitConfig({ PLR_ATTESTER: "dstack", PLR_VPN_POLICY_PATH: "/app/vpn-policy.json", PLR_PCCS_URL: "https://pccs.example.net" }).pccsUrl)
      .toBe("https://pccs.example.net");
    // Missing policy path throws, even with the MOCK variables set.
    expect(() => loadExitConfig({ PLR_ATTESTER: "dstack" })).toThrow(PlrError);
    expect(() => loadExitConfig({ PLR_ATTESTER: "dstack", ...mockEnv })).toThrow(/PLR_VPN_POLICY_PATH/);
  });

  it("PLR_ATTESTER accepts exactly mock|dstack; PLR_PCCS_URL must be https", () => {
    for (const v of ["Dstack", "phala", " mock", "mocks"]) {
      expect(() => loadExitConfig({ ...mockEnv, PLR_ATTESTER: v }), v).toThrow(/PLR_ATTESTER/);
    }
    expect(loadExitConfig({ ...mockEnv, PLR_ATTESTER: "mock" }).attester).toBe("mock");
    for (const u of ["http://pccs.phala.network", "not a url", "ftp://pccs.example.net"]) {
      expect(() => loadExitConfig({ ...mockEnv, PLR_PCCS_URL: u }), u).toThrow(/PLR_PCCS_URL/);
    }
  });
});

// ---------------------------------------------------------------------------------------------------------------
// T12 wiring (steps 4, 7, 8). These were never executed: nothing checked that the collateral reaches the
// registration args, that its presence selects register_instance_tdx, that selfCheckQuote uses the dstack event
// log in INTEL mode, that CollateralCache caches for its TTL, or that DstackAttester speaks the dstack socket.
// ---------------------------------------------------------------------------------------------------------------

const HERE = fileURLToPath(new URL(".", import.meta.url));
const DS_DEPOSIT = 100_000_000_000_000_000_000_000n;
const GAS_300 = 300n * 1_000_000_000_000n;

/** A quote service returning an INTEL-format quote over the asked report_data and one fixed event log. */
function intelAttester(eventLog: TdxEvent[], rtmr3 = replayRtmr3(eventLog)): Attester {
  return {
    async getQuote(rd: Uint8Array) {
      const base = mockOsReport();
      const report: TdReport = { ...base, reportData: rd, rtmr: [base.rtmr[0], base.rtmr[1], base.rtmr[2], rtmr3] };
      return { quote: encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, report, randomBytes(64)), eventLog };
    },
  };
}

/** The registration half of the registry (SPEC §7); every accepted call is recorded for the assertions. */
class FakeRegistrationChain implements RegistryWriter {
  readonly contractId = "vpnregistry.test.near";
  readonly operatorId = "pe-op-erhan.testnet";
  readonly submitted: RegisterArgs[] = [];

  async registerInstance(a: RegisterArgs): Promise<void> {
    this.submitted.push(a);
  }
  async anchorReceipts(_a: AnchorArgs): Promise<unknown> {
    return null;
  }
  async getInstanceNextSeq(): Promise<number | null> {
    return null;
  }
  async getInstanceOperator(): Promise<string | null> {
    return this.operatorId;
  }
  async anchorCount(): Promise<number> {
    return 0;
  }
  async getAnchor(_id: number): Promise<AnchorView | null> {
    return null;
  }
}

describe("INTEL registration carries the collateral and selects register_instance_tdx (T12 steps 7, 8)", () => {
  beforeEach(() => {
    nearCalls.length = 0;
    dcap.calls.length = 0;
    dcap.fail = null;
    dcap.result = COLLATERAL;
  });

  it("NearRegistryWriter.registerInstance: collateral ⇒ register_instance_tdx, no collateral ⇒ register_instance", async () => {
    const key = "ed25519:" + "1".repeat(64); // not a key: never used, the Account is faked
    const w = new NearRegistryWriter({
      rpcUrl: "https://rpc.test.fastnear.com",
      contractId: "vpnregistry.test.near",
      operatorId: "pe-op-erhan.testnet",
      operatorKey: key,
      registerDeposit: DS_DEPOSIT,
    });
    const args: RegisterArgs = { quote: "00", event_log: [], app_compose: "{}", x25519: "11".repeat(32), ed25519: "22".repeat(32) };

    await w.registerInstance(args);
    await w.registerInstance({ ...args, collateral: JSON.stringify(COLLATERAL) });

    expect(nearCalls).toHaveLength(2);
    expect(nearCalls[0]).toEqual({ contractId: "vpnregistry.test.near", methodName: "register_instance", args, gas: GAS_300, deposit: DS_DEPOSIT });
    // Same 300 Tgas and the same deposit: only the method name changes (SPEC-TDX §2.3).
    expect(nearCalls[1]).toEqual({
      contractId: "vpnregistry.test.near",
      methodName: "register_instance_tdx",
      args: { ...args, collateral: JSON.stringify(COLLATERAL) },
      gas: GAS_300,
      deposit: DS_DEPOSIT,
    });
  });

  it("Anchorer.register adds collateral = JSON.stringify(await cache.get(quote)), and only in INTEL mode", async () => {
    const lines: string[] = [];
    const log = new Logger("plr-router", (l) => lines.push(l));
    const keys = RouterKeys.generate();
    const chain = new FakeRegistrationChain();
    const cache = new CollateralCache("https://pccs.example.net", 3_600_000, () => 1_000);

    const intel = new Anchorer({ chain, attester: intelAttester(EVENT_LOG), keys, receipts: new ReceiptLog(), composeBytes: APP_COMPOSE_BYTES, log, collateral: cache });
    expect(await intel.register()).toBe(true);
    expect(chain.submitted).toHaveLength(1);
    expect(chain.submitted[0]!.collateral).toBe(JSON.stringify(COLLATERAL));
    // The collateral was fetched from the PCCS for exactly the quote that was submitted.
    expect(dcap.calls).toHaveLength(1);
    expect(dcap.calls[0]!.url).toBe("https://pccs.example.net");
    expect(toHex(new Uint8Array(dcap.calls[0]!.quote))).toBe(chain.submitted[0]!.quote);

    // MOCK mode (no CollateralCache): the args carry no collateral key at all.
    const mockChain = new FakeRegistrationChain();
    const mock = new Anchorer({ chain: mockChain, attester: intelAttester(EVENT_LOG), keys, receipts: new ReceiptLog(), composeBytes: APP_COMPOSE_BYTES, log });
    expect(await mock.register()).toBe(true);
    expect("collateral" in mockChain.submitted[0]!).toBe(false);
  });

  it("a PCCS failure fails the registration (it never registers without collateral)", async () => {
    dcap.fail = new Error("pccs down");
    const lines: string[] = [];
    const chain = new FakeRegistrationChain();
    const cache = new CollateralCache("https://pccs.example.net");
    const anchorer = new Anchorer({
      chain, attester: intelAttester(EVENT_LOG), keys: RouterKeys.generate(), receipts: new ReceiptLog(),
      composeBytes: APP_COMPOSE_BYTES, log: new Logger("plr-router", (l) => lines.push(l)), collateral: cache,
    });
    expect(await anchorer.register()).toBe(false);
    expect(chain.submitted).toHaveLength(0);
    expect(anchorer.lastError).toBe("E_REGISTRY_UNAVAILABLE");
  });
});

describe("selfCheckQuote in INTEL mode uses the dstack event log (T12 step 4)", () => {
  const keys = RouterKeys.generate();
  /** TV-E2's synthetic dstack log: `key-provider` before the boot sequence, which a MOCK-format log never has. */
  const dstackLog: TdxEvent[] = [
    makeEvent("key-provider", utf8("{}")),
    ...EVENT_LOG,
  ];

  it("accepts a dstack log whose boot hash is the compose being measured", async () => {
    await expect(selfCheckQuote(intelAttester(dstackLog), keys, APP_COMPOSE_HASH, "INTEL")).resolves.toBeUndefined();
    // The same log is not a valid MOCK log (its first event is not `system-preparing`): INTEL mode really did
    // pick verifyEventLogDstack rather than verifyEventLog.
    expect(codeOfEventLog(dstackLog)).toBe("E_EVENT_LOG");
  });

  it("rejects a log that is not a V1 dstack log (digest mismatch ⇒ E_EVENT_LOG)", async () => {
    const v2 = dstackLog.map((e, i) => (i === 0 ? { ...e, digest: toHex(new Uint8Array(48).fill(0xab)) } : e));
    await expect(selfCheckQuote(intelAttester(v2), keys, APP_COMPOSE_HASH, "INTEL")).rejects.toThrow(/E_EVENT_LOG/);
  });

  it("fails closed when the measured compose hash is not the one being served (E_COMPOSE_MISMATCH)", async () => {
    await expect(selfCheckQuote(intelAttester(dstackLog), keys, new Uint8Array(32).fill(0x5a), "INTEL")).rejects.toThrow(/E_COMPOSE_MISMATCH/);
  });
});

/** The error code `verifyEventLog` (MOCK rules) gives for `log`, or "ok". */
function codeOfEventLog(log: TdxEvent[]): string {
  try {
    verifyEventLog(log, replayRtmr3(log));
    return "ok";
  } catch (e) {
    return e instanceof PlrError ? e.code : "not-plr";
  }
}

describe("CollateralCache (SPEC-TDX §4.3)", () => {
  beforeEach(() => {
    dcap.calls.length = 0;
    dcap.fail = null;
    dcap.result = COLLATERAL;
  });

  it("refetches only after its TTL (injected clock) and canonicalises number arrays to hex", async () => {
    let now = 10_000;
    const cache = new CollateralCache("https://pccs.phala.network", 60_000, () => now);
    const quote = new Uint8Array([0x04, 0x00, 0x02]);

    const first = await cache.get(quote);
    expect(first).toEqual(COLLATERAL);
    expect(dcap.calls).toHaveLength(1);
    now += 59_999;
    expect(await cache.get(quote)).toBe(first); // same object: no refetch
    expect(dcap.calls).toHaveLength(1);
    now += 1;
    await cache.get(quote);
    expect(dcap.calls).toHaveLength(2);

    // getCollateral returns binary fields as number arrays; the cache stores the canonical hex form.
    const raw = JSON.parse(readFileSync(new URL("../../packages/shared/test/vectors/dcap/tdx_quote_collateral.json", import.meta.url), "utf8")) as Record<string, unknown>;
    const arrays = { ...raw, root_ca_crl: [...fromHex(raw.root_ca_crl as string)] };
    dcap.result = arrays;
    const fresh = new CollateralCache("https://pccs.phala.network", 60_000, () => now);
    const got = await fresh.get(quote);
    expect(got.root_ca_crl).toBe(raw.root_ca_crl);
    expect(got).toEqual(COLLATERAL);
  });

  it("propagates a PCCS error and does not cache the failure", async () => {
    const cache = new CollateralCache("https://pccs.phala.network");
    dcap.fail = new Error("pccs down");
    await expect(cache.get(new Uint8Array(8))).rejects.toThrow("pccs down");
    dcap.fail = null;
    await expect(cache.get(new Uint8Array(8))).resolves.toEqual(COLLATERAL);
    expect(dcap.calls).toHaveLength(2);
  });
});

/** A UNIX-socket stub of the dstack guest agent: the two RPCs DstackAttester uses, over raw HTTP. */
async function startDstackStub(sockPath: string) {
  const seen: { path: string; body: unknown }[] = [];
  const spike = JSON.parse(readFileSync(new URL("../../fixtures/phala-spike/phala-dump.json", import.meta.url), "utf8")) as {
    quote: string;
    event_log: string;
    info: { tcb_info: string };
  };
  const handler = (path: string, body: unknown): unknown => {
    if (path === "/GetQuote") return { quote: `0x${spike.quote}`, event_log: spike.event_log };
    if (path === "/Info") return { tcb_info: spike.info.tcb_info };
    return { error: `unknown ${path}` };
  };
  const server = createSocketServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on("error", () => undefined);
    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf("\r\n\r\n");
      if (headerEnd < 0) return;
      const head = buf.subarray(0, headerEnd).toString("latin1");
      const len = Number(/content-length:\s*(\d+)/i.exec(head)?.[1] ?? "0");
      if (buf.length < headerEnd + 4 + len) return;
      const path = head.split("\r\n")[0]!.split(" ")[1]!;
      const body = JSON.parse(buf.subarray(headerEnd + 4, headerEnd + 4 + len).toString("utf8") || "{}") as unknown;
      seen.push({ path, body });
      const out = JSON.stringify(handler(path, body));
      sock.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(out)}\r\n\r\n${out}`);
    });
  });
  await new Promise<void>((ok) => server.listen(sockPath, ok));
  return { seen, spike, close: () => new Promise<void>((ok) => { server.close(() => ok()); }) };
}

const sockDirs: string[] = [];
afterAll(() => {
  for (const d of sockDirs) rmSync(d, { recursive: true, force: true });
});

describe("DstackAttester (SPEC-TDX §4.2) against a dstack socket stub", () => {
  it("returns the real spike quote and only the IMR3 events; app-compose comes from /Info", async () => {
    const dir = mkdtempSync(join(HERE, "dstack-sock-"));
    sockDirs.push(dir);
    const stub = await startDstackStub(join(dir, "d.sock"));
    try {
      const att = new DstackAttester(join(dir, "d.sock"));
      const rd = new Uint8Array(64).fill(7);
      const r = await att.getQuote(rd);
      const spikeLog = JSON.parse(stub.spike.event_log) as Array<Record<string, unknown>>;
      const imr3 = spikeLog.filter((e) => e.imr === 3);

      // The `0x` prefix is stripped and the quote is the one the guest agent returned.
      expect(toHex(r.quote)).toBe(stub.spike.quote);
      expect(r.eventLog).toHaveLength(imr3.length);
      expect(r.eventLog).toEqual(imr3.map((e) => ({
        imr: 3,
        event_type: e.event_type as number,
        digest: String(e.digest),
        event: String(e.event),
        event_payload: String(e.event_payload),
      })));
      expect(stub.seen[0]).toEqual({ path: "/GetQuote", body: { report_data: toHex(rd) } });

      const tcb = JSON.parse(stub.spike.info.tcb_info) as { app_compose: string };
      await expect(att.appCompose()).resolves.toBe(tcb.app_compose);
      expect(stub.seen[1]).toEqual({ path: "/Info", body: {} });
    } finally {
      await stub.close();
    }
  });

  it("refuses a report_data that is not exactly 64 bytes, before any RPC", async () => {
    const dir = mkdtempSync(join(HERE, "dstack-sock-"));
    sockDirs.push(dir);
    const stub = await startDstackStub(join(dir, "d.sock"));
    try {
      const att = new DstackAttester(join(dir, "d.sock"));
      await expect(att.getQuote(new Uint8Array(63))).rejects.toThrow(/E_BAD_INPUT/);
      await expect(att.getQuote(new Uint8Array(65))).rejects.toThrow(/E_BAD_INPUT/);
      await expect(att.getQuote("00".repeat(64) as unknown as Uint8Array)).rejects.toThrow(/E_BAD_INPUT/);
      expect(stub.seen).toHaveLength(0);
    } finally {
      await stub.close();
    }
  });
});
