// T12: dstack mode (INTERFACES §4.4) — the same exit routes publish INTEL attestations with Intel collateral,
// served from a fake attester whose quote has the INTEL wire format and whose event log follows the dstack rules.
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  INTEL_QE_VENDOR_ID, PlrError, canonicalCollateral, encodeQuote, fromHex, makeEvent, mockOsReport, parseQuote,
  replayRtmr3, reportData, toHex, verifyEventLogDstack,
  type Attester, type CollateralJson, type TdReport, type TdxEvent,
} from "@plr/shared";
import { composeBytes, makeVpnCompose, vpnPolicyOf } from "../src/compose.js";
import { loadExitConfig } from "../src/vpn/config.js";
import { createExit } from "../src/vpn/exit.js";
import { VpnKeys } from "../src/vpn/keys.js";
import { VpnReceiptLog } from "../src/vpn/receipts.js";

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

/** The INTERFACES §1.4 app-compose (values illustrative, as in the policy tests). */
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

/** The synthetic dstack log of INTERFACES §1.3 TV-E2 (built with `makeEvent`, as in T09). */
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

/** The dcap-qvl sample collateral (INTERFACES §1.2), i.e. the real wire form the exit serves. */
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

describe("exit in dstack mode (INTERFACES §1.5, §4.4)", () => {
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
