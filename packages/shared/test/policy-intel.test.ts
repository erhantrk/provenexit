// INTERFACES §3.1 — the INTEL branch of verifyAttestation (dcap TCB, dstack log, compose policy).
// Real Intel quotes cannot be minted for our report_data, so the DCAP call goes through a stub verifier that keeps
// the same contract: it requires `ctx.collateral` and reports the accepted status in `lastStatus`.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import {
  CHECKS, INTEL_QE_VENDOR_ID, INTEL_ROOT_P256, MAX_DSTACK_COMPOSE_BYTES, MemoryRegistry, MockVerifier, PlrError,
  canonicalCollateral, encodeQuote, keyHash, makeEvent, mockOsReport, osMeasurement, parseQuote, registrationReportData,
  reportData, replayRtmr3, toHex, verifyAttestation, type AttestationBundle, type InstanceRecord, type QuoteVerifier,
  type TdxEvent, type TdReport,
} from "../src/index.js";
import { enc, fixture, hex, randomBytes, sha256 } from "./helpers.js";

const EMPTY = new Uint8Array(0);
const NOW_MS = 1_750_377_600_000;
const OPERATOR = "op.test.near";

/** Canonical wire form of the dcap-qvl sample collateral (INTERFACES §1.2). */
const COLLATERAL = canonicalCollateral(
  JSON.parse(readFileSync(new URL("./vectors/dcap/tdx_quote_collateral.json", import.meta.url), "utf8")),
);

const DIGEST = "0123456789abcdef".repeat(4);
const IMAGE = `ghcr.io/erhantrk/provenexit-exit@sha256:${DIGEST}`;

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
      PLR_VPN_PORT: "18200"
`;

/** The INTERFACES §1.4 app-compose (values illustrative). */
function appCompose(dockerComposeFile = DOCKER_COMPOSE): string {
  return JSON.stringify({
    manifest_version: 2,
    name: "provenexit-exit",
    runner: "docker-compose",
    docker_compose_file: dockerComposeFile,
    kms_enabled: true,
    gateway_enabled: true,
    public_logs: false,
    public_sysinfo: false,
    allowed_envs: ["PLR_OPERATOR_KEY"],
    no_instance_id: false,
    secure_time: false,
  });
}

type Seen = { collateral?: unknown; nowSecs?: number };

/** Stub DCAP verifier: no collateral ⇒ E_COLLATERAL, otherwise "UpToDate" (as DcapQvlVerifier reports it). */
function stubVerifier(seen: Seen[] = []): QuoteVerifier & { lastStatus?: string } {
  return {
    rootKind: "INTEL",
    rootPublicKey: INTEL_ROOT_P256,
    verify(q, ctx) {
      if (!ctx?.collateral) throw new PlrError("E_COLLATERAL");
      seen.push({ collateral: ctx.collateral, nowSecs: ctx.nowSecs });
      this.lastStatus = "UpToDate";
      return parseQuote(q, "INTEL");
    },
  };
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

interface IntelFixture {
  registry: MemoryRegistry;
  contractId: string;
  keyHash: Uint8Array;
  x25519: Uint8Array;
  ed25519: Uint8Array;
  composeHash: Uint8Array;
  osHash: Uint8Array;
  bundle(nonce: Uint8Array): AttestationBundle;
  /** A quote over `registrationReportData(keys, contractId, OPERATOR)`, same boot as the session quote. */
  registrationQuote(): Uint8Array;
}

function intelFixture(o: { compose?: string; verifiesOnChain?: boolean } = {}): IntelFixture {
  const compose = o.compose ?? appCompose();
  const composeHash = sha256(enc(compose));
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  const kh = keyHash(xp, ep);
  const os = osMeasurement(mockOsReport());
  const log: TdxEvent[] = [
    makeEvent("key-provider", enc("{}")),
    makeEvent("system-preparing", EMPTY),
    makeEvent("app-id", new Uint8Array(20).fill(0x11)),
    makeEvent("compose-hash", composeHash),
    makeEvent("instance-id", new Uint8Array(20).fill(0x22)),
    makeEvent("boot-mr-done", EMPTY),
    makeEvent("system-ready", EMPTY),
  ];
  const rtmr3 = replayRtmr3(log);
  const base = mockOsReport();
  const quoteFor = (rd: Uint8Array): Uint8Array => {
    const report: TdReport = { ...base, reportData: rd, rtmr: [base.rtmr[0], base.rtmr[1], base.rtmr[2], rtmr3] };
    return encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, report, randomBytes(64));
  };
  const record: InstanceRecord = {
    compose_hash: hex(composeHash), os_measurement: hex(os), x25519: hex(xp), ed25519: hex(ep),
    operator: OPERATOR, org_id: null, registered_at_ms: 1, expires_at_ms: NOW_MS + 3_600_000, next_seq: 0,
  };
  const contractId = "registry.memory";
  const registrationQuote = quoteFor(registrationReportData(xp, ep, contractId, OPERATOR));
  const registry = new MemoryRegistry({
    root: { kind: "INTEL", p256: toHex(INTEL_ROOT_P256) },
    compose: [hex(composeHash)],
    os: [hex(os)],
    instances: { [hex(kh)]: record },
    contractId,
    now: () => NOW_MS,
    verifiesOnChain: o.verifiesOnChain ?? true,
    registrationQuotes: { [hex(kh)]: hex(registrationQuote) },
  });
  return {
    registry, contractId, keyHash: kh, x25519: xp, ed25519: ep, composeHash, osHash: os,
    bundle(nonce) {
      return {
        v: "PLR-v1", root_kind: "INTEL", quote: hex(quoteFor(reportData(xp, ep, nonce))), event_log: log,
        app_compose: compose, x25519: hex(xp), ed25519: hex(ep), collateral: COLLATERAL,
      };
    },
    registrationQuote: () => registrationQuote,
  };
}

function run(f: IntelFixture, bundle: AttestationBundle, nonce: Uint8Array, verifier: QuoteVerifier, registry = f.registry) {
  return verifyAttestation({ bundle, nonce, verifier, registry, trustedRoot: INTEL_ROOT_P256, now: NOW_MS });
}

describe("verifyAttestation — INTEL branch (INTERFACES §3.1)", () => {
  it("passes { collateral, nowSecs } to the verifier and reports TCB, images and every check in order", async () => {
    const f = intelFixture();
    const n = randomBytes(32);
    const seen: Seen[] = [];
    const v = await run(f, f.bundle(n), n, stubVerifier(seen));

    expect(seen).toHaveLength(1);
    expect(seen[0]!.collateral).toEqual(COLLATERAL);
    expect(seen[0]!.nowSecs).toBe(NOW_MS / 1000);
    expect(v.rootKind).toBe("INTEL");
    expect(v.tcbStatus).toBe("UpToDate");
    expect(v.images).toEqual([IMAGE]);
    expect(v.composeHash).toEqual(f.composeHash);
    expect(v.osMeasurement).toEqual(f.osHash);
    expect(v.keyHash).toEqual(f.keyHash);
    expect(v.checks).toContain(CHECKS.TCB);
    expect(v.checks).toContain(CHECKS.COMPOSE_POLICY);
    // TCB right after QUOTE_SIG, COMPOSE_POLICY right after COMPOSE (INTERFACES §3.1).
    expect(v.checks).toEqual([
      CHECKS.RESPONSE, CHECKS.QUOTE_FORMAT, CHECKS.TEE_TYPE, CHECKS.ROOT, CHECKS.QUOTE_SIG, CHECKS.TCB, CHECKS.DEBUG,
      CHECKS.REPORT_DATA_KEYS, CHECKS.NONCE, CHECKS.EVENT_LOG, CHECKS.RTMR3, CHECKS.COMPOSE, CHECKS.COMPOSE_POLICY,
      CHECKS.COMPOSE_ALLOWED, CHECKS.OS_ALLOWED, CHECKS.INSTANCE,
    ]);
  });

  it("requires collateral: a missing or malformed one is E_BAD_RESPONSE", async () => {
    const f = intelFixture();
    const n = randomBytes(32);
    const { collateral: _absent, ...withoutCollateral } = f.bundle(n);
    expect(await codeOf(run(f, withoutCollateral as AttestationBundle, n, stubVerifier()))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(run(f, { ...f.bundle(n), collateral: { root_ca_crl: "00" } }, n, stubVerifier()))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(run(f, { ...f.bundle(n), collateral: [] as unknown as Record<string, unknown> }, n, stubVerifier()))).toBe("E_BAD_RESPONSE");
  });

  it("allows an app-compose above the MOCK limit, up to MAX_DSTACK_COMPOSE_BYTES", async () => {
    const padding = "x".repeat(9 * 1024);
    const big = appCompose(`${DOCKER_COMPOSE}    labels:\n      pad: ${padding}\n`);
    expect(enc(big).length).toBeGreaterThan(8 * 1024);
    expect(enc(big).length).toBeLessThan(MAX_DSTACK_COMPOSE_BYTES);

    const f = intelFixture({ compose: big });
    const n = randomBytes(32);
    expect((await run(f, f.bundle(n), n, stubVerifier())).images).toEqual([IMAGE]);

    // One byte over the INTEL bound is rejected in parseBundle.
    const tooBig = appCompose(`${DOCKER_COMPOSE}    labels:\n      pad: ${"x".repeat(33 * 1024)}\n`);
    expect(enc(tooBig).length).toBeGreaterThan(MAX_DSTACK_COMPOSE_BYTES);
    const g = intelFixture({ compose: tooBig });
    expect(await codeOf(run(g, g.bundle(n), n, stubVerifier()))).toBe("E_BAD_RESPONSE");

    // MOCK keeps the 8 KiB bound.
    const mock = fixture({ composeStr: big });
    expect(await codeOf(verifyAttestation({
      bundle: await mock.bundle(n), nonce: n, verifier: new MockVerifier(mock.root.publicKey), registry: mock.registry,
      trustedRoot: mock.root.publicKey,
    }))).toBe("E_BAD_RESPONSE");
  });

  it("E_COMPOSE_POLICY: the exit service does not disable logging", async () => {
    const noisy = appCompose(DOCKER_COMPOSE.replace("    logging:\n      driver: none\n", ""));
    expect(noisy).not.toContain("logging");
    const f = intelFixture({ compose: noisy });
    const n = randomBytes(32);
    expect(await codeOf(run(f, f.bundle(n), n, stubVerifier()))).toBe("E_COMPOSE_POLICY");
  });

  it("E_COMPOSE_POLICY: an image is not pinned by digest", async () => {
    const f = intelFixture({ compose: appCompose(DOCKER_COMPOSE.replace(IMAGE, "node:22")) });
    const n = randomBytes(32);
    expect(await codeOf(run(f, f.bundle(n), n, stubVerifier()))).toBe("E_COMPOSE_POLICY");
  });

  it("uses the dstack event-log rules: a 300-byte payload (over SPEC §3's 256) replays fine", async () => {
    const f = intelFixture();
    const n = randomBytes(32);
    const b = f.bundle(n);
    const log = [...b.event_log, makeEvent("storage-fs", new Uint8Array(300).fill(7))];
    const base = mockOsReport();
    const report: TdReport = { ...base, reportData: reportData(f.x25519, f.ed25519, n), rtmr: [base.rtmr[0], base.rtmr[1], base.rtmr[2], replayRtmr3(log)] };
    b.event_log = log;
    b.quote = hex(encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, report, randomBytes(64)));
    expect((await run(f, b, n, stubVerifier())).images).toEqual([IMAGE]);

    // The SPEC §3 verifier rejects it: proof that the INTEL branch is the one running.
    const mock = fixture();
    expect(await codeOf(verifyAttestation({
      bundle: { ...(await mock.bundle(n)), event_log: [...(await mock.bundle(n)).event_log, makeEvent("storage-fs", new Uint8Array(300).fill(7))] },
      nonce: n, verifier: new MockVerifier(mock.root.publicKey), registry: mock.registry, trustedRoot: mock.root.publicKey,
    }))).toBe("E_EVENT_LOG");
  });

  it("verifies the registration quote with the same { collateral, nowSecs }", async () => {
    const f = intelFixture({ verifiesOnChain: false });
    const n = randomBytes(32);
    const seen: Seen[] = [];
    const v = await run(f, f.bundle(n), n, stubVerifier(seen));
    expect(seen).toHaveLength(2);
    expect(seen[1]!.collateral).toEqual(COLLATERAL);
    expect(seen[1]!.nowSecs).toBe(NOW_MS / 1000);
    expect(toHex(v.registrationQuote!)).toBe(hex(f.registrationQuote()));
    expect(v.checks.at(-1)).toBe("registration quote: same boot, bound to (registry, operator)");
  });
});

describe("verifyAttestation — MOCK never pushes the INTEL checks", () => {
  it("has the SPEC §9 check list and no INTEL-only fields", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const v = await verifyAttestation({
      bundle: await f.bundle(n), nonce: n, verifier: new MockVerifier(f.root.publicKey), registry: f.registry,
      trustedRoot: f.root.publicKey,
    });
    expect(v.checks).not.toContain(CHECKS.TCB);
    expect(v.checks).not.toContain(CHECKS.COMPOSE_POLICY);
    expect(v.checks).toHaveLength(14);
    expect(v.tcbStatus).toBeUndefined();
    expect(v.images).toBeUndefined();
  });
});
