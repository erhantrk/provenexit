// T15 — fixture replay (INTERFACES §3.3). A real capture needs a real Intel-signed quote, so until T19 records one
// under fixtures/, the tests build a synthetic INTEL fixture from the T09 stub-verifier path. The stub keeps the
// DCAP contract (it requires ctx.collateral and reports lastStatus); everything else goes through the real
// verifyAttestation / MemoryRegistry code.
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  CHECKS, DcapQvlVerifier, INTEL_QE_VENDOR_ID, INTEL_ROOT_P256, PlrError, encodeQuote, keyHash, makeEvent, mockOsReport,
  osMeasurement, parseQuote, reportData, replayRtmr3, toHex,
  type AttestationBundle, type InstanceRecord, type QuoteVerifier, type TdxEvent, type TdReport,
} from "@plr/shared";
import { runCli } from "../src/index.js";
import { fixtureReplayLine, fixtureVerifier, readFixture, verifyFixture } from "../src/fixture.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const FIXTURES = fileURLToPath(new URL("../../fixtures/", import.meta.url));
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const EMPTY = new Uint8Array(0);

/** A capture from 2025-06-20 (the TV-Q1 collateral window): far enough in the past that only the capture clock passes. */
const CAPTURED_AT = 1_750_377_600_000;
const IMAGE = `ghcr.io/erhantrk/provenexit-exit@sha256:${"ab".repeat(32)}`;
const OPERATOR = "pe-op-erhan.testnet";
const REGISTRY = "pe-vpnreg-erhan.testnet";

/** Canonical collateral shape (§1.2); the stub never checks the signature, only that collateral is present. */
const COLLATERAL = {
  pck_crl_issuer_chain: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
  tcb_info_issuer_chain: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
  tcb_info: "{}",
  qe_identity_issuer_chain: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
  qe_identity: "{}",
  root_ca_crl: "00",
  pck_crl: "00",
  tcb_info_signature: "00",
  qe_identity_signature: "00",
};

/** INTERFACES §1.4 app-compose with one digest-pinned exit image and logging disabled. */
function appCompose(image = IMAGE): string {
  const dockerComposeFile = `services:
  exit:
    image: ${image}
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
`;
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

/** T09 stub verifier: the DCAP call is the only thing a synthetic quote cannot provide. */
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

interface Synthetic {
  dir: string;
  keyHashHex: string;
  composeHash: Uint8Array;
  os: Uint8Array;
}

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function syntheticFixture(o: { capturedAt?: number; image?: string } = {}): Synthetic {
  const capturedAt = o.capturedAt ?? CAPTURED_AT;
  const compose = appCompose(o.image);
  const composeHash = new Uint8Array(sha256(enc(compose)));
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  const kh = keyHash(xp, ep);
  const os = osMeasurement(mockOsReport());
  const nonce = new Uint8Array(randomBytes(32));
  const log: TdxEvent[] = [
    makeEvent("key-provider", enc("{}")),
    makeEvent("system-preparing", EMPTY),
    makeEvent("app-id", new Uint8Array(20).fill(0x11)),
    makeEvent("compose-hash", composeHash),
    makeEvent("instance-id", new Uint8Array(20).fill(0x22)),
    makeEvent("boot-mr-done", EMPTY),
    makeEvent("system-ready", EMPTY),
  ];
  const base = mockOsReport();
  const report: TdReport = { ...base, reportData: reportData(xp, ep, nonce), rtmr: [base.rtmr[0], base.rtmr[1], base.rtmr[2], replayRtmr3(log)] };
  const quote = encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, report, new Uint8Array(randomBytes(64)));
  const bundle: AttestationBundle = {
    v: "PLR-v1",
    root_kind: "INTEL",
    quote: toHex(quote),
    event_log: log,
    app_compose: compose,
    x25519: toHex(xp),
    ed25519: toHex(ep),
    collateral: COLLATERAL,
  };
  const record: InstanceRecord = {
    compose_hash: toHex(composeHash),
    os_measurement: toHex(os),
    x25519: toHex(xp),
    ed25519: toHex(ep),
    operator: OPERATOR,
    org_id: null,
    registered_at_ms: 1,
    expires_at_ms: capturedAt + 3_600_000,
    next_seq: 0,
  };
  const registry = {
    root: { kind: "INTEL", p256: toHex(INTEL_ROOT_P256) },
    compose: [toHex(composeHash)],
    os: [toHex(os)],
    instances: { [toHex(kh)]: record },
  };
  const dir = mkdtempSync(join(HERE, "fixture-"));
  dirs.push(dir);
  writeFileSync(join(dir, "meta.json"), JSON.stringify({
    captured_at_ms: capturedAt,
    exit_url: "https://abc123-18200.dstack-prod5.phala.network",
    network: "testnet",
    registry: REGISTRY,
    registration_tx: "regtx123",
    revocation_tx: null,
    note: "synthetic fixture (T15)",
  }, null, 2));
  writeFileSync(join(dir, "nonce.hex"), toHex(nonce));
  writeFileSync(join(dir, "bundle.json"), JSON.stringify(bundle));
  writeFileSync(join(dir, "registry.json"), JSON.stringify(registry));
  return { dir, keyHashHex: toHex(kh), composeHash, os };
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

/** First fixture directory under fixtures/ that has all four files of INTERFACES §3.3, if any (T19). */
function realCapture(): string | null {
  let names: string[];
  try {
    names = readdirSync(FIXTURES);
  } catch {
    return null;
  }
  for (const name of names) {
    const dir = join(FIXTURES, name);
    if (["meta.json", "nonce.hex", "bundle.json", "registry.json"].every((f) => existsSync(join(dir, f)))) return dir;
  }
  return null;
}

describe("readFixture", () => {
  it("reads the four files and the capture clock", () => {
    const f = syntheticFixture();
    const r = readFixture(f.dir);
    expect(r.meta.captured_at_ms).toBe(CAPTURED_AT);
    expect(r.meta.exit_url).toContain("phala.network");
    expect(r.nonce).toHaveLength(32);
    expect(r.bundle.root_kind).toBe("INTEL");
    expect(r.registry.verifiesOnChain).toBe(true);
    expect(r.registry.contractId).toBe(REGISTRY);
    expect(r.registry.now?.()).toBe(CAPTURED_AT);
  });

  it("rejects a malformed nonce and a missing directory (E_BAD_INPUT)", async () => {
    const f = syntheticFixture();
    writeFileSync(join(f.dir, "nonce.hex"), "ABCDEF");
    expect(await codeOf(verifyFixture(f.dir, stubVerifier()))).toBe("E_BAD_INPUT");
    expect(await codeOf(verifyFixture(join(HERE, "no-such-fixture"), stubVerifier()))).toBe("E_BAD_INPUT");
  });
});

describe("verifyFixture (INTERFACES §3.3)", () => {
  it("replays a synthetic INTEL fixture at the capture time and reports TCB + images", async () => {
    const f = syntheticFixture();
    const seen: Seen[] = [];
    const v = await verifyFixture(f.dir, stubVerifier(seen));

    expect(v.rootKind).toBe("INTEL");
    expect(v.tcbStatus).toBe("UpToDate");
    expect(v.images).toEqual([IMAGE]);
    expect(v.composeHash).toEqual(f.composeHash);
    expect(v.osMeasurement).toEqual(f.os);
    expect(v.checks).toContain(CHECKS.TCB);
    expect(v.checks).toContain(CHECKS.COMPOSE_POLICY);
    // The DCAP clock is the capture's, so an old capture verifies forever.
    expect(seen).toEqual([{ collateral: COLLATERAL, nowSecs: CAPTURED_AT / 1000 }]);
  });

  it("uses the capture clock for instance expiry, not the wall clock", async () => {
    const f = syntheticFixture();
    const registry = JSON.parse(readFileSync(join(f.dir, "registry.json"), "utf8")) as {
      instances: Record<string, { expires_at_ms: number }>;
    };
    registry.instances[f.keyHashHex]!.expires_at_ms = CAPTURED_AT - 1;
    writeFileSync(join(f.dir, "registry.json"), JSON.stringify(registry));
    expect(await codeOf(verifyFixture(f.dir, stubVerifier()))).toBe("E_INSTANCE_NOT_REGISTERED");
  });

  it("fails closed when the snapshot no longer allows the compose hash", async () => {
    const f = syntheticFixture();
    const registry = JSON.parse(readFileSync(join(f.dir, "registry.json"), "utf8")) as { compose: string[] };
    registry.compose = [];
    writeFileSync(join(f.dir, "registry.json"), JSON.stringify(registry));
    expect(await codeOf(verifyFixture(f.dir, stubVerifier()))).toBe("E_COMPOSE_NOT_ALLOWED");
  });
});

describe("fixture replay CLI line", () => {
  it("names the exit, the capture time, the registry snapshot and the registration tx", () => {
    const f = syntheticFixture();
    const line = fixtureReplayLine(readFixture(f.dir).meta);
    expect(line).toBe(
      `✔ VERIFIED (FIXTURE REPLAY of https://abc123-18200.dstack-prod5.phala.network, captured ${new Date(CAPTURED_AT).toISOString()}; ` +
        `registry snapshot of ${REGISTRY}; registration tx regtx123)`,
    );
  });

  it("plr vpn verify --fixture needs a directory and refuses a non-fixture", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (s: string) => out.push(s), err: (s: string) => err.push(s) };
    expect(await runCli(["vpn", "verify", "--fixture"], {}, io)).toBe(2);
    expect(err.join("\n")).toContain("--fixture");
    expect(await runCli(["vpn", "verify", "--fixture", join(HERE, "no-such-fixture")], {}, io)).toBe(1);
    expect(out.join("\n")).toContain("✘ REFUSED");
  });
});

const real = realCapture();
describe.skipIf(real === null)("recorded capture replay (T19)", () => {
  it("verifies the recorded Intel TDX fixture offline with the real DCAP verifier", async () => {
    const v = await verifyFixture(real!);
    expect(v.rootKind).toBe("INTEL");
    expect(v.tcbStatus).toBeDefined();
    expect(v.images?.length).toBeGreaterThan(0);
    expect(v.checks).toContain(CHECKS.TCB);
    expect(v.checks).toContain(CHECKS.COMPOSE_POLICY);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// The default (real) verifier of verifyFixture. Every test above injects a stub, so the production path —
// `new DcapQvlVerifier(INTEL_ROOT_P256, { clock: () => captured_at_ms })` — was never executed. These tests use
// the real TV-Q1 quote and its real Intel collateral (INTERFACES §1.1): the DCAP call really happens.
// ---------------------------------------------------------------------------------------------------------------

const TVQ1_QUOTE = new Uint8Array(readFileSync(new URL("../../packages/shared/test/vectors/dcap/tdx_quote.bin", import.meta.url)));
const TVQ1_COLLATERAL = JSON.parse(
  readFileSync(new URL("../../packages/shared/test/vectors/dcap/tdx_quote_collateral.json", import.meta.url), "utf8"),
) as Record<string, unknown>;
/** TV-Q1 collateral is valid 2025-06-19..2025-07-19 and expired at 2026-11-08 (INTERFACES §1.1). */
const TVQ1_CAPTURED_AT = 1_750_377_600_000;
const TVQ1_EXPIRED_AT = 1_794_096_000_000;
const TVQ1_MRTD = "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7";

/**
 * A fixture whose bundle carries the real TV-Q1 quote and collateral. Its `report_data` is not our key hash (it is
 * Intel's sample), so verification necessarily stops at E_REPORT_DATA_KEYS — after the DCAP signature and TCB steps.
 */
function tvq1Fixture(capturedAt: number): string {
  const compose = appCompose();
  const composeHash = new Uint8Array(sha256(enc(compose)));
  const xp = x25519.getPublicKey(x25519.utils.randomSecretKey());
  const ep = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
  const log: TdxEvent[] = [
    makeEvent("system-preparing", EMPTY),
    makeEvent("app-id", new Uint8Array(20).fill(0x11)),
    makeEvent("compose-hash", composeHash),
    makeEvent("instance-id", new Uint8Array(20).fill(0x22)),
    makeEvent("boot-mr-done", EMPTY),
  ];
  const bundle: AttestationBundle = {
    v: "PLR-v1",
    root_kind: "INTEL",
    quote: toHex(TVQ1_QUOTE),
    event_log: log,
    app_compose: compose,
    x25519: toHex(xp),
    ed25519: toHex(ep),
    collateral: TVQ1_COLLATERAL,
  };
  const dir = mkdtempSync(join(HERE, "fixture-tvq1-"));
  dirs.push(dir);
  writeFileSync(join(dir, "meta.json"), JSON.stringify({
    captured_at_ms: capturedAt,
    exit_url: "https://abc123-18200.dstack-prod5.phala.network",
    network: "testnet",
    registry: REGISTRY,
    registration_tx: "regtx123",
    revocation_tx: null,
  }));
  writeFileSync(join(dir, "nonce.hex"), toHex(new Uint8Array(randomBytes(32))));
  writeFileSync(join(dir, "bundle.json"), JSON.stringify(bundle));
  writeFileSync(join(dir, "registry.json"), JSON.stringify({
    root: { kind: "INTEL", p256: toHex(INTEL_ROOT_P256) },
    compose: [toHex(composeHash)],
    os: [],
    instances: {},
  }));
  return dir;
}

describe("verifyFixture's default verifier is the real DCAP verifier at the capture clock", () => {
  it("reaches past the quote-signature step with TV-Q1 at its capture time (no stub)", async () => {
    // UpToDate at 2025-06-20 ⇒ DCAP verified the real Intel signature; the next failing check is ours.
    expect(await codeOf(verifyFixture(tvq1Fixture(TVQ1_CAPTURED_AT)))).toBe("E_REPORT_DATA_KEYS");
  });

  it("fails at the quote-signature step with the same fixture once the collateral expired", async () => {
    expect(await codeOf(verifyFixture(tvq1Fixture(TVQ1_EXPIRED_AT)))).toBe("E_QUOTE_SIG");
  });

  it("fixtureVerifier passes captured_at_ms to DCAP (not the wall clock)", () => {
    const v = fixtureVerifier(readFixture(tvq1Fixture(TVQ1_CAPTURED_AT)).meta);
    expect(v).toBeInstanceOf(DcapQvlVerifier);
    expect(v.rootKind).toBe("INTEL");
    // No `nowSecs`: the verifier must use its own clock, i.e. the capture time. Today the collateral is expired,
    // so a verifier built without `{ clock }` would throw here.
    const parsed = v.verify(TVQ1_QUOTE, { collateral: TVQ1_COLLATERAL });
    expect(toHex(parsed.report.mrTd)).toBe(TVQ1_MRTD);
    expect(v.lastStatus).toBe("UpToDate");

    const expired = fixtureVerifier(readFixture(tvq1Fixture(TVQ1_EXPIRED_AT)).meta);
    expect(() => expired.verify(TVQ1_QUOTE, { collateral: TVQ1_COLLATERAL })).toThrow(PlrError);
  });
});
