// Additional (non-locked) hardening tests for @plr/shared.
import { describe, it, expect } from "vitest";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  fromHex, toHex, PlrError, verifyAttestation, MockVerifier, MockRoot, MockTdxAttester, MemoryRegistry, keyHash,
  reportData, registrationNonce, registrationReportData,
  osMeasurement, mockOsReport, verifyEventLog, bootEvents, replayRtmr3, makeEvent, merkleRoot, merkleProof,
  verifyMerkleProof, DcapQvlVerifier, DstackAttester, parseQuote, encodeQuote, INTEL_QE_VENDOR_ID, FrameReader,
  sealFrame, receiptLeaf, isReceipt, CHECKS, type RegistryReader, type InstanceRecord, type AttestationBundle,
  type Receipt,
} from "../src/index.js";

const code = async (fn: () => unknown) => {
  try { await fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
};
const enc = (s: string) => new TextEncoder().encode(s);

describe("strict hex", () => {
  it("rejects prefix, uppercase, odd length, wrong length, non-strings", async () => {
    for (const h of ["0x00", "AB", "abc", " 00", "0g", "00\n"]) expect(await code(() => fromHex(h))).toBe("E_BAD_HEX");
    expect(await code(() => fromHex("0011", 3))).toBe("E_BAD_HEX");
    expect(await code(() => fromHex(7 as unknown as string))).toBe("E_BAD_HEX");
    expect(fromHex("")).toEqual(new Uint8Array());
    expect(toHex(fromHex("00ff10", 3))).toBe("00ff10");
  });
});

function setup() {
  const root = MockRoot.generate();
  const composeStr = '{"name":"x"}\n';
  const composeBytes = enc(composeStr);
  const att = new MockTdxAttester({ root, composeBytes });
  const xs = x25519.utils.randomSecretKey(), xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey(), ep = ed25519.getPublicKey(es);
  const kh = keyHash(xp, ep);
  const os = osMeasurement(mockOsReport());
  const rec: InstanceRecord = {
    compose_hash: toHex(sha256(composeBytes)), os_measurement: toHex(os), x25519: toHex(xp), ed25519: toHex(ep),
    operator: "op", org_id: null, registered_at_ms: 1, expires_at_ms: Date.now() + 60_000, next_seq: 0,
  };
  const registry = new MemoryRegistry({
    root: { kind: "MOCK", p256: toHex(root.publicKey) }, compose: [rec.compose_hash], os: [rec.os_measurement],
    instances: { [toHex(kh)]: rec },
  });
  const bundle = async (nonce: Uint8Array): Promise<AttestationBundle> => {
    const { quote, eventLog } = await att.getQuote(reportData(xp, ep, nonce));
    return { v: "PLR-v1", root_kind: "MOCK", quote: toHex(quote), event_log: eventLog, app_compose: composeStr, x25519: toHex(xp), ed25519: toHex(ep) };
  };
  /** Bundle over arbitrary 64-byte report_data (pre-rev-1.3 raw nonce, registration quote, …). */
  const bundleRd = async (rd: Uint8Array): Promise<AttestationBundle> => {
    const { quote, eventLog } = await att.getQuote(rd);
    return { v: "PLR-v1", root_kind: "MOCK", quote: toHex(quote), event_log: eventLog, app_compose: composeStr, x25519: toHex(xp), ed25519: toHex(ep) };
  };
  const run = (b: AttestationBundle, nonce: Uint8Array, reg: RegistryReader = registry, now?: number) =>
    verifyAttestation({
      bundle: b, nonce, verifier: new MockVerifier(root.publicKey), registry: reg, trustedRoot: root.publicKey,
      ...(now === undefined ? {} : { now }),
    });
  return { root, registry, rec, kh, xp, ep, bundle, bundleRd, run };
}

describe("rev 1.3 quote-purpose separation", () => {
  it("E_NONCE for a quote carrying the raw client nonce (pre-rev-1.3) or a registration nonce", async () => {
    const s = setup();
    const n = randomBytes(32);
    expect(await code(async () => s.run(await s.bundleRd(new Uint8Array([...s.kh, ...n])), n))).toBe("E_NONCE");
    const regN = registrationNonce("registry.test.near", "op.test.near");
    const regB = await s.bundleRd(registrationReportData(s.xp, s.ep, "registry.test.near", "op.test.near"));
    expect(await code(() => s.run(regB, regN))).toBe("E_NONCE");
    expect((await s.run(await s.bundle(n), n)).keyHash).toEqual(s.kh);
  });
  it("registrationNonce validates ids (1..64 printable ASCII bytes), reportData validates the nonce", async () => {
    expect(registrationNonce("a".repeat(64), "b".repeat(64))).toHaveLength(32);
    for (const [c, o] of [["", "o"], ["c", ""], ["a b", "o"], ["c", "\u00e9"], ["c", 5 as unknown as string], ["\ud800", "o"]] as const) {
      expect(await code(() => registrationNonce(c, o))).toBe("E_BAD_INPUT");
    }
    const s = setup();
    expect(await code(() => reportData(s.xp, s.ep, new Uint8Array(33)))).toBe("E_BAD_INPUT");
    expect(await code(() => registrationReportData(s.xp, s.ep, "c".repeat(65), "o"))).toBe("E_BAD_INPUT");
  });
});

describe("verifyAttestation extra", () => {
  it("reports every check in order", async () => {
    const s = setup(); const n = randomBytes(32);
    const v = await s.run(await s.bundle(n), n);
    expect(v.checks).toEqual(Object.values(CHECKS));
  });

  it("rejects an expired registration even if the registry still returns it", async () => {
    const s = setup(); const n = randomBytes(32);
    const b = await s.bundle(n);
    expect(await code(() => s.run(b, n, s.registry, Date.now() + 3_600_000))).toBe("E_INSTANCE_NOT_REGISTERED");
  });

  it("maps malformed registry replies to E_REGISTRY_UNAVAILABLE", async () => {
    const s = setup(); const n = randomBytes(32); const b = await s.bundle(n);
    const weird: RegistryReader = {
      chain: "x", contractId: "x",
      getRoot: () => s.registry.getRoot(),
      isComposeAllowed: async () => "true" as unknown as boolean,
      isOsAllowed: (h) => s.registry.isOsAllowed(h),
      getInstance: (k) => s.registry.getInstance(k),
      getAnchor: (i) => s.registry.getAnchor(i),
    };
    expect(await code(() => s.run(b, n, weird))).toBe("E_REGISTRY_UNAVAILABLE");
    const throwing: RegistryReader = { ...weird, isComposeAllowed: () => { throw new Error("sync"); } };
    expect(await code(() => s.run(b, n, throwing))).toBe("E_REGISTRY_UNAVAILABLE");
    const badRoot: RegistryReader = { ...weird, getRoot: async () => ({ kind: "MOCK" as const, p256: "AA".repeat(64) }) };
    expect(await code(() => s.run(b, n, badRoot))).toBe("E_REGISTRY_UNAVAILABLE");
    const badInst: RegistryReader = {
      ...weird, isComposeAllowed: (h) => s.registry.isComposeAllowed(h),
      getInstance: async () => ({ ...s.rec, x25519: "zz" }),
    };
    expect(await code(() => s.run(b, n, badInst))).toBe("E_REGISTRY_UNAVAILABLE");
  });

  it("rejects an all-zero nonce, oversized / ill-formed compose, small-order ed25519 key, null bundle", async () => {
    const s = setup(); const n = randomBytes(32); const b = await s.bundle(n);
    expect(await code(() => s.run(b, new Uint8Array(32)))).toBe("E_BAD_RESPONSE");
    expect(await code(() => s.run({ ...b, app_compose: "x".repeat(8193) }, n))).toBe("E_BAD_RESPONSE");
    expect(await code(() => s.run({ ...b, app_compose: "\uD800" }, n))).toBe("E_BAD_RESPONSE");
    const identity = "01" + "00".repeat(31);
    expect(await code(() => s.run({ ...b, ed25519: identity }, n))).toBe("E_BAD_RESPONSE");
    expect(await code(() => s.run(null as never, n))).toBe("E_BAD_RESPONSE");
    expect(await code(() => s.run({ ...b, quote: b.quote.toUpperCase() }, n))).toBe("E_BAD_RESPONSE");
  });

  it("rejects registry root kind mismatch as E_ROOT_UNTRUSTED", async () => {
    const s = setup(); const n = randomBytes(32); const b = await s.bundle(n);
    s.registry.setRoot({ kind: "INTEL", p256: toHex(s.root.publicKey) });
    expect(await code(() => s.run(b, n))).toBe("E_ROOT_UNTRUSTED");
  });
});

describe("event log extra", () => {
  const compose = enc("{}");
  it("rejects unknown fields, names with ':' and bad inputs", async () => {
    const evs = bootEvents(compose, new Uint8Array(20));
    const withExtra = evs.map((e, i) => (i === 4 ? { ...e, extra: 1 } : e));
    expect(await code(() => verifyEventLog(withExtra, replayRtmr3(withExtra)))).toBe("E_EVENT_LOG");
    const colon = [...evs, makeEvent("a:b", new Uint8Array())];
    expect(await code(() => verifyEventLog(colon, replayRtmr3(colon)))).toBe("E_EVENT_LOG");
    expect(await code(() => verifyEventLog(evs, new Uint8Array(47)))).toBe("E_RTMR3");
    expect(await code(() => verifyEventLog("x" as never, new Uint8Array(48)))).toBe("E_EVENT_LOG");
  });
});

describe("quote extra", () => {
  it("MOCK mode rejects a non-mock QE vendor id; INTEL mode needs Intel vendor", async () => {
    const q = encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, mockOsReport(), new Uint8Array(192));
    expect(await code(() => parseQuote(q))).toBe("E_QUOTE_FORMAT");
    expect(parseQuote(q, "INTEL").sigData.length).toBe(192);
  });
});

describe("stubs", () => {
  it("DstackAttester fails closed; DcapQvlVerifier only trusts the Intel root", async () => {
    expect(await code(() => new DstackAttester().getQuote(new Uint8Array(64)))).toBe("E_NOT_IMPLEMENTED");
    expect(await code(() => new DcapQvlVerifier(MockRoot.generate().publicKey))).toBe("E_ROOT_UNTRUSTED");
    const v = new DcapQvlVerifier();
    expect(v.rootKind).toBe("INTEL");
    expect(await code(() => v.verify(new Uint8Array(828)))).toBe("E_QUOTE_FORMAT");
  });
});

describe("merkle extra", () => {
  it("proofs verify for a large batch and reject non-integer / malformed inputs", () => {
    const ls = Array.from({ length: 1000 }, () => randomBytes(32));
    const root = merkleRoot(ls);
    for (const i of [0, 1, 511, 512, 998, 999]) expect(verifyMerkleProof(ls[i]!, i, 1000, merkleProof(ls, i), root)).toBe(true);
    expect(verifyMerkleProof(ls[0]!, 0.5, 1000, merkleProof(ls, 0), root)).toBe(false);
    expect(verifyMerkleProof(ls[0]!, 0, 1000, "x" as never, root)).toBe(false);
    expect(() => merkleRoot([new Uint8Array(31)])).toThrow(PlrError);
  });
});

describe("frames / receipts extra", () => {
  it("FrameReader failure is sticky", async () => {
    const k = randomBytes(32), th = randomBytes(32);
    const r = new FrameReader(k, th);
    expect(await code(() => r.push(0, randomBytes(40)))).toBe("E_DECRYPT");
    expect(await code(() => r.push(0, sealFrame(k, th, 0, true, enc("x"))))).toBe("E_DECRYPT");
    expect(await code(() => r.end())).toBe("E_TRUNCATED");
  });

  it("receipts with extra or malformed fields are rejected", async () => {
    const r: Receipt = { v: 1, th: "a1".repeat(32), req_hash: "b2".repeat(32), resp_hash: "c3".repeat(32), compose_hash: "d4".repeat(32), key_hash: "e5".repeat(32), seq: 0, ts_ms: 1 };
    expect(isReceipt(r)).toBe(true);
    expect(isReceipt({ ...r, extra: 1 })).toBe(false);
    expect(isReceipt({ ...r, seq: -1 })).toBe(false);
    expect(isReceipt({ ...r, th: "A1".repeat(32) })).toBe(false);
    expect(await code(() => receiptLeaf({ ...r, seq: 1.5 }))).toBe("E_BAD_INPUT");
  });
});
