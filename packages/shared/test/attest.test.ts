// LOCKED — SPEC §2.3, §4, §5
import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/nist.js";
import {
  MockRoot, MockTdxAttester, MockVerifier, parseQuote, replayRtmr3, keyHash, reportData, registrationNonce, registrationReportData,
  PlrError, MOCK_QE_VENDOR_ID, isDebug,
} from "../src/index.js";
import { sha256, enc, cat, hex, COMPOSE_STR, randomBytes } from "./helpers.js";

const code = async (fn: () => unknown) => { try { await fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const compose = enc(COMPOSE_STR);
const p256verify = (sig: Uint8Array, msg: Uint8Array, pub64: Uint8Array) =>
  p256.verify(sig, msg, cat(new Uint8Array([4]), pub64), { prehash: true, lowS: true });

describe("key binding (§5 rev 1.3: quote-purpose domain separation)", () => {
  const lp = (str: string) => { const b = enc(str); return cat(new Uint8Array([b.length]), b); };
  it("keyHash / reportData / registrationNonce / registrationReportData follow §5", () => {
    const x = randomBytes(32), e = randomBytes(32), n = randomBytes(32);
    const kh = sha256(cat(enc("PLR-v1"), x, e));
    expect(hex(keyHash(x, e))).toBe(hex(kh));
    expect(reportData(x, e, n)).toEqual(cat(kh, sha256(cat(enc("PLR-v1/session-nonce"), n))));
    const rn = sha256(cat(enc("PLR-v1/register/2"), lp("registry.test.near"), lp("op.test.near")));
    expect(registrationNonce("registry.test.near", "op.test.near")).toEqual(rn);
    expect(registrationReportData(x, e, "registry.test.near", "op.test.near")).toEqual(cat(kh, rn));
    expect(() => reportData(x, e, randomBytes(31))).toThrow(PlrError);
  });
  it("length prefixes make (contract, operator) unambiguous", () => {
    expect(registrationNonce("ab", "c")).not.toEqual(registrationNonce("a", "bc"));
    expect(() => registrationNonce("", "op")).toThrow(PlrError);
    expect(() => registrationNonce("c".repeat(65), "op")).toThrow(PlrError);
    expect(() => registrationNonce("reg", "o".repeat(65))).toThrow(PlrError);
  });
  it("a session quote can never equal a registration quote, whatever nonce the client picks", () => {
    const x = randomBytes(32), e = randomBytes(32);
    const reg = registrationReportData(x, e, "registry.test.near", "attacker.test.near");
    // the attacker asks for a session quote using the registration nonce itself as its "client nonce"
    expect(reportData(x, e, registrationNonce("registry.test.near", "attacker.test.near"))).not.toEqual(reg);
  });
});

describe("MockRoot", () => {
  it("is reconstructible from its secret and certifies AKs per §2.3", () => {
    const r = MockRoot.generate();
    expect(r.publicKey.length).toBe(64);
    const r2 = MockRoot.fromSecret(r.secretKey);
    expect(r2.publicKey).toEqual(r.publicKey);
    const ak = p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);
    const cert = r.certifyAk(ak);
    expect(cert.length).toBe(64);
    expect(p256verify(cert, cat(enc("PLR-MOCK-AK-v1"), ak), r.publicKey)).toBe(true);
  });
});

describe("MockTdxAttester + MockVerifier", () => {
  const root = MockRoot.generate();
  const att = new MockTdxAttester({ root, composeBytes: compose });
  const rd = randomBytes(64);

  it("produces a verifiable 828-byte quote binding report_data and RTMR3", async () => {
    const { quote, eventLog } = await att.getQuote(rd);
    expect(quote.length).toBe(828);
    const v = new MockVerifier(root.publicKey);
    expect(v.rootKind).toBe("MOCK");
    const p = v.verify(quote);
    expect(p.report.reportData).toEqual(rd);
    expect(p.report.rtmr[3]).toEqual(replayRtmr3(eventLog));
    expect(p.qeVendorId).toEqual(MOCK_QE_VENDOR_ID);
    expect(isDebug(p.report)).toBe(false);
    expect(eventLog.find((e) => e.event === "compose-hash")!.event_payload).toBe(hex(sha256(compose)));
  });

  it("signature data is independently verifiable with raw P-256", async () => {
    const { quote } = await att.getQuote(rd);
    const sd = quote.slice(636);
    const akPub = sd.slice(64, 128);
    expect(p256verify(sd.slice(128, 192), cat(enc("PLR-MOCK-AK-v1"), akPub), root.publicKey)).toBe(true);
    expect(p256verify(sd.slice(0, 64), quote.slice(0, 632), akPub)).toBe(true);
  });

  it("keeps RTMR3 stable across quotes of one boot, varies across boots", async () => {
    const a = parseQuote((await att.getQuote(rd)).quote).report.rtmr[3];
    const b = parseQuote((await att.getQuote(randomBytes(64))).quote).report.rtmr[3];
    expect(a).toEqual(b);
    const other = new MockTdxAttester({ root, composeBytes: compose });
    expect(parseQuote((await other.getQuote(rd)).quote).report.rtmr[3]).not.toEqual(a); // random instance-id
  });

  it("honours an explicit instanceId and the debug flag", async () => {
    const iid = new Uint8Array(20).fill(1);
    const a = new MockTdxAttester({ root, composeBytes: compose, instanceId: iid, debug: true });
    const { quote, eventLog } = await a.getQuote(rd);
    expect(eventLog.find((e) => e.event === "instance-id")!.event_payload).toBe(hex(iid));
    expect(isDebug(new MockVerifier(root.publicKey).verify(quote).report)).toBe(true);
  });

  it("rejects report_data that is not 64 bytes", async () => {
    expect(await code(() => att.getQuote(randomBytes(32)))).toBe("E_BAD_REQUEST");
  });

  it("rejects wrong root, tampered body, tampered AK, tampered cert", async () => {
    const { quote } = await att.getQuote(rd);
    const other = MockRoot.generate();
    expect(await code(() => new MockVerifier(other.publicKey).verify(quote))).toBe("E_QUOTE_SIG");
    const v = new MockVerifier(root.publicKey);
    for (const off of [0 + 28, 184, 520, 568, 631]) {
      const q = quote.slice(); q[off]! ^= 1;
      expect(await code(() => v.verify(q))).toMatch(/^E_QUOTE_(SIG|FORMAT)$/);
    }
    for (const off of [636 + 10, 636 + 70, 636 + 140]) {
      const q = quote.slice(); q[off]! ^= 1;
      expect(await code(() => v.verify(q))).toBe("E_QUOTE_SIG");
    }
  });

  it("rejects a quote whose AK is certified by a different root", async () => {
    const evil = MockRoot.generate();
    const { quote } = await new MockTdxAttester({ root: evil, composeBytes: compose }).getQuote(rd);
    expect(await code(() => new MockVerifier(root.publicKey).verify(quote))).toBe("E_QUOTE_SIG");
  });

  it("rejects high-S signatures (malleability)", async () => {
    const { quote } = await att.getQuote(rd);
    const q = quote.slice();
    const sig = p256.Signature.fromBytes(q.slice(636, 700), "compact");
    const n = p256.Point.CURVE().n;
    const high = new p256.Signature(sig.r, n - sig.s).toBytes("compact");
    q.set(high, 636);
    expect(await code(() => new MockVerifier(root.publicKey).verify(q))).toBe("E_QUOTE_SIG");
  });
});
