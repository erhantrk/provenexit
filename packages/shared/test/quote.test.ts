// LOCKED — SPEC §2
import { describe, it, expect } from "vitest";
import {
  QUOTE, MOCK_QE_VENDOR_ID, encodeQuote, parseQuote, isDebug, osMeasurement, mockOsReport, PlrError,
} from "../src/index.js";
import { sha256, sha384, enc, cat, hex } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const sig192 = () => new Uint8Array(192).fill(7);

function sample() {
  const r = mockOsReport();
  r.rtmr[3] = new Uint8Array(48).fill(0x33);
  r.reportData = new Uint8Array(64).map((_, i) => i);
  return r;
}

describe("constants", () => {
  it("match the TDX v4 layout", () => {
    expect(QUOTE.HEADER_LEN).toBe(48);
    expect(QUOTE.BODY_LEN).toBe(584);
    expect(QUOTE.SIGNED_LEN).toBe(632);
    expect(QUOTE.MOCK_LEN).toBe(828);
    expect(QUOTE.OFF).toMatchObject({ MR_TD: 184, RTMR0: 376, RTMR3: 520, REPORT_DATA: 568, TD_ATTRIBUTES: 168 });
    expect(Buffer.from(MOCK_QE_VENDOR_ID).toString()).toBe("PLR-MOCK-QE-0001");
  });
});

describe("mockOsReport", () => {
  it("uses deterministic §2.4 measurements", () => {
    const r = mockOsReport();
    expect(hex(r.mrTd)).toBe(hex(sha384(enc("PLR-MOCK-OS-v1:MRTD"))));
    for (const n of [0, 1, 2]) expect(hex(r.rtmr[n]!)).toBe(hex(sha384(enc(`PLR-MOCK-OS-v1:RTMR${n}`))));
    expect(r.rtmr[3]).toEqual(new Uint8Array(48));
    expect(r.reportData).toEqual(new Uint8Array(64));
    expect(isDebug(r)).toBe(false);
    expect(isDebug(mockOsReport({ debug: true }))).toBe(true);
  });
  it("osMeasurement = SHA256(mrTd‖rtmr0‖rtmr1‖rtmr2)", () => {
    const r = mockOsReport();
    expect(hex(osMeasurement(r))).toBe(hex(sha256(cat(r.mrTd, r.rtmr[0]!, r.rtmr[1]!, r.rtmr[2]!))));
    const r2 = mockOsReport(); r2.rtmr[3] = new Uint8Array(48).fill(9);
    expect(hex(osMeasurement(r2))).toBe(hex(osMeasurement(r))); // rtmr3 is NOT part of the OS measurement
  });
});

describe("encodeQuote / parseQuote", () => {
  it("places every field at its absolute offset", () => {
    const r = sample();
    const q = encodeQuote({ qeVendorId: MOCK_QE_VENDOR_ID }, r, sig192());
    expect(q.length).toBe(828);
    const dv = new DataView(q.buffer, q.byteOffset);
    expect(dv.getUint16(0, true)).toBe(4);
    expect(dv.getUint16(2, true)).toBe(2);
    expect(dv.getUint32(4, true)).toBe(0x81);
    expect(q.slice(8, 12)).toEqual(new Uint8Array(4));
    expect(q.slice(12, 28)).toEqual(MOCK_QE_VENDOR_ID);
    expect(q.slice(184, 232)).toEqual(r.mrTd);
    expect(q.slice(376, 424)).toEqual(r.rtmr[0]);
    expect(q.slice(424, 472)).toEqual(r.rtmr[1]);
    expect(q.slice(472, 520)).toEqual(r.rtmr[2]);
    expect(q.slice(520, 568)).toEqual(r.rtmr[3]);
    expect(q.slice(568, 632)).toEqual(r.reportData);
    expect(dv.getUint32(632, true)).toBe(192);
    expect(q.slice(636)).toEqual(sig192());
  });

  it("round-trips", () => {
    const r = sample();
    const q = encodeQuote({ qeVendorId: MOCK_QE_VENDOR_ID }, r, sig192());
    const p = parseQuote(q);
    expect(p.version).toBe(4);
    expect(p.attKeyType).toBe(2);
    expect(p.teeType).toBe(0x81);
    expect(p.qeVendorId).toEqual(MOCK_QE_VENDOR_ID);
    expect(p.report).toEqual(r);
    expect(p.signedBytes).toEqual(q.slice(0, 632));
    expect(p.sigData).toEqual(sig192());
  });

  it("detects the debug bit at byte 168 bit 0", () => {
    const q = encodeQuote({ qeVendorId: MOCK_QE_VENDOR_ID }, mockOsReport({ debug: true }), sig192());
    expect(q[168]! & 1).toBe(1);
    expect(isDebug(parseQuote(q).report)).toBe(true);
  });

  const good = () => encodeQuote({ qeVendorId: MOCK_QE_VENDOR_ID }, sample(), sig192());
  const mut = (f: (q: Uint8Array, dv: DataView) => void) => { const q = good(); f(q, new DataView(q.buffer, q.byteOffset)); return q; };

  it("rejects malformed quotes", () => {
    expect(code(() => parseQuote(mut((_, dv) => dv.setUint16(0, 3, true))))).toBe("E_QUOTE_FORMAT");
    expect(code(() => parseQuote(mut((_, dv) => dv.setUint16(2, 3, true))))).toBe("E_QUOTE_FORMAT");
    expect(code(() => parseQuote(mut((_, dv) => dv.setUint32(4, 0, true))))).toBe("E_TEE_TYPE");
    expect(code(() => parseQuote(mut((q) => { q[9] = 1; })))).toBe("E_QUOTE_FORMAT");
    expect(code(() => parseQuote(mut((_, dv) => dv.setUint32(632, 191, true))))).toBe("E_QUOTE_FORMAT");
    expect(code(() => parseQuote(good().slice(0, 827)))).toBe("E_QUOTE_FORMAT");
    expect(code(() => parseQuote(cat(good(), new Uint8Array(1))))).toBe("E_QUOTE_FORMAT");
    expect(code(() => parseQuote(new Uint8Array(0)))).toBe("E_QUOTE_FORMAT");
  });

  it("returns copies, not views into the input", () => {
    const q = good();
    const p = parseQuote(q);
    q[568] = 0xff;
    expect(p.report.reportData[0]).toBe(0);
  });
});
