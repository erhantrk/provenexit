import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { parseQuote, osMeasurement, toHex, PlrError } from "../src/index.js";

const q = new Uint8Array(readFileSync(new URL("./vectors/dcap/tdx_quote.bin", import.meta.url)));

describe("INTEL parseQuote (SPEC-TDX §1.1, TV-Q1)", () => {
  it("parses the dcap-qvl sample with 70 zero padding bytes", () => {
    const p = parseQuote(q, "INTEL");
    expect(p.sigData.length).toBe(4300);
    expect(toHex(p.report.mrTd)).toBe("91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7");
    expect(toHex(osMeasurement(p.report))).toBe("345469a462dafe286b728237091da824ce7508ebf14b390a47b1766c9c22cd65");
  });
  it("rejects a non-zero padding byte", () => {
    const b = q.slice();
    b[b.length - 1] = 1;
    expect(() => parseQuote(b, "INTEL")).toThrow(PlrError);
  });
  it("rejects non-zero mr_signer_seam", () => {
    const b = q.slice();
    b[112] = 1;
    expect(() => parseQuote(b, "INTEL")).toThrow(/E_QUOTE_FORMAT|mr_signer_seam/);
  });
  it("MOCK mode rejects it", () => {
    expect(() => parseQuote(q, "MOCK")).toThrow(PlrError);
  });
});
