import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import {
  DcapQvlVerifier, INTEL_ROOT_P256, ACCEPTED_TCB_STATUSES, isIntelRoot, canonicalCollateral, isCollateralJson,
  toHex, PlrError, type CollateralJson,
} from "../src/index.js";

const q = new Uint8Array(readFileSync(new URL("./vectors/dcap/tdx_quote.bin", import.meta.url)));
const raw = JSON.parse(
  readFileSync(new URL("./vectors/dcap/tdx_quote_collateral.json", import.meta.url), "utf8"),
) as CollateralJson;
const collateral = canonicalCollateral(raw);

const NOW = 1750377600;
const EXPIRED = 1794096000;

function code(fn: () => unknown): string {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof PlrError ? e.code : "not-plr";
  }
}

describe("DcapQvlVerifier (INTERFACES §3.1, TV-Q1)", () => {
  it("verifies the sample quote at 2025-06-20 and records lastStatus", () => {
    const v = new DcapQvlVerifier();
    const parsed = v.verify(q, { collateral, nowSecs: NOW });
    expect(toHex(parsed.report.mrTd)).toBe(
      "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7",
    );
    expect(parsed.sigData.length).toBe(4300);
    expect(v.lastStatus).toBe("UpToDate");
  });

  it("rejects verification once the collateral TCBInfo expired", () => {
    expect(code(() => new DcapQvlVerifier().verify(q, { collateral, nowSecs: EXPIRED }))).toBe("E_QUOTE_SIG");
  });

  it("rejects an accepted-status list that excludes the report status", () => {
    const v = new DcapQvlVerifier(INTEL_ROOT_P256, { acceptedStatuses: ["SWHardeningNeeded"] });
    expect(code(() => v.verify(q, { collateral, nowSecs: NOW }))).toBe("E_TCB_STATUS");
  });

  it("requires collateral and reports E_COLLATERAL when it is missing", () => {
    expect(code(() => new DcapQvlVerifier().verify(q, { nowSecs: NOW }))).toBe("E_COLLATERAL");
    expect(isCollateralJson(undefined)).toBe(false);
  });

  it("accepts number arrays for binary collateral fields", () => {
    const arr = Uint8Array.from(Buffer.from(raw.root_ca_crl!, "hex"));
    const collateralArrays = { ...raw, root_ca_crl: [...arr] };
    expect(canonicalCollateral(collateralArrays).root_ca_crl).toBe(raw.root_ca_crl);
    const v = new DcapQvlVerifier();
    expect(toHex(v.verify(q, { collateral: collateralArrays, nowSecs: NOW }).report.mrTd)).toBe(
      "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7",
    );
    expect(v.lastStatus).toBe("UpToDate");
  });

  it("pins the Intel root and exposes the constants", () => {
    expect(() => new DcapQvlVerifier(new Uint8Array(64))).toThrow(PlrError);
    expect(code(() => new DcapQvlVerifier(new Uint8Array(64)))).toBe("E_ROOT_UNTRUSTED");
    expect(isIntelRoot(INTEL_ROOT_P256)).toBe(true);
    expect(isIntelRoot(new Uint8Array(64))).toBe(false);
    expect(ACCEPTED_TCB_STATUSES).toEqual(["UpToDate", "SWHardeningNeeded"]);
    expect(toHex(new DcapQvlVerifier().rootPublicKey)).toBe(toHex(INTEL_ROOT_P256));
  });
});
