/** Fresh Intel collateral from a PCCS (`PLR_PCCS_URL`, TASKS T24). */
import { createRequire } from "node:module";
import { PlrError, canonicalCollateral, type CollateralJson } from "@plr/shared";

type Dcap = {
  getCollateral(pccsUrl: string, quote: Buffer): Promise<unknown>;
};

let dcap: Dcap | undefined;

/**
 * `@phala/dcap-qvl` loads on first use, like `@plr/shared`'s `DcapQvlVerifier`: a process that never verifies an
 * INTEL quote (MOCK mode, `plr chat`) must not need the package.
 */
function getDcap(): Dcap {
  dcap ??= createRequire(import.meta.url)("@phala/dcap-qvl") as Dcap;
  return dcap;
}

/**
 * `getCollateral(pccsUrl, quote)` normalised to the canonical wire form (SPEC-TDX §1.2).
 * @throws PlrError E_COLLATERAL when the PCCS cannot be reached or its answer is not collateral
 */
export async function fetchPccsCollateral(pccsUrl: string, quote: Uint8Array): Promise<CollateralJson> {
  let raw: unknown;
  try {
    raw = await getDcap().getCollateral(pccsUrl, Buffer.from(quote));
  } catch {
    throw new PlrError("E_COLLATERAL", "PCCS");
  }
  return canonicalCollateral(raw);
}

/** True iff `u` is an acceptable `PLR_PCCS_URL`: https and at most 2048 chars (the exit's rule, SPEC-TDX §4.1). */
export function isPccsUrl(u: string): boolean {
  if (u.length > 2048) return false;
  try {
    return new URL(u).protocol === "https:";
  } catch {
    return false;
  }
}
