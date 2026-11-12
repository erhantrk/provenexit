/** Fresh Intel collateral fetched by the client itself (`PLR_PCCS_URL`, TASKS T24; on by default in INTEL mode). */
import { createRequire } from "node:module";
import { PlrError, canonicalCollateral, type CollateralJson } from "@plr/shared";

type Dcap = {
  getCollateral(pccsUrl: string, quote: Buffer): Promise<unknown>;
};

/**
 * Where the client fetches collateral when `PLR_PCCS_URL` is unset: Intel's own Provisioning Certification
 * Service. It is the origin of the PCK CRL / TCB info / QE identity (a PCCS such as pccs.phala.network is a cache
 * of it, so it can lag), it needs no API key for these endpoints, and it is not run by the company that hosts
 * the exit. The exit's compose uses Phala's PCCS; set `PLR_PCCS_URL=https://pccs.phala.network` to use that one.
 */
export const DEFAULT_PCCS_URL = "https://api.trustedservices.intel.com";

/** `PLR_PCCS_URL=exit`: the opt-out. The client fetches nothing and uses the collateral the exit served. */
export const COLLATERAL_FROM_EXIT = "exit";

/** Whole-fetch budget (about five GETs; ~0.3-2 s in practice). The status bundle's verify budget is 25 s. */
export const PCCS_TIMEOUT_MS = 8_000;

/** Where an INTEL verification takes its collateral from. */
export type CollateralSource = { source: "pccs"; url: string } | { source: "exit" };

/** The collateral source for a `pccsUrl` option: unset ⇒ {@link DEFAULT_PCCS_URL}, `"exit"` ⇒ the exit's copy. */
export function collateralSource(pccsUrl: string | undefined): CollateralSource {
  if (pccsUrl === COLLATERAL_FROM_EXIT) return { source: "exit" };
  return { source: "pccs", url: pccsUrl === undefined || pccsUrl === "" ? DEFAULT_PCCS_URL : pccsUrl };
}

/**
 * Client-only error code: the client could not fetch fresh Intel collateral from the PCCS itself (INTEL mode;
 * fails closed). It is not one of `@plr/shared`'s `ERROR_CODES`: the shared package is part of the measured exit
 * image and this check exists only in the client.
 */
export const E_COLLATERAL_FETCH = "E_COLLATERAL_FETCH";

/** Name of the client's own collateral check line (INTEL mode), listed right before the signature check. */
export const COLLATERAL_LINE = "fresh Intel collateral fetched by the client from the PCCS (not the exit's copy)";

/** The client's own PCCS fetch failed. A `PlrError` whose `code` is `E_COLLATERAL_FETCH`. */
export class CollateralFetchError extends PlrError {
  constructor(detail?: string) {
    super("E_COLLATERAL");
    (this as { code: string }).code = E_COLLATERAL_FETCH;
    this.message = detail === undefined ? E_COLLATERAL_FETCH : `${E_COLLATERAL_FETCH}: ${detail}`;
  }
}

export function isCollateralFetchError(e: unknown): e is CollateralFetchError {
  return e instanceof PlrError && (e.code as string) === E_COLLATERAL_FETCH;
}

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
 * `dcap-qvl`'s fetches carry no timeout of their own, so the whole call is bounded here (the work is abandoned,
 * not cancelled).
 * @throws CollateralFetchError (E_COLLATERAL_FETCH) when the PCCS cannot be reached in time or its answer is not collateral
 */
export async function fetchPccsCollateral(pccsUrl: string, quote: Uint8Array, timeoutMs: number = PCCS_TIMEOUT_MS): Promise<CollateralJson> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const work = getDcap().getCollateral(pccsUrl, Buffer.from(quote));
    work.catch(() => undefined);
    const raw = await Promise.race([
      work,
      new Promise<never>((_, rej) => {
        timer = setTimeout(() => rej(new Error("timeout")), timeoutMs);
      }),
    ]);
    return canonicalCollateral(raw);
  } catch {
    throw new CollateralFetchError("PCCS");
  } finally {
    clearTimeout(timer);
  }
}

/** True iff `u` is an acceptable PCCS URL for `PLR_PCCS_URL`: https and at most 2048 chars (the exit's rule, SPEC-TDX §4.1). */
export function isPccsUrl(u: string): boolean {
  if (u.length > 2048) return false;
  try {
    return new URL(u).protocol === "https:";
  } catch {
    return false;
  }
}
