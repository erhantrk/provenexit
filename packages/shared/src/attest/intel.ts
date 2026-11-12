/** Intel DCAP verification of real TDX v4 quotes (SPEC-TDX §1.1, §3.1). */
import { createRequire } from "node:module";
import { PlrError } from "../errors.js";
import { equalBytes, fromHex, isBytes } from "../bytes.js";
import { parseQuote, type ParsedQuote } from "../tdx/quote.js";
import { canonicalCollateral } from "./collateral.js";
import type { QuoteVerifier, VerifyContext } from "./types.js";

const require = createRequire(import.meta.url);
type Dcap = {
  verify(q: Uint8Array, c: unknown, nowSecs: number): { status: string; advisory_ids: string[] };
};
let dcap: Dcap | undefined;

/**
 * Loads `@phala/dcap-qvl` on first INTEL verification, not at import time. Bundlers cannot inline the dynamic
 * `require` that `createRequire` produces, so an eager load would make every bundle that imports `@plr/shared`
 * (the VPN exit's `vpn.bundle.mjs`, which ships without `node_modules`) throw at start-up — even in MOCK mode.
 * INTEL-mode deployments must therefore ship the package next to the bundle (T12/T13); MOCK mode never loads it.
 */
function getDcap(): Dcap {
  dcap ??= require("@phala/dcap-qvl") as Dcap;
  return dcap;
}

/** Public key (`x‖y`) of `CN=Intel SGX Root CA` (SPEC-TDX §0). */
export const INTEL_ROOT_P256 = fromHex(
  "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394",
  64,
);

/** TCB statuses accepted by clients and the registry (project decision, SPEC-TDX §0). */
export const ACCEPTED_TCB_STATUSES: readonly string[] = Object.freeze(["UpToDate", "SWHardeningNeeded"]);

/** True iff `r` is exactly the Intel SGX Root CA public key. */
export const isIntelRoot = (r: Uint8Array): boolean => isBytes(r) && equalBytes(r, INTEL_ROOT_P256);

/** Verifies INTEL-mode TDX quotes with `@phala/dcap-qvl` against the pinned Intel root. */
export class DcapQvlVerifier implements QuoteVerifier {
  readonly rootKind = "INTEL" as const;
  readonly #accepted: readonly string[];
  readonly #clock: () => number;
  lastStatus: string | undefined;

  /** @throws PlrError E_ROOT_UNTRUSTED unless `rootPub` is the Intel SGX Root CA public key */
  constructor(rootPub: Uint8Array = INTEL_ROOT_P256, o: { acceptedStatuses?: readonly string[]; clock?: () => number } = {}) {
    if (!isIntelRoot(rootPub)) throw new PlrError("E_ROOT_UNTRUSTED", "not the Intel SGX Root CA");
    this.#accepted = o.acceptedStatuses ?? ACCEPTED_TCB_STATUSES;
    this.#clock = o.clock ?? Date.now;
  }

  get rootPublicKey(): Uint8Array {
    return INTEL_ROOT_P256.slice();
  }

  /**
   * Structural parse first, then DCAP verification.
   *
   * @throws PlrError E_QUOTE_FORMAT / E_TEE_TYPE (parse), E_COLLATERAL, E_QUOTE_SIG (dcap), E_TCB_STATUS
   */
  verify(quote: Uint8Array, ctx: VerifyContext = {}): ParsedQuote {
    const parsed = parseQuote(quote, "INTEL");
    const collateral = canonicalCollateral(ctx.collateral);
    const now = ctx.nowSecs ?? Math.floor(this.#clock() / 1000);
    let status: string;
    try {
      status = getDcap().verify(Buffer.from(quote), collateral, now).status;
    } catch {
      throw new PlrError("E_QUOTE_SIG", "dcap");
    }
    this.lastStatus = status;
    if (!this.#accepted.includes(status)) throw new PlrError("E_TCB_STATUS", status);
    return parsed;
  }
}
