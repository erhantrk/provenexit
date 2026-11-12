/** Canonical collateral JSON for `@phala/dcap-qvl` (SPEC-TDX §1.2). */
import { PlrError } from "../errors.js";
import { isPlainObject, toHex } from "../bytes.js";

export type CollateralJson = Record<string, string>;

const STR = ["pck_crl_issuer_chain", "tcb_info_issuer_chain", "tcb_info", "qe_identity_issuer_chain", "qe_identity"] as const;
const BIN = ["root_ca_crl", "pck_crl", "tcb_info_signature", "qe_identity_signature"] as const;
const HEX_RE = /^(?:[0-9a-f]{2})+$/;

/**
 * Normalises a collateral object to the canonical wire form: binary fields as lowercase hex strings,
 * unknown keys dropped. Accepts hex strings, `number[]` and `Uint8Array` for the binary fields.
 *
 * @throws PlrError E_COLLATERAL on anything that is not a valid collateral object
 */
export function canonicalCollateral(c: unknown): CollateralJson {
  if (!isPlainObject(c)) throw new PlrError("E_COLLATERAL", "not an object");
  const out: CollateralJson = {};
  for (const k of STR) {
    const v = c[k];
    if (typeof v !== "string" || v.length === 0) throw new PlrError("E_COLLATERAL", k);
    out[k] = v;
  }
  for (const k of BIN) {
    const v = c[k];
    if (typeof v === "string") {
      const h = v.toLowerCase();
      if (!HEX_RE.test(h)) throw new PlrError("E_COLLATERAL", k);
      out[k] = h;
    } else if (v instanceof Uint8Array || (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255))) {
      out[k] = toHex(Uint8Array.from(v as ArrayLike<number>));
    } else throw new PlrError("E_COLLATERAL", k);
  }
  if (typeof c.pck_certificate_chain === "string" && c.pck_certificate_chain.length > 0) {
    out.pck_certificate_chain = c.pck_certificate_chain;
  }
  return out;
}

/** True if `c` is a collateral object that {@link canonicalCollateral} accepts. */
export function isCollateralJson(c: unknown): c is CollateralJson {
  try {
    canonicalCollateral(c);
    return true;
  } catch {
    return false;
  }
}
