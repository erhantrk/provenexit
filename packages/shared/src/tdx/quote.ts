/** Intel TDX Quote v4 layout, MOCK signature mode (SPEC §2). */
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, equalBytes, isAllZero, isBytes, utf8 } from "../bytes.js";

export const QUOTE = Object.freeze({
  HEADER_LEN: 48,
  BODY_LEN: 584,
  SIGNED_LEN: 632,
  /** Offset of `u32le sig_data_len`. */
  SIG_LEN_OFF: 632,
  /** Offset of `sig_data`. */
  SIG_DATA_OFF: 636,
  MOCK_SIG_DATA_LEN: 192,
  MOCK_LEN: 828,
  /** Upper bound for INTEL-mode quotes (QE report + PCK chain); anything larger is rejected. */
  MAX_LEN: 32 * 1024,
  VERSION: 4,
  ATT_KEY_TYPE_ECDSA_P256: 2,
  TEE_TYPE_TDX: 0x81,
  OFF: Object.freeze({
    VERSION: 0,
    ATT_KEY_TYPE: 2,
    TEE_TYPE: 4,
    RESERVED: 8,
    QE_VENDOR_ID: 12,
    USER_DATA: 28,
    TEE_TCB_SVN: 48,
    MR_SEAM: 64,
    MR_SIGNER_SEAM: 112,
    SEAM_ATTRIBUTES: 160,
    TD_ATTRIBUTES: 168,
    XFAM: 176,
    MR_TD: 184,
    MR_CONFIG_ID: 232,
    MR_OWNER: 280,
    MR_OWNER_CONFIG: 328,
    RTMR0: 376,
    RTMR1: 424,
    RTMR2: 472,
    RTMR3: 520,
    REPORT_DATA: 568,
  } as const),
} as const);

/** `utf8("PLR-MOCK-QE-0001")` */
export const MOCK_QE_VENDOR_ID: Uint8Array = utf8("PLR-MOCK-QE-0001");
/** Intel QE vendor id `939a7233f79c4ca9940a0db3957f0607`. */
export const INTEL_QE_VENDOR_ID: Uint8Array = Uint8Array.from([
  0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
]);

export type RootKind = "MOCK" | "INTEL";

export interface TdReport {
  teeTcbSvn: Uint8Array; // 16
  mrSeam: Uint8Array; // 48
  mrSignerSeam: Uint8Array; // 48
  seamAttributes: Uint8Array; // 8
  tdAttributes: Uint8Array; // 8
  xfam: Uint8Array; // 8
  mrTd: Uint8Array; // 48
  mrConfigId: Uint8Array; // 48
  mrOwner: Uint8Array; // 48
  mrOwnerConfig: Uint8Array; // 48
  rtmr: [Uint8Array, Uint8Array, Uint8Array, Uint8Array]; // 4 × 48
  reportData: Uint8Array; // 64
}

export interface ParsedQuote {
  version: number;
  attKeyType: number;
  teeType: number;
  qeVendorId: Uint8Array;
  userData: Uint8Array;
  report: TdReport;
  /** `quote[0:632]` — the bytes covered by `quote_sig`. */
  signedBytes: Uint8Array;
  sigData: Uint8Array;
}

type ScalarField = Exclude<keyof TdReport, "rtmr">;

/** Report body fields in wire order (absolute offset, length). */
const FIELDS: ReadonlyArray<readonly [ScalarField | "rtmr0" | "rtmr1" | "rtmr2" | "rtmr3", number, number]> = [
  ["teeTcbSvn", 48, 16],
  ["mrSeam", 64, 48],
  ["mrSignerSeam", 112, 48],
  ["seamAttributes", 160, 8],
  ["tdAttributes", 168, 8],
  ["xfam", 176, 8],
  ["mrTd", 184, 48],
  ["mrConfigId", 232, 48],
  ["mrOwner", 280, 48],
  ["mrOwnerConfig", 328, 48],
  ["rtmr0", 376, 48],
  ["rtmr1", 424, 48],
  ["rtmr2", 472, 48],
  ["rtmr3", 520, 48],
  ["reportData", 568, 64],
];

function fieldOf(report: TdReport, name: (typeof FIELDS)[number][0]): unknown {
  switch (name) {
    case "rtmr0":
      return report.rtmr?.[0];
    case "rtmr1":
      return report.rtmr?.[1];
    case "rtmr2":
      return report.rtmr?.[2];
    case "rtmr3":
      return report.rtmr?.[3];
    default:
      return report[name];
  }
}

/** Serialises a quote. Throws PlrError E_BAD_INPUT on any wrong field length. */
export function encodeQuote(
  header: { qeVendorId: Uint8Array; userData?: Uint8Array },
  report: TdReport,
  sigData: Uint8Array,
): Uint8Array {
  const qe = header?.qeVendorId;
  const ud = header?.userData ?? new Uint8Array(20);
  if (!isBytes(qe) || qe.length !== 16) throw new PlrError("E_BAD_INPUT", "qeVendorId must be 16 bytes");
  if (!isBytes(ud) || ud.length !== 20) throw new PlrError("E_BAD_INPUT", "userData must be 20 bytes");
  if (!isBytes(sigData) || sigData.length > QUOTE.MAX_LEN - QUOTE.SIG_DATA_OFF) {
    throw new PlrError("E_BAD_INPUT", "bad sigData");
  }
  if (typeof report !== "object" || report === null || !Array.isArray(report.rtmr) || report.rtmr.length !== 4) {
    throw new PlrError("E_BAD_INPUT", "bad report");
  }
  const q = new Uint8Array(QUOTE.SIG_DATA_OFF + sigData.length);
  const dv = new DataView(q.buffer);
  dv.setUint16(0, QUOTE.VERSION, true);
  dv.setUint16(2, QUOTE.ATT_KEY_TYPE_ECDSA_P256, true);
  dv.setUint32(4, QUOTE.TEE_TYPE_TDX, true);
  q.set(qe, QUOTE.OFF.QE_VENDOR_ID);
  q.set(ud, QUOTE.OFF.USER_DATA);
  for (const [name, off, len] of FIELDS) {
    const v = fieldOf(report, name);
    if (!isBytes(v) || v.length !== len) throw new PlrError("E_BAD_INPUT", `report.${name} must be ${len} bytes`);
    q.set(v, off);
  }
  dv.setUint32(QUOTE.SIG_LEN_OFF, sigData.length, true);
  q.set(sigData, QUOTE.SIG_DATA_OFF);
  return q;
}

/**
 * Parses and structurally validates a quote (SPEC §2.3). Returned byte fields are copies.
 *
 * MOCK mode (default): length exactly 828, `sig_data_len == 192`, `qe_vendor_id == MOCK_QE_VENDOR_ID`.
 * INTEL mode: `qe_vendor_id` = Intel, `sig_data_len` equals the remaining length (≤ {@link QUOTE.MAX_LEN}).
 *
 * @throws PlrError E_QUOTE_FORMAT, or E_TEE_TYPE when the TEE type is not TDX.
 */
export function parseQuote(q: Uint8Array, mode: RootKind = "MOCK"): ParsedQuote {
  if (!isBytes(q) || q.length < QUOTE.SIG_DATA_OFF || q.length > QUOTE.MAX_LEN) {
    throw new PlrError("E_QUOTE_FORMAT", "bad length");
  }
  if (mode !== "MOCK" && mode !== "INTEL") throw new PlrError("E_QUOTE_FORMAT", "unknown mode");
  const dv = new DataView(q.buffer, q.byteOffset, q.byteLength);
  const version = dv.getUint16(QUOTE.OFF.VERSION, true);
  const attKeyType = dv.getUint16(QUOTE.OFF.ATT_KEY_TYPE, true);
  const teeType = dv.getUint32(QUOTE.OFF.TEE_TYPE, true);
  if (version !== QUOTE.VERSION) throw new PlrError("E_QUOTE_FORMAT", "version");
  if (attKeyType !== QUOTE.ATT_KEY_TYPE_ECDSA_P256) throw new PlrError("E_QUOTE_FORMAT", "att_key_type");
  if (teeType !== QUOTE.TEE_TYPE_TDX) throw new PlrError("E_TEE_TYPE");
  if (!isAllZero(q.subarray(QUOTE.OFF.RESERVED, QUOTE.OFF.RESERVED + 4))) throw new PlrError("E_QUOTE_FORMAT", "reserved");
  const qeVendorId = q.slice(QUOTE.OFF.QE_VENDOR_ID, QUOTE.OFF.QE_VENDOR_ID + 16);
  const sigDataLen = dv.getUint32(QUOTE.SIG_LEN_OFF, true);
  if (mode === "MOCK") {
    if (!equalBytes(qeVendorId, MOCK_QE_VENDOR_ID)) throw new PlrError("E_QUOTE_FORMAT", "qe_vendor_id");
    if (sigDataLen !== QUOTE.MOCK_SIG_DATA_LEN || q.length !== QUOTE.MOCK_LEN) {
      throw new PlrError("E_QUOTE_FORMAT", "sig_data length");
    }
  } else {
    if (!equalBytes(qeVendorId, INTEL_QE_VENDOR_ID)) throw new PlrError("E_QUOTE_FORMAT", "qe_vendor_id");
    if (sigDataLen === 0 || sigDataLen !== q.length - QUOTE.SIG_DATA_OFF) {
      throw new PlrError("E_QUOTE_FORMAT", "sig_data length");
    }
  }
  const at = (off: number, len: number) => q.slice(off, off + len);
  const report: TdReport = {
    teeTcbSvn: at(48, 16),
    mrSeam: at(64, 48),
    mrSignerSeam: at(112, 48),
    seamAttributes: at(160, 8),
    tdAttributes: at(168, 8),
    xfam: at(176, 8),
    mrTd: at(184, 48),
    mrConfigId: at(232, 48),
    mrOwner: at(280, 48),
    mrOwnerConfig: at(328, 48),
    rtmr: [at(376, 48), at(424, 48), at(472, 48), at(520, 48)],
    reportData: at(568, 64),
  };
  return {
    version,
    attKeyType,
    teeType,
    qeVendorId,
    userData: at(QUOTE.OFF.USER_DATA, 20),
    report,
    signedBytes: q.slice(0, QUOTE.SIGNED_LEN),
    sigData: q.slice(QUOTE.SIG_DATA_OFF),
  };
}

/** DEBUG = bit 0 of td_attributes byte 0 (absolute byte 168). Malformed attributes count as debug (fail closed). */
export function isDebug(report: TdReport): boolean {
  const a = report?.tdAttributes;
  if (!isBytes(a) || a.length !== 8) return true;
  return (a[0]! & 0x01) === 0x01;
}

/** `SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)` (SPEC §2.5). */
export function osMeasurement(report: TdReport): Uint8Array {
  const parts = [report?.mrTd, report?.rtmr?.[0], report?.rtmr?.[1], report?.rtmr?.[2]];
  for (const p of parts) if (!isBytes(p) || p.length !== 48) throw new PlrError("E_BAD_INPUT", "measurement must be 48 bytes");
  return sha256(concatBytes(...(parts as Uint8Array[])));
}

/** Deterministic mock OS measurements (SPEC §2.4); rtmr3 and reportData are zero. */
export function mockOsReport(opts: { debug?: boolean } = {}): TdReport {
  const tdAttributes = new Uint8Array(8);
  if (opts.debug === true) tdAttributes[0] = 0x01;
  return {
    teeTcbSvn: new Uint8Array(16),
    mrSeam: new Uint8Array(48),
    mrSignerSeam: new Uint8Array(48),
    seamAttributes: new Uint8Array(8),
    tdAttributes,
    xfam: new Uint8Array(8),
    mrTd: sha384(utf8("PLR-MOCK-OS-v1:MRTD")),
    mrConfigId: new Uint8Array(48),
    mrOwner: new Uint8Array(48),
    mrOwnerConfig: new Uint8Array(48),
    rtmr: [
      sha384(utf8("PLR-MOCK-OS-v1:RTMR0")),
      sha384(utf8("PLR-MOCK-OS-v1:RTMR1")),
      sha384(utf8("PLR-MOCK-OS-v1:RTMR2")),
      new Uint8Array(48),
    ],
    reportData: new Uint8Array(64),
  };
}
