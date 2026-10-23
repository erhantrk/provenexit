/**
 * MOCK attestation root, mock TDX attester and verifier (SPEC §2.3, §2.4).
 *
 * Signatures are ECDSA-P256-SHA256, encoded `r‖s` (64 bytes), low-S. Public keys are 64-byte `x‖y`.
 */
import { p256 } from "@noble/curves/nist.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { PlrError } from "../errors.js";
import { concatBytes, isBytes, utf8 } from "../bytes.js";
import { MOCK_QE_VENDOR_ID, QUOTE, encodeQuote, mockOsReport, osMeasurement, parseQuote, type ParsedQuote } from "../tdx/quote.js";
import { bootEvents, replayRtmr3, type TdxEvent } from "../tdx/eventlog.js";
import type { Attester, QuoteVerifier } from "./types.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** Domain prefix of the AK certificate message. */
export const MOCK_AK_CERT_PREFIX: Uint8Array = utf8("PLR-MOCK-AK-v1");

const N = p256.Point.CURVE().n;
const HALF_N = N >> 1n;

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/** True if `pub` is a 64-byte `x‖y` encoding of a valid P-256 point (not infinity). */
export function isValidP256Pub(pub: unknown): pub is Uint8Array {
  if (!isBytes(pub) || pub.length !== 64) return false;
  try {
    p256.Point.fromBytes(concatBytes(Uint8Array.of(0x04), pub)).assertValidity();
    return true;
  } catch {
    return false;
  }
}

/**
 * Verifies a 64-byte `r‖s` ECDSA-P256-SHA256 signature under a 64-byte `x‖y` key.
 * Rejects (returns false) high-S (`s > n/2`), out-of-range r/s, invalid keys. Never throws.
 */
export function p256VerifyLowS(sig: Uint8Array, msg: Uint8Array, pub64: Uint8Array): boolean {
  try {
    if (!isBytes(sig) || sig.length !== 64 || !isBytes(msg) || !isValidP256Pub(pub64)) return false;
    const r = bytesToBigInt(sig.subarray(0, 32));
    const s = bytesToBigInt(sig.subarray(32, 64));
    if (r <= 0n || r >= N || s <= 0n || s > HALF_N) return false;
    return p256.verify(sig, msg, concatBytes(Uint8Array.of(0x04), pub64), { prehash: true, lowS: true, format: "compact" });
  } catch {
    return false;
  }
}

function p256SignLowS(msg: Uint8Array, sk: Uint8Array): Uint8Array {
  return p256.sign(msg, sk, { prehash: true, lowS: true, format: "compact" });
}

function pub64Of(sk: Uint8Array): Uint8Array {
  return p256.getPublicKey(sk, false).slice(1);
}

/** The MOCK attestation root (stand-in for Intel's root of trust). */
export class MockRoot {
  readonly publicKey: Uint8Array;
  readonly #sk: Uint8Array;

  private constructor(sk: Uint8Array) {
    this.#sk = sk.slice();
    this.publicKey = pub64Of(this.#sk);
  }

  static generate(): MockRoot {
    return new MockRoot(p256.utils.randomSecretKey());
  }

  /** @throws PlrError E_BAD_INPUT if `sk` is not a valid 32-byte P-256 scalar */
  static fromSecret(sk: Uint8Array): MockRoot {
    if (!isBytes(sk) || sk.length !== 32 || !p256.utils.isValidSecretKey(sk)) {
      throw new PlrError("E_BAD_INPUT", "invalid root secret key");
    }
    return new MockRoot(sk);
  }

  /** A copy of the 32-byte secret scalar. */
  get secretKey(): Uint8Array {
    return this.#sk.slice();
  }

  /** `ECDSA-P256-SHA256(ROOT, utf8("PLR-MOCK-AK-v1") ‖ akPub)`, low-S, `r‖s`. */
  certifyAk(akPub: Uint8Array): Uint8Array {
    if (!isValidP256Pub(akPub)) throw new PlrError("E_BAD_INPUT", "invalid AK public key");
    return p256SignLowS(concatBytes(MOCK_AK_CERT_PREFIX, akPub), this.#sk);
  }
}

export interface MockTdxAttesterOptions {
  root: MockRoot;
  composeBytes: Uint8Array;
  /** 20 bytes; random if omitted (one value per "boot"). */
  instanceId?: Uint8Array;
  /** Launch with the TD DEBUG attribute set. */
  debug?: boolean;
}

/**
 * Mock TDX quoting for one "boot": a fresh attestation key certified by the root, the §3 boot sequence
 * measured into RTMR3, and the §2.4 OS measurements. Quotes are produced only through {@link getQuote}.
 */
export class MockTdxAttester implements Attester {
  readonly #akSk: Uint8Array;
  readonly #akPub: Uint8Array;
  readonly #akCert: Uint8Array;
  readonly #events: TdxEvent[];
  readonly #rtmr3: Uint8Array;
  readonly #debug: boolean;
  readonly #composeHash: Uint8Array;

  constructor(opts: MockTdxAttesterOptions) {
    if (typeof opts !== "object" || opts === null || !(opts.root instanceof MockRoot)) {
      throw new PlrError("E_BAD_INPUT", "root required");
    }
    if (!isBytes(opts.composeBytes)) throw new PlrError("E_BAD_INPUT", "composeBytes must be bytes");
    const instanceId = opts.instanceId ?? randomBytes(20);
    if (!isBytes(instanceId) || instanceId.length !== 20) throw new PlrError("E_BAD_INPUT", "instanceId must be 20 bytes");
    if (opts.debug !== undefined && typeof opts.debug !== "boolean") throw new PlrError("E_BAD_INPUT", "debug must be boolean");
    this.#debug = opts.debug === true;
    this.#akSk = p256.utils.randomSecretKey();
    this.#akPub = pub64Of(this.#akSk);
    this.#akCert = opts.root.certifyAk(this.#akPub);
    this.#composeHash = sha256(opts.composeBytes);
    this.#events = bootEvents(opts.composeBytes, instanceId);
    this.#rtmr3 = replayRtmr3(this.#events);
  }

  /** SHA256 of the measured compose bytes. */
  get composeHash(): Uint8Array {
    return this.#composeHash.slice();
  }

  /** The OS measurement every quote of this attester carries (SPEC §2.5). */
  get osMeasurement(): Uint8Array {
    return osMeasurement(mockOsReport());
  }

  /** A copy of the measured event log. */
  get eventLog(): TdxEvent[] {
    return this.#events.map((e) => ({ ...e }));
  }

  /** @throws PlrError E_BAD_REQUEST unless `reportData` is exactly 64 bytes */
  async getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }> {
    if (!isBytes(reportData) || reportData.length !== 64) throw new PlrError("E_BAD_REQUEST", "report_data must be 64 bytes");
    const report = mockOsReport({ debug: this.#debug });
    report.rtmr[3] = this.#rtmr3.slice();
    report.reportData = reportData.slice();
    const header = { qeVendorId: MOCK_QE_VENDOR_ID };
    const unsigned = encodeQuote(header, report, new Uint8Array(QUOTE.MOCK_SIG_DATA_LEN));
    const quoteSig = p256SignLowS(unsigned.subarray(0, QUOTE.SIGNED_LEN), this.#akSk);
    const quote = encodeQuote(header, report, concatBytes(quoteSig, this.#akPub, this.#akCert));
    return { quote, eventLog: this.eventLog };
  }
}

/** Verifies MOCK quotes: `ak_cert_sig` under ROOT, then `quote_sig` under `ak_pub`; both low-S. */
export class MockVerifier implements QuoteVerifier {
  readonly rootKind = "MOCK" as const;
  readonly #root: Uint8Array;

  /** @throws PlrError E_ROOT_UNTRUSTED if `rootPub` is not a valid 64-byte P-256 `x‖y` key */
  constructor(rootPub: Uint8Array) {
    if (!isValidP256Pub(rootPub)) throw new PlrError("E_ROOT_UNTRUSTED", "invalid root public key");
    this.#root = rootPub.slice();
  }

  get rootPublicKey(): Uint8Array {
    return this.#root.slice();
  }

  /** @throws PlrError E_QUOTE_FORMAT / E_TEE_TYPE / E_QUOTE_SIG */
  verify(quote: Uint8Array): ParsedQuote {
    const parsed = parseQuote(quote, "MOCK");
    const sd = parsed.sigData;
    const quoteSig = sd.subarray(0, 64);
    const akPub = sd.subarray(64, 128);
    const akCertSig = sd.subarray(128, 192);
    if (!p256VerifyLowS(akCertSig, concatBytes(MOCK_AK_CERT_PREFIX, akPub), this.#root)) {
      throw new PlrError("E_QUOTE_SIG", "AK certificate");
    }
    if (!p256VerifyLowS(quoteSig, parsed.signedBytes, akPub)) throw new PlrError("E_QUOTE_SIG", "quote signature");
    return parsed;
  }
}
