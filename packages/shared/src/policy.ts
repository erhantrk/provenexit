/** Client-side attestation policy: `verifyAttestation` with the exact check order and codes of SPEC §9. */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError, type PlrErrorCode } from "./errors.js";
import { equalBytes, fromHex, isAllZero, isBytes, isHex, isPlainObject, isWellFormedString, toHex, utf8 } from "./bytes.js";
import { QUOTE, isDebug, osMeasurement, parseQuote, type ParsedQuote, type RootKind, type TdReport } from "./tdx/quote.js";
import { verifyEventLog, type TdxEvent } from "./tdx/eventlog.js";
import { verifyEventLogDstack } from "./tdx/eventlog-dstack.js";
import { keyHash, registrationReportData, sessionNonceDigest } from "./tdx/measure.js";
import type { QuoteVerifier, VerifyContext } from "./attest/types.js";
import { isCollateralJson } from "./attest/collateral.js";
import { checkDstackComposePolicy } from "./attest/compose-policy.js";
import { isInstanceRecord, isRegistryRoot, type InstanceRecord, type RegistryReader } from "./registry.js";

/** `GET /v1/attestation` response body (SPEC §6.2). */
export interface AttestationBundle {
  v: "PLR-v1";
  root_kind: RootKind;
  quote: string;
  event_log: TdxEvent[];
  app_compose: string;
  x25519: string;
  ed25519: string;
  /**
   * SPEC-CHAINS §2 (rev 1.4): the instance's registration quote (hex), included once registered. Offered to
   * tier-C registries, which accept it only if it matches the on-chain commitment. Malformed ⇒ treated as absent.
   */
  registration_quote?: string;
  /**
   * INTEL mode only (INTERFACES §1.5): the canonical collateral JSON of the quote (§1.2). Required in INTEL mode,
   * ignored or absent in MOCK mode. Intel signs it and the client freshness-checks it, so taking it from the
   * (untrusted) exit is safe.
   */
  collateral?: Record<string, unknown>;
}

export interface VerifiedRouter {
  x25519: Uint8Array;
  ed25519: Uint8Array;
  keyHash: Uint8Array;
  composeHash: Uint8Array;
  osMeasurement: Uint8Array;
  rootKind: RootKind;
  /** Human-readable names of the checks that passed, in order. */
  checks: string[];
  /**
   * The registration quote that passed SPEC-CHAINS §2 (tier B/C only). Re-checks pass it to `getInstance` so a
   * tier-C reader keeps selecting the registration this evidence binds.
   */
  registrationQuote?: Uint8Array;
  /** INTEL mode only: the DCAP TCB status the verifier accepted (INTERFACES §3.1). */
  tcbStatus?: string;
  /** INTEL mode only: the image references checkDstackComposePolicy extracted (§1.4). */
  images?: string[];
}

export interface VerifyAttestationParams {
  bundle: AttestationBundle;
  /** The fresh 32-byte random nonce this client sent. */
  nonce: Uint8Array;
  verifier: QuoteVerifier;
  registry: RegistryReader;
  /** Root public key pinned in the client config (64-byte P-256 `x‖y`). */
  trustedRoot: Uint8Array;
  /** Clock for the instance-expiry check (default `Date.now()`). */
  now?: number;
}

/** Max UTF-8 size of `app_compose` (matches the contract bound, SPEC §7). */
export const MAX_APP_COMPOSE_BYTES = 8 * 1024;

/** Max UTF-8 size of the dstack app-compose in INTEL mode (INTERFACES §0, §1.4). */
export const MAX_DSTACK_COMPOSE_BYTES = 32 * 1024;

/** Names of the checks reported in {@link VerifiedRouter.checks}, in SPEC §9 order. */
export const CHECKS = Object.freeze({
  RESPONSE: "response well-formed, fresh 32-byte nonce",
  QUOTE_FORMAT: "quote structure (TDX v4)",
  TEE_TYPE: "TEE type is TDX",
  ROOT: "pinned root == registry root == verifier root",
  QUOTE_SIG: "quote signature chain to root",
  DEBUG: "TD debug attribute clear",
  REPORT_DATA_KEYS: "report_data binds router keys",
  NONCE: "report_data binds client nonce",
  EVENT_LOG: "event log digests and boot sequence",
  RTMR3: "event log replays to RTMR3",
  COMPOSE: "app-compose matches measured compose-hash",
  COMPOSE_ALLOWED: "compose hash allowed by registry",
  OS_ALLOWED: "OS measurement allowed by registry",
  INSTANCE: "instance registered with matching keys",
  TCB: "Intel TCB status accepted",
  COMPOSE_POLICY: "dstack compose: images pinned by digest, exit logging disabled",
} as const);

/**
 * SPEC-CHAINS §2 step 9b, reported in {@link VerifiedRouter.checks} (after {@link CHECKS.INSTANCE}) only when the
 * registry does not verify registration quotes on-chain. Kept out of `CHECKS` because tier-A verifications skip it.
 */
export const REGISTRATION_EVIDENCE_CHECK = "registration quote: same boot, bound to (registry, operator)";

const fail = (code: PlrErrorCode, detail?: string): never => {
  throw new PlrError(code, detail);
};

/** Runs `f`, mapping any thrown value to PlrError(fallback) unless it is a PlrError with an allowed code. */
function guard<T>(f: () => T, allowed: readonly PlrErrorCode[], fallback: PlrErrorCode): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof PlrError && allowed.includes(e.code)) throw e;
    throw new PlrError(fallback);
  }
}

/** Any registry failure (rejection, throw, or malformed reply) → E_REGISTRY_UNAVAILABLE. */
async function reg<T>(f: () => Promise<unknown>, valid: (v: unknown) => v is T): Promise<T> {
  let v: unknown;
  try {
    v = await f();
  } catch {
    throw new PlrError("E_REGISTRY_UNAVAILABLE");
  }
  if (!valid(v)) throw new PlrError("E_REGISTRY_UNAVAILABLE", "malformed registry reply");
  return v;
}

const isBool = (v: unknown): v is boolean => typeof v === "boolean";

interface ParsedBundle {
  rootKind: RootKind;
  quote: Uint8Array;
  eventLog: TdxEvent[];
  composeBytes: Uint8Array;
  x25519: Uint8Array;
  ed25519: Uint8Array;
  /** The bundle's well-formed `registration_quote`, else undefined. */
  registrationQuote: Uint8Array | undefined;
  /** INTEL mode: the canonical collateral JSON (§1.2); undefined in MOCK mode. */
  collateral: Record<string, unknown> | undefined;
}

/** Step 1: shape of the response (E_BAD_RESPONSE). Content of event entries is checked in step 6. */
function parseBundle(b: unknown, expectedKind: RootKind): ParsedBundle {
  const bad = (d: string): never => fail("E_BAD_RESPONSE", d);
  if (!isPlainObject(b)) return bad("bundle is not an object");
  if (b.v !== "PLR-v1") bad("v");
  if (b.root_kind !== expectedKind) bad("root_kind");
  if (!isHex(b.quote) || b.quote.length === 0 || b.quote.length > QUOTE.MAX_LEN * 2) bad("quote");
  if (!Array.isArray(b.event_log)) bad("event_log");
  if (!isWellFormedString(b.app_compose)) bad("app_compose");
  if (!isHex(b.x25519, 32)) bad("x25519");
  if (!isHex(b.ed25519, 32)) bad("ed25519");
  const composeBytes = utf8(b.app_compose as string);
  const maxCompose = expectedKind === "INTEL" ? MAX_DSTACK_COMPOSE_BYTES : MAX_APP_COMPOSE_BYTES;
  if (composeBytes.length === 0 || composeBytes.length > maxCompose) bad("app_compose size");
  // INTERFACES §1.5: collateral is required in INTEL mode (ignored or absent in MOCK mode).
  let collateral: Record<string, unknown> | undefined;
  if (expectedKind === "INTEL") {
    const c = b.collateral;
    if (isCollateralJson(c)) collateral = c;
    else bad("collateral");
  }
  const x = fromHex(b.x25519 as string, 32);
  const e = fromHex(b.ed25519 as string, 32);
  if (isAllZero(x)) bad("x25519");
  try {
    const pt = ed25519.Point.fromBytes(e, false);
    if (pt.isSmallOrder()) bad("ed25519");
  } catch {
    bad("ed25519");
  }
  // SPEC-CHAINS §4: a malformed registration_quote is treated as absent (never a reason to reject the bundle).
  const rq = b.registration_quote;
  const registrationQuote = isHex(rq) && rq.length > 0 && rq.length <= QUOTE.MAX_LEN * 2 ? fromHex(rq) : undefined;
  return {
    rootKind: expectedKind,
    registrationQuote,
    collateral,
    quote: fromHex(b.quote as string),
    eventLog: b.event_log as TdxEvent[],
    composeBytes,
    x25519: x,
    ed25519: e,
  };
}

/**
 * Verifies a router attestation bundle against the client's nonce, pinned root, quote verifier and the
 * on-chain registry, in SPEC §9 order. Fails closed: the first failing check throws `PlrError(code)`.
 */
export async function verifyAttestation(p: VerifyAttestationParams): Promise<VerifiedRouter> {
  const checks: string[] = [];
  if (!isPlainObject(p)) fail("E_BAD_RESPONSE", "params");
  const { bundle, nonce, verifier, registry, trustedRoot } = p;
  const nowSecs = Math.floor((p.now ?? Date.now()) / 1000);

  // Configuration sanity (not attacker-controlled; fail closed).
  if (typeof verifier !== "object" || verifier === null || typeof verifier.verify !== "function" ||
      (verifier.rootKind !== "MOCK" && verifier.rootKind !== "INTEL")) {
    fail("E_ROOT_UNTRUSTED", "verifier");
  }

  // 1. nonce + response shape
  if (!isBytes(nonce) || nonce.length !== 32 || isAllZero(nonce)) fail("E_BAD_RESPONSE", "nonce");
  const b = parseBundle(bundle, verifier.rootKind);
  checks.push(CHECKS.RESPONSE);

  // 2. quote structure, TEE type
  const parsed: ParsedQuote = guard(() => parseQuote(b.quote, b.rootKind), ["E_QUOTE_FORMAT", "E_TEE_TYPE"], "E_QUOTE_FORMAT");
  checks.push(CHECKS.QUOTE_FORMAT, CHECKS.TEE_TYPE);

  // 3. root: pinned == registry == verifier, then signature chain
  const root = await reg(() => registry.getRoot(), isRegistryRoot);
  if (!isBytes(trustedRoot) || trustedRoot.length !== 64) fail("E_ROOT_UNTRUSTED", "pinned root");
  if (root.kind !== verifier.rootKind || !equalBytes(fromHex(root.p256, 64), trustedRoot)) {
    fail("E_ROOT_UNTRUSTED", "registry root differs from pinned root");
  }
  const verifierRoot: unknown = guard(() => verifier.rootPublicKey, [], "E_ROOT_UNTRUSTED");
  if (!isBytes(verifierRoot) || !equalBytes(verifierRoot, trustedRoot)) {
    fail("E_ROOT_UNTRUSTED", "verifier root differs from pinned root");
  }
  checks.push(CHECKS.ROOT);
  const ctx: VerifyContext = { collateral: b.collateral, nowSecs };
  const verified = guard(
    () => verifier.verify(b.quote, ctx),
    ["E_QUOTE_FORMAT", "E_TEE_TYPE", "E_QUOTE_SIG", "E_TCB_STATUS", "E_COLLATERAL"],
    "E_QUOTE_SIG",
  );
  if (!isPlainObject(verified) || !isBytes(verified.signedBytes) || !equalBytes(verified.signedBytes, parsed.signedBytes)) {
    fail("E_QUOTE_SIG", "verifier result");
  }
  checks.push(CHECKS.QUOTE_SIG);
  // INTEL only (§3.1): the DCAP verifier reports the accepted TCB status after a successful verify.
  let tcbStatus: string | undefined;
  if (b.rootKind === "INTEL") {
    tcbStatus = (verifier as { lastStatus?: string }).lastStatus;
    checks.push(CHECKS.TCB);
  }
  const report = parsed.report;

  // 4. debug
  if (isDebug(report)) fail("E_DEBUG_TD");
  checks.push(CHECKS.DEBUG);

  // 5. report_data = key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce) (rev 1.3)
  const kh = keyHash(b.x25519, b.ed25519);
  if (!equalBytes(report.reportData.subarray(0, 32), kh)) fail("E_REPORT_DATA_KEYS");
  checks.push(CHECKS.REPORT_DATA_KEYS);
  if (!equalBytes(report.reportData.subarray(32, 64), sessionNonceDigest(nonce))) fail("E_NONCE");
  checks.push(CHECKS.NONCE);

  // 6. event log, RTMR3 (INTEL mode: the dstack V1 log of INTERFACES §1.3)
  const ids = guard(
    () => (b.rootKind === "INTEL" ? verifyEventLogDstack : verifyEventLog)(b.eventLog, report.rtmr[3]),
    ["E_EVENT_LOG", "E_RTMR3"],
    "E_EVENT_LOG",
  );
  checks.push(CHECKS.EVENT_LOG, CHECKS.RTMR3);

  // 7. published compose == measured compose
  if (!equalBytes(sha256(b.composeBytes), ids.composeHash)) fail("E_COMPOSE_MISMATCH");
  checks.push(CHECKS.COMPOSE);

  // 7b. INTEL only: the measured compose is a dstack app-compose whose images are pinned and whose exit is silent.
  let pol: { images: string[] } | undefined;
  if (b.rootKind === "INTEL") {
    pol = guard(() => checkDstackComposePolicy(bundle.app_compose as string), ["E_COMPOSE_POLICY"], "E_COMPOSE_POLICY");
    checks.push(CHECKS.COMPOSE_POLICY);
  }

  // 8. on-chain allowlists (checked separately)
  const composeHex = toHex(ids.composeHash);
  const os = osMeasurement(report);
  const osHex = toHex(os);
  if (!(await reg(() => registry.isComposeAllowed(composeHex), isBool))) fail("E_COMPOSE_NOT_ALLOWED");
  checks.push(CHECKS.COMPOSE_ALLOWED);
  if (!(await reg(() => registry.isOsAllowed(osHex), isBool))) fail("E_OS_NOT_ALLOWED");
  checks.push(CHECKS.OS_ALLOWED);

  // 9. live registration for exactly these keys / compose / OS
  const inst = await reg(() => registry.getInstance(toHex(kh)), (v): v is unknown => v === null || isInstanceRecord(v));
  if (!isInstanceRecord(inst)) return fail("E_INSTANCE_NOT_REGISTERED");
  const now = p.now ?? Date.now();
  if (
    inst.compose_hash !== composeHex ||
    inst.os_measurement !== osHex ||
    inst.x25519 !== toHex(b.x25519) ||
    inst.ed25519 !== toHex(b.ed25519) ||
    !(inst.expires_at_ms > now)
  ) {
    fail("E_INSTANCE_NOT_REGISTERED", "registry record does not match attestation");
  }
  checks.push(CHECKS.INSTANCE);

  // 9b. registration evidence (SPEC-CHAINS §2, rev 1.4) unless the registry verified the quote on-chain (tier A).
  // Fail closed: anything but an explicit `true` requires the evidence.
  let onChain: unknown;
  try {
    onChain = registry.verifiesOnChain;
  } catch {
    onChain = false;
  }
  let evidence: Uint8Array | undefined;
  if (onChain !== true) {
    evidence = await verifyRegistrationEvidence({ registry, verifier, keyHashHex: toHex(kh), offered: b.registrationQuote, session: report, inst, x25519: b.x25519, ed25519: b.ed25519, rootKind: b.rootKind, ctx });
    checks.push(REGISTRATION_EVIDENCE_CHECK);
  }

  return {
    ...(evidence !== undefined ? { registrationQuote: evidence } : {}),
    ...(tcbStatus !== undefined ? { tcbStatus } : {}),
    ...(pol !== undefined ? { images: pol.images } : {}),
    x25519: b.x25519.slice(),
    ed25519: b.ed25519.slice(),
    keyHash: kh,
    composeHash: ids.composeHash,
    osMeasurement: os,
    rootKind: b.rootKind,
    checks,
  };
}

const isQuoteOrNull = (v: unknown): v is Uint8Array | null => v === null || isBytes(v);

/**
 * SPEC-CHAINS §2 steps 1–4: the registration quote verifies under the pinned root, is not DEBUG, binds
 * `registrationReportData(keys, registry.contractId, record.operator)` and comes from the same TD boot
 * (MRTD and RTMR0..3 equal the session quote's). Any failure ⇒ E_REGISTRATION_EVIDENCE; a throwing or
 * malformed registry ⇒ E_REGISTRY_UNAVAILABLE.
 */
async function verifyRegistrationEvidence(p: {
  registry: RegistryReader;
  verifier: QuoteVerifier;
  keyHashHex: string;
  offered: Uint8Array | undefined;
  session: TdReport;
  inst: InstanceRecord;
  x25519: Uint8Array;
  ed25519: Uint8Array;
  rootKind: RootKind;
  /** INTEL mode: same `{ collateral, nowSecs }` as the session quote (INTERFACES §3.1 step 7). */
  ctx: VerifyContext;
}): Promise<Uint8Array> {
  const E = "E_REGISTRATION_EVIDENCE" as const;
  const offered = p.offered === undefined ? undefined : p.offered.slice();
  const rq = await reg(() => p.registry.getRegistrationQuote(p.keyHashHex, offered), isQuoteOrNull);
  if (rq === null || rq.length === 0 || rq.length > QUOTE.MAX_LEN) return fail(E, "no registration quote");
  const quote = rq.slice();
  const parsed = guard(() => parseQuote(quote, p.rootKind), [], E);
  const verified: unknown = guard(() => p.verifier.verify(quote, p.ctx), [], E);
  if (!isPlainObject(verified) || !isBytes(verified.signedBytes) || !equalBytes(verified.signedBytes, parsed.signedBytes)) {
    fail(E, "registration quote signature");
  }
  const r = parsed.report;
  if (isDebug(r)) fail(E, "registration quote is DEBUG");
  const expected = guard(() => registrationReportData(p.x25519, p.ed25519, p.registry.contractId, p.inst.operator), [], E);
  if (!equalBytes(r.reportData, expected)) fail(E, "registration report_data");
  const s = p.session;
  if (
    !equalBytes(r.mrTd, s.mrTd) ||
    !equalBytes(r.rtmr[0], s.rtmr[0]) ||
    !equalBytes(r.rtmr[1], s.rtmr[1]) ||
    !equalBytes(r.rtmr[2], s.rtmr[2]) ||
    !equalBytes(r.rtmr[3], s.rtmr[3])
  ) {
    fail(E, "registration quote is from another boot");
  }
  return quote.slice();
}
