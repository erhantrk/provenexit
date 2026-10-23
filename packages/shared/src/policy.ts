/** Client-side attestation policy: `verifyAttestation` with the exact check order and codes of SPEC §9. */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError, type PlrErrorCode } from "./errors.js";
import { equalBytes, fromHex, isAllZero, isBytes, isHex, isPlainObject, isWellFormedString, toHex, utf8 } from "./bytes.js";
import { QUOTE, isDebug, osMeasurement, parseQuote, type ParsedQuote, type RootKind } from "./tdx/quote.js";
import { verifyEventLog, type TdxEvent } from "./tdx/eventlog.js";
import { keyHash, sessionNonceDigest } from "./tdx/measure.js";
import type { QuoteVerifier } from "./attest/types.js";
import { isInstanceRecord, isRegistryRoot, type RegistryReader } from "./registry.js";

/** `GET /v1/attestation` response body (SPEC §6.2). */
export interface AttestationBundle {
  v: "PLR-v1";
  root_kind: RootKind;
  quote: string;
  event_log: TdxEvent[];
  app_compose: string;
  x25519: string;
  ed25519: string;
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
} as const);

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
}

/** Step 1: shape of the response (E_BAD_RESPONSE). Content of event entries is checked in step 6. */
function parseBundle(b: unknown, expectedKind: RootKind): ParsedBundle {
  const bad = (d: string) => fail("E_BAD_RESPONSE", d);
  if (!isPlainObject(b)) return bad("bundle is not an object");
  if (b.v !== "PLR-v1") bad("v");
  if (b.root_kind !== expectedKind) bad("root_kind");
  if (!isHex(b.quote) || b.quote.length === 0 || b.quote.length > QUOTE.MAX_LEN * 2) bad("quote");
  if (!Array.isArray(b.event_log)) bad("event_log");
  if (!isWellFormedString(b.app_compose)) bad("app_compose");
  if (!isHex(b.x25519, 32)) bad("x25519");
  if (!isHex(b.ed25519, 32)) bad("ed25519");
  const composeBytes = utf8(b.app_compose as string);
  if (composeBytes.length === 0 || composeBytes.length > MAX_APP_COMPOSE_BYTES) bad("app_compose size");
  const x = fromHex(b.x25519 as string, 32);
  const e = fromHex(b.ed25519 as string, 32);
  if (isAllZero(x)) bad("x25519");
  try {
    const pt = ed25519.Point.fromBytes(e, false);
    if (pt.isSmallOrder()) bad("ed25519");
  } catch {
    bad("ed25519");
  }
  return {
    rootKind: expectedKind,
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
  const verified = guard(() => verifier.verify(b.quote), ["E_QUOTE_FORMAT", "E_TEE_TYPE", "E_QUOTE_SIG"], "E_QUOTE_SIG");
  if (!isPlainObject(verified) || !isBytes(verified.signedBytes) || !equalBytes(verified.signedBytes, parsed.signedBytes)) {
    fail("E_QUOTE_SIG", "verifier result");
  }
  checks.push(CHECKS.QUOTE_SIG);
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

  // 6. event log, RTMR3
  const ids = guard(() => verifyEventLog(b.eventLog, report.rtmr[3]), ["E_EVENT_LOG", "E_RTMR3"], "E_EVENT_LOG");
  checks.push(CHECKS.EVENT_LOG, CHECKS.RTMR3);

  // 7. published compose == measured compose
  if (!equalBytes(sha256(b.composeBytes), ids.composeHash)) fail("E_COMPOSE_MISMATCH");
  checks.push(CHECKS.COMPOSE);

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

  return {
    x25519: b.x25519.slice(),
    ed25519: b.ed25519.slice(),
    keyHash: kh,
    composeHash: ids.composeHash,
    osMeasurement: os,
    rootKind: b.rootKind,
    checks,
  };
}
