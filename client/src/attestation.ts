/**
 * Attestation session of `VpnClient` and each hop of `TwoHopClient` (SPEC §9, SPEC-VPN §7): fresh 32-byte random
 * nonce per attestation, `verifyAttestation` against the pinned root and the registry, a time-bounded cache of the last verification, and single-flight sharing of one in-flight
 * attestation between concurrent callers. Fails closed: any failure clears the cache and throws `PlrError`.
 */
import { randomBytes } from "node:crypto";
import {
  PlrError,
  fromHex,
  isHex,
  isInstanceRecord,
  isPlrError,
  toHex,
  verifyAttestation,
  type AttestationBundle,
  type InstanceRecord,
  type QuoteVerifier,
  type RegistryReader,
  type VerifiedRouter,
} from "@plr/shared";
import { fetchPccsCollateral } from "./pccs.js";
import { checkRegistryCode, isRegistryCodeHashError } from "./near-registry.js";

/** `MAX_TDX_QUOTE_BYTES` (SPEC-TDX §0) in hex. */
const MAX_PCCS_QUOTE_HEX = 2 * 8192;

/** A verified attestation plus the nonce it was verified with (the tunnel / session binds that nonce). */
export interface AttestationSession {
  verified: VerifiedRouter;
  attNonce: Uint8Array;
  /** Monotonic clock value at verification time. */
  at: number;
  /** The published `app-compose.json` exactly as received (its hash was verified against the quote). */
  appCompose: string;
}

export interface AttestationCacheOptions {
  /** Fetches the attestation bundle for `nonce` from the attested service (untrusted; shape checked later). */
  fetchBundle: (nonce: Uint8Array) => Promise<AttestationBundle>;
  verifier: QuoteVerifier;
  registry: RegistryReader;
  /** Pinned attestation root, 64-byte P-256 `x‖y`. */
  trustedRoot: Uint8Array;
  /** A verification is reused for less than this many ms (0 = never reused). */
  ttlMs: number;
  /** Monotonic clock in ms. */
  clock: () => number;
  /**
   * `PLR_PCCS_URL` (TASKS T24): fetch fresh Intel collateral for the quote from this PCCS instead of using the
   * exit's copy. INTEL mode only; unset ⇒ the bundle's `collateral` field is used as before.
   */
  pccsUrl?: string;
}

export class AttestationCache {
  readonly #o: AttestationCacheOptions;
  #session: AttestationSession | undefined;
  #pending: Promise<AttestationSession> | undefined;

  constructor(o: AttestationCacheOptions) {
    this.#o = { ...o, trustedRoot: o.trustedRoot.slice() };
  }

  get ttlMs(): number {
    return this.#o.ttlMs;
  }

  /** Fetches and verifies a fresh attestation (new random nonce every call) and caches it. @throws PlrError */
  async attest(): Promise<AttestationSession> {
    const nonce = new Uint8Array(randomBytes(32));
    try {
      // First of all: a registry whose account does not run the pinned code answers nothing we would trust.
      await checkRegistryCode(this.#o.registry);
      const bundle = await this.#withFreshCollateral(await this.#o.fetchBundle(nonce));
      const verified = await verifyAttestation({
        bundle,
        nonce,
        verifier: this.#o.verifier,
        registry: this.#o.registry,
        trustedRoot: this.#o.trustedRoot,
      });
      const session: AttestationSession = { verified, attNonce: nonce, at: this.#o.clock(), appCompose: bundle.app_compose };
      this.#session = session;
      return session;
    } catch (e) {
      this.#session = undefined;
      if (isPlrError(e)) throw e;
      throw new PlrError("E_BAD_RESPONSE");
    }
  }

  /**
   * SPEC-TDX §1.5 / TASKS T24: in INTEL mode with `pccsUrl` set, replace the exit's `collateral` with a fresh
   * copy fetched from the PCCS (`getCollateral`) before verification. The fetch is async and runs here, so
   * `verifyAttestation` stays synchronous and receives the value through the bundle field. The exit's own copy is
   * untrusted anyway; a stale or missing one must not decide whether the client can verify.
   * @throws PlrError E_BAD_RESPONSE (malformed quote), E_COLLATERAL (PCCS unreachable / not collateral)
   */
  async #withFreshCollateral(bundle: AttestationBundle): Promise<AttestationBundle> {
    const pccsUrl = this.#o.pccsUrl;
    if (pccsUrl === undefined || this.#o.verifier.rootKind !== "INTEL") return bundle;
    const q = bundle.quote;
    if (typeof q !== "string" || !isHex(q) || q.length === 0 || q.length > MAX_PCCS_QUOTE_HEX) {
      throw new PlrError("E_BAD_RESPONSE", "quote");
    }
    return { ...bundle, collateral: await fetchPccsCollateral(pccsUrl, fromHex(q)) };
  }

  /** The cached verification if it is younger than `ttlMs`, else a fresh one (shared between concurrent callers). */
  async current(): Promise<AttestationSession> {
    const s = this.#session;
    if (s !== undefined && this.#o.clock() - s.at < this.#o.ttlMs) return s;
    this.#pending ??= this.attest().finally(() => {
      this.#pending = undefined;
    });
    return this.#pending;
  }

  /** Forgets the cached verification; the next {@link current} re-attests. */
  invalidate(): void {
    this.#session = undefined;
  }
}

async function regCall<T>(f: () => Promise<unknown>, valid: (v: unknown) => v is T): Promise<T> {
  let v: unknown;
  try {
    v = await f();
  } catch (e) {
    if (isRegistryCodeHashError(e)) throw e;
    throw new PlrError("E_REGISTRY_UNAVAILABLE");
  }
  if (!valid(v)) throw new PlrError("E_REGISTRY_UNAVAILABLE", "malformed registry reply");
  return v;
}

const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const isInstanceOrNull = (v: unknown): v is InstanceRecord | null => v === null || isInstanceRecord(v);

/**
 * Registry re-check of an already verified attestation (SPEC §9 checks 8–10, SPEC-VPN §7 step 2): the compose
 * hash and OS measurement are still allowed and the instance is still registered, unexpired, with exactly these
 * keys / compose / OS. Used on every new connection, even with a cached attestation, so an owner revocation
 * applies to the very next connection. Returns the live instance record (incl. its operator's `org_id`).
 * @throws PlrError E_COMPOSE_NOT_ALLOWED, E_OS_NOT_ALLOWED, E_INSTANCE_NOT_REGISTERED, E_REGISTRY_UNAVAILABLE,
 *         E_REGISTRY_CODE_HASH (a pinned registry whose account runs other code)
 */
export async function recheckRegistry(registry: RegistryReader, v: VerifiedRouter, now: number = Date.now()): Promise<InstanceRecord> {
  await checkRegistryCode(registry);
  const composeHex = toHex(v.composeHash);
  const osHex = toHex(v.osMeasurement);
  if (!(await regCall(() => registry.isComposeAllowed(composeHex), isBool))) throw new PlrError("E_COMPOSE_NOT_ALLOWED");
  if (!(await regCall(() => registry.isOsAllowed(osHex), isBool))) throw new PlrError("E_OS_NOT_ALLOWED");
  const inst = await regCall(() => registry.getInstance(toHex(v.keyHash)), isInstanceOrNull);
  if (
    inst === null ||
    inst.compose_hash !== composeHex ||
    inst.os_measurement !== osHex ||
    inst.x25519 !== toHex(v.x25519) ||
    inst.ed25519 !== toHex(v.ed25519) ||
    !(inst.expires_at_ms > now)
  ) {
    throw new PlrError("E_INSTANCE_NOT_REGISTERED");
  }
  return inst;
}
