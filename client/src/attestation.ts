/**
 * Attestation session of `VpnClient` and each hop of `TwoHopClient` (SPEC §9, SPEC-VPN §7): fresh 32-byte random
 * nonce per attestation, `verifyAttestation` against the pinned root and the registry, a time-bounded cache of the last verification, and single-flight sharing of one in-flight
 * attestation between concurrent callers. Fails closed: any failure clears the cache and throws `PlrError`.
 */
import { randomBytes } from "node:crypto";
import {
  PlrError,
  fromHex,
  isCollateralJson,
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
import { CollateralFetchError, collateralSource, fetchPccsCollateral, type CollateralSource } from "./pccs.js";
import { checkRegistryCode, isRegistryRefusal } from "./near-registry.js";

/** A verified attestation plus the nonce it was verified with (the tunnel / session binds that nonce). */
export interface AttestationSession {
  verified: VerifiedRouter;
  attNonce: Uint8Array;
  /** Monotonic clock value at verification time. */
  at: number;
  /** The published `app-compose.json` exactly as received (its hash was verified against the quote). */
  appCompose: string;
  /** INTEL mode only: where the collateral of this verification came from (the client's PCCS, or the exit). */
  collateral?: CollateralSource;
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
   * `PLR_PCCS_URL` (TASKS T24), INTEL mode only: the PCCS this client fetches fresh Intel collateral from, instead
   * of using the exit's copy. Unset ⇒ `DEFAULT_PCCS_URL` (on by default, fails closed with `E_COLLATERAL_FETCH`);
   * `"exit"` ⇒ opt out and use the bundle's `collateral` field.
   */
  pccsUrl?: string;
  /** Tests only: replaces the PCCS fetch (default `fetchPccsCollateral`), so no test needs Intel's service. */
  fetchCollateral?: (pccsUrl: string, quote: Uint8Array) => Promise<Record<string, unknown>>;
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

  /** Where an INTEL verification takes its collateral from; undefined for a MOCK verifier (it has no collateral). */
  get collateral(): CollateralSource | undefined {
    return this.#o.verifier.rootKind === "INTEL" ? collateralSource(this.#o.pccsUrl) : undefined;
  }

  /** Fetches and verifies a fresh attestation (new random nonce every call) and caches it. @throws PlrError */
  async attest(): Promise<AttestationSession> {
    const nonce = new Uint8Array(randomBytes(32));
    // `@plr/shared`'s `verifyAttestation` (part of the measured exit image, not changed here) reports every registry
    // failure as E_REGISTRY_UNAVAILABLE. The registry is therefore watched for this one attestation: if it refused
    // for one of the client's own reasons (other code than pinned, RPC endpoints disagree), that refusal is what
    // the caller gets. `verifyAttestation` stops at the first failing check, so the remembered refusal is its cause.
    const watched = watchRefusals(this.#o.registry);
    try {
      // First of all: a registry whose account does not run the pinned code answers nothing we would trust.
      await checkRegistryCode(this.#o.registry);
      const bundle = await this.#o.fetchBundle(nonce);
      // SPEC-TDX §1.5 / TASKS T24: by default the collateral comes from the client's own PCCS fetch, made right
      // before the DCAP check. The exit's copy is untrusted for freshness.
      const src = this.collateral;
      const verified =
        src?.source === "pccs"
          ? await this.#verifyWithFreshCollateral(bundle, nonce, src.url, watched.registry)
          : await verifyAttestation({
              bundle,
              nonce,
              verifier: this.#o.verifier,
              registry: watched.registry,
              trustedRoot: this.#o.trustedRoot,
            });
      const session: AttestationSession = {
        verified,
        attNonce: nonce,
        at: this.#o.clock(),
        appCompose: bundle.app_compose,
        ...(src !== undefined ? { collateral: src } : {}),
      };
      this.#session = session;
      return session;
    } catch (e) {
      this.#session = undefined;
      if (isPlrError(e) && e.code === "E_REGISTRY_UNAVAILABLE" && watched.refusal !== undefined) throw watched.refusal;
      if (isPlrError(e)) throw e;
      throw new PlrError("E_BAD_RESPONSE");
    }
  }

  /**
   * INTEL verification on collateral this client fetched itself. `@plr/shared`'s `verifyAttestation` is part of the
   * measured exit image and has no hook for it, so the client runs it twice:
   *  1. with a verifier that stops where the DCAP check would start. Every check before it (response shape, quote
   *     structure, TEE type, pinned root) runs on the exit's bundle and fails with its own code; the real verifier
   *     is not called, so the exit's collateral is never used for a DCAP check.
   *  2. if that point was reached: fetch fresh collateral for the quote from the PCCS (any failure, or an answer
   *     that is not collateral, is `E_COLLATERAL_FETCH`: there is no fallback to the exit's copy), then the full
   *     verification of the same bundle with `collateral` replaced by the fresh copy.
   * The registry root is read once and reused by the second run.
   * @throws PlrError (incl. CollateralFetchError)
   */
  async #verifyWithFreshCollateral(bundle: AttestationBundle, nonce: Uint8Array, pccsUrl: string, inner: RegistryReader): Promise<VerifiedRouter> {
    const real = this.#o.verifier;
    let root: ReturnType<RegistryReader["getRoot"]> | undefined;
    const registry: RegistryReader = {
      get chain() {
        return inner.chain;
      },
      get contractId() {
        return inner.contractId;
      },
      getRoot: () => (root ??= inner.getRoot()),
      isComposeAllowed: (h) => inner.isComposeAllowed(h),
      isOsAllowed: (h) => inner.isOsAllowed(h),
      getInstance: (k) => inner.getInstance(k),
      getAnchor: (id) => inner.getAnchor(id),
    };
    let reached = false;
    const stop: QuoteVerifier = {
      rootKind: real.rootKind,
      get rootPublicKey() {
        return real.rootPublicKey;
      },
      verify: () => {
        reached = true;
        throw new PlrError("E_QUOTE_SIG");
      },
    };
    try {
      await verifyAttestation({ bundle, nonce, verifier: stop, registry, trustedRoot: this.#o.trustedRoot });
    } catch (e) {
      if (!reached) throw e;
    }
    if (!reached) throw new PlrError("E_BAD_RESPONSE");
    // The first run accepted the bundle's shape, so `quote` is non-empty hex.
    let fresh: unknown;
    try {
      fresh = await (this.#o.fetchCollateral ?? fetchPccsCollateral)(pccsUrl, fromHex(bundle.quote));
    } catch {
      throw new CollateralFetchError();
    }
    if (!isCollateralJson(fresh)) throw new CollateralFetchError("not collateral");
    return verifyAttestation({
      bundle: { ...bundle, collateral: fresh },
      nonce,
      verifier: real,
      registry,
      trustedRoot: this.#o.trustedRoot,
    });
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

/**
 * A view of `inner` that remembers the last client-only refusal one of its calls rejected with (see
 * `isRegistryRefusal`), and rejects with it unchanged.
 */
function watchRefusals(inner: RegistryReader): { registry: RegistryReader; refusal: unknown } {
  const w: { registry: RegistryReader; refusal: unknown } = { registry: inner, refusal: undefined };
  const watch = <T>(p: Promise<T>): Promise<T> =>
    p.catch((e: unknown) => {
      if (isRegistryRefusal(e)) w.refusal = e;
      throw e;
    });
  w.registry = {
    get chain() {
      return inner.chain;
    },
    get contractId() {
      return inner.contractId;
    },
    getRoot: () => watch(inner.getRoot()),
    isComposeAllowed: (h) => watch(inner.isComposeAllowed(h)),
    isOsAllowed: (h) => watch(inner.isOsAllowed(h)),
    getInstance: (k) => watch(inner.getInstance(k)),
    getAnchor: (id) => watch(inner.getAnchor(id)),
  };
  return w;
}

async function regCall<T>(f: () => Promise<unknown>, valid: (v: unknown) => v is T): Promise<T> {
  let v: unknown;
  try {
    v = await f();
  } catch (e) {
    if (isRegistryRefusal(e)) throw e;
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
 *         E_REGISTRY_CODE_HASH (a pinned registry whose account runs other code), E_REGISTRY_RPC_DISAGREE
 *         (several RPC endpoints configured and they answer a registry query differently)
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
