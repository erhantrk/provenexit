/**
 * Attestation session shared by {@link PrivateClient} (LLM router, SPEC §9/§12) and `VpnClient` (VPN exit,
 * SPEC-VPN §7): fresh 32-byte random nonce per attestation, `verifyAttestation` against the pinned root and the
 * registry, a time-bounded cache of the last verification, and single-flight sharing of one in-flight
 * attestation between concurrent callers. Fails closed: any failure clears the cache and throws `PlrError`.
 */
import { randomBytes } from "node:crypto";
import {
  PlrError,
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
}

export class AttestationCache {
  readonly #o: AttestationCacheOptions;
  #session: AttestationSession | undefined;
  #pending: Promise<AttestationSession> | undefined;
  /** Keys of the last successful verification (kept across expiry/invalidation; used only as an anchor-signer hint). */
  #keys: { x25519: Uint8Array; ed25519: Uint8Array } | undefined;

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
      const bundle = await this.#o.fetchBundle(nonce);
      const verified = await verifyAttestation({
        bundle,
        nonce,
        verifier: this.#o.verifier,
        registry: this.#o.registry,
        trustedRoot: this.#o.trustedRoot,
      });
      const session: AttestationSession = { verified, attNonce: nonce, at: this.#o.clock(), appCompose: bundle.app_compose };
      this.#session = session;
      this.#keys = { x25519: verified.x25519.slice(), ed25519: verified.ed25519.slice() };
      return session;
    } catch (e) {
      this.#session = undefined;
      if (isPlrError(e)) throw e;
      throw new PlrError("E_BAD_RESPONSE");
    }
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

  /**
   * The x25519/ed25519 keys of the last successful verification, or undefined. Attested keys stay authentic after the
   * session expires, so they may check signatures of that instance (SPEC-CHAINS §2 anchors) when the key hash matches.
   */
  get verifiedKeys(): { x25519: Uint8Array; ed25519: Uint8Array } | undefined {
    const k = this.#keys;
    return k === undefined ? undefined : { x25519: k.x25519.slice(), ed25519: k.ed25519.slice() };
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
  } catch {
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
 * @throws PlrError E_COMPOSE_NOT_ALLOWED, E_OS_NOT_ALLOWED, E_INSTANCE_NOT_REGISTERED, E_REGISTRY_UNAVAILABLE
 */
export async function recheckRegistry(registry: RegistryReader, v: VerifiedRouter, now: number = Date.now()): Promise<InstanceRecord> {
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
