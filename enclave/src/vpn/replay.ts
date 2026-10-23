/**
 * Exit-side anti-replay for tunnel hellos.
 *
 * SPEC-VPN §4.1 derives `th`, `k_c2s` and `k_s2c` from the exit's static key and the client's hello alone, and
 * frame nonces restart at seq 0 in every tunnel. A replayed hello would therefore re-create a victim tunnel's
 * exact keys and nonces: the replayed CONNECT/DATA would reach the destination again, and the replay's s2c
 * frames would be valid in the victim's live tunnel (spliced data, a forged clean EOF, nonce reuse). The wire
 * format is frozen, so the exit refuses to accept any hello twice:
 *
 *   - a hello's `att_nonce` must be a nonce this exit served an attestation for (`GET /v1/attestation`) within
 *     the last {@link NONCE_TTL_MS} (longer than any client `attestTtlMs`, max 1 h) — otherwise ⇒ close;
 *   - each `epk` is admitted at most once per live nonce — a repeat ⇒ close. Once a nonce expires, every hello
 *     naming it is refused, so for the lifetime of the boot keys no hello is ever accepted twice.
 *
 * Bounded: ≤ `maxNonces` live nonces (when full, the oldest nonce no tunnel has used yet is dropped; if every
 * live nonce is in use, new attestations are refused) and ≤ `maxHellos` remembered keys in total (when full,
 * new tunnels are refused until nonces expire). Fail closed in both cases.
 *
 * No retention: it holds only random values the client picked (attestation nonce, ephemeral public key), never a
 * destination, address, port or payload, and only in memory.
 */
import { performance } from "node:perf_hooks";
import { toHex } from "@plr/shared";

const is32 = (b: unknown): b is Uint8Array => b instanceof Uint8Array && b.length === 32;

/** How long an issued attestation nonce opens tunnels: 2 h (> the client's maximum attestTtlMs of 1 h). */
export const NONCE_TTL_MS = 2 * 60 * 60 * 1000;
export const MAX_LIVE_NONCES = 65_536;
export const MAX_REMEMBERED_HELLOS = 1 << 20;

export interface HelloGuardOptions {
  nonceTtlMs?: number;
  maxNonces?: number;
  maxHellos?: number;
  /** Monotonic milliseconds (default `performance.now`). */
  clock?: () => number;
}

interface NonceEntry {
  expiresAt: number;
  /** Ephemeral keys already admitted under this nonce (hex), null until the first tunnel. */
  epks: Set<string> | null;
}

export class HelloGuard {
  readonly #ttl: number;
  readonly #maxNonces: number;
  readonly #maxHellos: number;
  readonly #clock: () => number;
  /** Insertion order = expiry order (constant TTL, monotonic clock; a re-issue moves the entry to the end). */
  readonly #nonces = new Map<string, NonceEntry>();
  /** Live nonces no tunnel has used yet, same order (evictable when the table is full). */
  readonly #unused = new Set<string>();
  #hellos = 0;

  constructor(o: HelloGuardOptions = {}) {
    this.#ttl = posInt(o.nonceTtlMs, NONCE_TTL_MS);
    this.#maxNonces = posInt(o.maxNonces, MAX_LIVE_NONCES);
    this.#maxHellos = posInt(o.maxHellos, MAX_REMEMBERED_HELLOS);
    this.#clock = o.clock ?? (() => performance.now());
  }

  /** Live nonces / remembered hellos (tests, bounds). */
  get size(): { nonces: number; hellos: number } {
    return { nonces: this.#nonces.size, hellos: this.#hellos };
  }

  /**
   * Records a nonce the exit is about to serve an attestation for (a repeat refreshes its lifetime and keeps
   * its admitted keys). Returns false if the table is full of nonces already in use (caller answers 503).
   */
  issue(nonce: Uint8Array): boolean {
    if (!is32(nonce)) return false;
    const now = this.#clock();
    this.#purge(now);
    const k = toHex(nonce);
    const prev = this.#nonces.get(k);
    if (prev) {
      this.#nonces.delete(k);
      this.#nonces.set(k, { expiresAt: now + this.#ttl, epks: prev.epks });
      if (this.#unused.delete(k)) this.#unused.add(k);
      return true;
    }
    if (this.#nonces.size >= this.#maxNonces) {
      const oldestUnused = this.#unused.values().next();
      if (oldestUnused.done) return false;
      this.#unused.delete(oldestUnused.value);
      this.#nonces.delete(oldestUnused.value);
    }
    this.#nonces.set(k, { expiresAt: now + this.#ttl, epks: null });
    this.#unused.add(k);
    return true;
  }

  /**
   * Admits a tunnel hello: true iff `attNonce` is live and `epk` was never admitted under it (then remembered).
   * False ⇒ the caller closes the tunnel.
   */
  admit(attNonce: Uint8Array, epk: Uint8Array): boolean {
    if (!is32(attNonce) || !is32(epk)) return false;
    this.#purge(this.#clock());
    const k = toHex(attNonce);
    const e = this.#nonces.get(k);
    if (!e) return false;
    const ek = toHex(epk);
    if (e.epks?.has(ek)) return false;
    if (this.#hellos >= this.#maxHellos) return false;
    (e.epks ??= new Set()).add(ek);
    this.#hellos++;
    this.#unused.delete(k);
    return true;
  }

  #purge(now: number): void {
    for (const [k, e] of this.#nonces) {
      if (e.expiresAt > now) break;
      this.#nonces.delete(k);
      this.#unused.delete(k);
      this.#hellos -= e.epks?.size ?? 0;
    }
  }
}

function posInt(v: number | undefined, d: number): number {
  if (v === undefined) return d;
  if (!Number.isSafeInteger(v) || v < 1) throw new RangeError("HelloGuard: bad option");
  return v;
}
