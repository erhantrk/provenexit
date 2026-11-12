/**
 * One attested VPN exit as seen by the client (SPEC-VPN §7): attestation fetch + cache, the per-connection
 * registry re-check, and opening a tunnel (upgrade + handshake v2 + CONNECT). Shared by {@link VpnClient}
 * (one hop, direct TCP) and `TwoHopClient` (entry hop direct, exit hop dialed through the entry, SPEC-VPN §10).
 *
 * Fail closed: every failure that says something about the exit (anything except a CONNECT_ERR answer or a
 * bad destination) drops the cached attestation, so the next connection re-attests.
 */
import {
  DcapQvlVerifier,
  MockVerifier,
  PlrError,
  TUNNEL_IDLE_TIMEOUT_MS,
  TUNNEL_STEP_TIMEOUT_MS,
  isIntelRoot,
  isPlrError,
  isValidP256Pub,
  toHex,
  type AttestationBundle,
  type InstanceRecord,
  type PlrErrorCode,
  type QuoteVerifier,
  type RegistryReader,
} from "@plr/shared";
import { AttestationCache, recheckRegistry, type AttestationSession } from "../attestation.js";
import { fail, parseJsonBytes } from "../http.js";
import { isPlainObject } from "../util.js";
import { TransportError, getBounded, openUpgrade, type Dialer, type ExitTarget, type Lookup } from "./transport.js";
import { TunnelStream, TwoHopTunnelStream, type TunnelStreamParams, type VpnStream } from "./stream.js";

export interface VpnClientTimeouts {
  /** Whole attestation / proof fetch (default 15 s). */
  attestMs: number;
  /** Tunnel upgrade + handshake + CONNECT until CONNECT_OK / CONNECT_ERR (default 30 s: covers the exit's DNS + 10 s dial). */
  connectMs: number;
  /** Wait for the RECEIPT after both FINs (default and max 10 s, SPEC-VPN §4.3). */
  receiptMs: number;
  /** Tunnel transport inactivity limit (default: the exit's 300 s idle limit + 5 s). */
  idleMs: number;
}

/** Default reuse window of a verified exit attestation (SPEC-VPN §7). */
export const VPN_ATTEST_TTL_MS = 60_000;
export const MAX_ATTEST_TTL_MS = 3_600_000;
const MAX_ATTESTATION_BODY = 256 * 1024;
const MAX_PROOF_BODY = 16 * 1024;
/** After a two-hop inner tunnel ended cleanly, the entry tunnel gets this long to deliver its own receipt. */
const ENTRY_LINGER_MS = 3 * TUNNEL_STEP_TIMEOUT_MS;

export const DEFAULT_TIMEOUTS: VpnClientTimeouts = {
  attestMs: 15_000,
  connectMs: 3 * TUNNEL_STEP_TIMEOUT_MS,
  receiptMs: TUNNEL_STEP_TIMEOUT_MS,
  idleMs: TUNNEL_IDLE_TIMEOUT_MS + 5_000,
};

/** CONNECT_ERR answers and input errors: the exit behaved correctly, the attestation stays valid. */
export const KEEP_SESSION: ReadonlySet<PlrErrorCode> = new Set<PlrErrorCode>(["E_BAD_INPUT", "E_DNS", "E_EGRESS_DENIED", "E_CONNECT_FAILED"]);

/** Validates an exit base URL: `http(s):`, no credentials / query / fragment. Returns it without trailing slash. */
export function normalizeExitUrl(u: unknown, what = "exitUrl"): URL {
  if (typeof u !== "string") return fail("E_BAD_INPUT", `${what} must be a string`);
  let url: URL;
  try {
    url = new URL(u);
  } catch {
    return fail("E_BAD_INPUT", `${what} must be a URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") fail("E_BAD_INPUT", `${what} must be http(s)`);
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    fail("E_BAD_INPUT", `${what} must not carry credentials, query or fragment`);
  }
  return new URL(url.origin + url.pathname.replace(/\/+$/, ""));
}

export function boundedMs(v: unknown, dflt: number, min: number, max: number): number {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) return fail("E_BAD_INPUT", "bad timeout");
  return v;
}

export function resolveTimeouts(t: unknown): VpnClientTimeouts {
  if (t !== undefined && !isPlainObject(t)) fail("E_BAD_INPUT", "bad timeouts");
  const o = (t ?? {}) as Partial<Record<keyof VpnClientTimeouts, unknown>>;
  return {
    attestMs: boundedMs(o.attestMs, DEFAULT_TIMEOUTS.attestMs, 1, MAX_ATTEST_TTL_MS),
    connectMs: boundedMs(o.connectMs, DEFAULT_TIMEOUTS.connectMs, 1, MAX_ATTEST_TTL_MS),
    receiptMs: boundedMs(o.receiptMs, DEFAULT_TIMEOUTS.receiptMs, 1, TUNNEL_STEP_TIMEOUT_MS),
    idleMs: boundedMs(o.idleMs, DEFAULT_TIMEOUTS.idleMs, 1, MAX_ATTEST_TTL_MS),
  };
}

export interface ExitHopOptions {
  base: URL;
  registry: RegistryReader;
  trustedRoot: Uint8Array;
  verifier: QuoteVerifier | undefined;
  attestTtlMs: unknown;
  lookup: Lookup | undefined;
  /** Dial through something else than direct TCP (the exit hop of a two-hop client). */
  createConnection?: Dialer;
  timeouts: VpnClientTimeouts;
  clock: () => number;
  /** `PLR_PCCS_URL`: fetch fresh Intel collateral from this PCCS instead of using the exit's copy (INTEL mode). */
  pccsUrl?: string;
}

/** A verified, registry-re-checked hop, ready for a tunnel. */
export interface CheckedHop {
  session: AttestationSession;
  instance: InstanceRecord;
}

/** @internal building block of VpnClient / TwoHopClient. */
export class ExitHop {
  readonly base: URL;
  readonly registry: RegistryReader;
  readonly verifier: QuoteVerifier;
  readonly timeouts: VpnClientTimeouts;
  readonly #target: ExitTarget;
  readonly #attestation: AttestationCache;

  constructor(o: ExitHopOptions) {
    this.base = o.base;
    const r: unknown = o.registry;
    if (typeof r !== "object" || r === null) fail("E_BAD_INPUT", "registry required");
    this.registry = o.registry;
    if (!isValidP256Pub(o.trustedRoot)) fail("E_ROOT_UNTRUSTED", "trustedRoot must be a valid 64-byte P-256 key");
    const trustedRoot = o.trustedRoot.slice();
    // Pinning the Intel SGX Root CA is what selects INTEL mode (SPEC-TDX §3.2); no separate env var.
    this.verifier = o.verifier ?? (isIntelRoot(trustedRoot) ? new DcapQvlVerifier(trustedRoot) : new MockVerifier(trustedRoot));
    if (o.lookup !== undefined && typeof o.lookup !== "function") fail("E_BAD_INPUT", "lookup must be a function");
    this.#target = { base: o.base, lookup: o.lookup, ...(o.createConnection !== undefined ? { createConnection: o.createConnection } : {}) };
    this.timeouts = o.timeouts;
    this.#attestation = new AttestationCache({
      fetchBundle: (nonce) => this.#fetchAttestation(nonce),
      verifier: this.verifier,
      registry: this.registry,
      trustedRoot,
      ttlMs: boundedMs(o.attestTtlMs, VPN_ATTEST_TTL_MS, 0, MAX_ATTEST_TTL_MS),
      clock: o.clock,
      ...(o.pccsUrl !== undefined ? { pccsUrl: o.pccsUrl } : {}),
    });
  }

  /** Fresh attestation (new nonce, SPEC §9 checks 1–10). @throws PlrError */
  attest(): Promise<AttestationSession> {
    return this.#attestation.attest();
  }

  invalidate(): void {
    this.#attestation.invalidate();
  }

  /** Drops the cached attestation unless `e` is a benign code; returns `e` as a PlrError. */
  failed(e: unknown): PlrError {
    const err = isPlrError(e) ? e : new PlrError("E_TUNNEL_PROTOCOL");
    if (!KEEP_SESSION.has(err.code)) this.invalidate();
    return err;
  }

  /** Re-checks the registry for `session` (SPEC-VPN §7 step 2) and returns the live instance record. @throws PlrError */
  async recheck(session: AttestationSession): Promise<InstanceRecord> {
    try {
      return await recheckRegistry(this.registry, session.verified);
    } catch (e) {
      throw this.failed(e);
    }
  }

  /** Cached (≤ ttl) or fresh attestation, then the registry re-check — on every connection. @throws PlrError */
  async checked(): Promise<CheckedHop> {
    let session: AttestationSession;
    try {
      session = await this.#attestation.current();
    } catch (e) {
      throw this.failed(e);
    }
    return { session, instance: await this.recheck(session) };
  }

  /**
   * Upgrades `/v1/tunnel`, runs handshake v2 and CONNECT with `connectPayload`, resolves after CONNECT_OK.
   * With `outer` (two-hop), the upgrade runs over that entry tunnel and the result is a {@link TwoHopTunnelStream}.
   * @throws PlrError — the CONNECT_ERR code, E_DECRYPT, E_TUNNEL_PROTOCOL, E_BAD_RESPONSE (unreachable), or a
   *         dialer's code
   */
  async openTunnel(session: AttestationSession, connectPayload: Uint8Array, outer?: VpnStream): Promise<TunnelStream> {
    try {
      const target: ExitTarget = outer === undefined ? this.#target : { base: this.base, lookup: undefined, createConnection: async () => outer };
      let up: { socket: import("node:stream").Duplex; head: Uint8Array };
      try {
        up = await openUpgrade(target, "/v1/tunnel", { timeoutMs: this.timeouts.connectMs });
      } catch (e) {
        if (isPlrError(e)) throw e;
        return fail(e instanceof TransportError && (e.kind === "status" || e.kind === "bad-upgrade") ? "E_TUNNEL_PROTOCOL" : "E_BAD_RESPONSE", "tunnel upgrade failed");
      }
      const params: TunnelStreamParams = {
        transport: up.socket,
        verified: session.verified,
        attNonce: session.attNonce,
        receiptTimeoutMs: this.timeouts.receiptMs,
        idleTimeoutMs: this.timeouts.idleMs,
        onFailure: () => this.invalidate(),
      };
      const stream =
        outer === undefined
          ? new TunnelStream(params)
          : new TwoHopTunnelStream({ ...params, outer, closeTransport: (t, clean) => closeEntryTunnel(t, outer, clean) });
      await stream.open(connectPayload, up.head, this.timeouts.connectMs);
      return stream;
    } catch (e) {
      throw this.failed(e);
    }
  }

  /** Keys of this hop's last successful verification (anchor-signer hint, SPEC-CHAINS §2), or undefined. */
  get verifiedKeys(): { x25519: Uint8Array; ed25519: Uint8Array } | undefined {
    return this.#attestation.verifiedKeys;
  }

  /** `GET /v1/receipts/proof?seq=` (bounded). @throws PlrError E_BAD_RESPONSE */
  async fetchProof(seq: number): Promise<{ status: number; body: Uint8Array }> {
    try {
      return await getBounded(this.#target, `/v1/receipts/proof?seq=${seq}`, { timeoutMs: this.timeouts.attestMs, maxBytes: MAX_PROOF_BODY });
    } catch (e) {
      if (isPlrError(e)) throw e;
      return fail("E_BAD_RESPONSE", "exit unreachable");
    }
  }

  async #fetchAttestation(nonce: Uint8Array): Promise<AttestationBundle> {
    return fetchAttestation(this.#target, nonce, this.timeouts.attestMs);
  }
}

/** `GET /v1/attestation?nonce=` over `t` (bounded). @throws PlrError E_BAD_RESPONSE, or a dialer's PlrError */
async function fetchAttestation(t: ExitTarget, nonce: Uint8Array, timeoutMs: number): Promise<AttestationBundle> {
  let res: { status: number; body: Uint8Array };
  try {
    res = await getBounded(t, `/v1/attestation?nonce=${toHex(nonce)}`, { timeoutMs, maxBytes: MAX_ATTESTATION_BODY });
  } catch (e) {
    if (isPlrError(e)) throw e; // e.g. the entry hop's verification failure (two-hop)
    return fail("E_BAD_RESPONSE", e instanceof TransportError && e.kind === "too-large" ? "attestation too large" : "exit unreachable");
  }
  if (res.status !== 200) fail("E_BAD_RESPONSE", "attestation HTTP status");
  const j = parseJsonBytes(res.body);
  if (!isPlainObject(j)) fail("E_BAD_RESPONSE", "attestation is not a JSON object");
  // Full shape validation happens in verifyAttestation (step 1, E_BAD_RESPONSE).
  return j as unknown as AttestationBundle;
}

/**
 * Fetches `/v1/attestation` over a direct connection, without any registry: the INTEL inspection path of
 * `plr vpn inspect`. The body is untrusted; callers validate it.
 * @throws PlrError E_BAD_RESPONSE
 */
export function fetchAttestationDirect(base: URL, nonce: Uint8Array, timeoutMs = DEFAULT_TIMEOUTS.attestMs): Promise<AttestationBundle> {
  return fetchAttestation({ base, lookup: undefined }, nonce, timeoutMs);
}

/**
 * Lets go of a two-hop inner tunnel's transport. Clean: end it (c2s FIN on the entry tunnel), keep draining
 * so the entry's s2c FIN and RECEIPT can arrive, and destroy after a bounded linger. Otherwise destroy both.
 */
function closeEntryTunnel(transport: import("node:stream").Duplex, outer: VpnStream, clean: boolean): void {
  if (!clean) {
    transport.destroy();
    outer.destroy();
    return;
  }
  if (!transport.destroyed && !transport.writableEnded) transport.end();
  transport.resume();
  if (transport !== outer) outer.resume();
  const t = setTimeout(() => {
    transport.destroy();
    outer.destroy();
  }, ENTRY_LINGER_MS);
  t.unref?.();
  outer.receipt().then(
    () => clearTimeout(t),
    () => clearTimeout(t),
  );
}
