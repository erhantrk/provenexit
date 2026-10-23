/**
 * PLR-VPN-v1 client (SPEC-VPN §7, §9.2): before any byte leaves for a destination, the exit's attestation is
 * verified (SPEC §9 checks 1–10) against the pinned root and the **VPN registry**, and on every new connection —
 * even with a cached attestation — the registry is re-checked (compose / OS allowed, instance registered with
 * matching keys), so a revocation applies to the very next connection. Only then is a tunnel opened, end-to-end
 * encrypted to the attested X25519 key.
 *
 * The client never resolves destinations (remote DNS, SPEC-VPN §1.4): the host travels in the encrypted CONNECT
 * frame. Its only own lookups (the exit URL host) go through `o.lookup` when given. Errors are `PlrError`s with
 * a code only — never a destination, address, port or payload.
 */
import {
  MockVerifier,
  PlrError,
  TUNNEL_IDLE_TIMEOUT_MS,
  TUNNEL_STEP_TIMEOUT_MS,
  encodeConnect,
  isPlrError,
  isValidP256Pub,
  isVpnReceipt,
  toHex,
  tunnelClientInit,
  validateDestination,
  type AttestationBundle,
  type PlrErrorCode,
  type QuoteVerifier,
  type RegistryReader,
  type VerifiedRouter,
  type VpnReceipt,
} from "@plr/shared";
import { AttestationCache, recheckRegistry, type AttestationSession } from "../attestation.js";
import { verifyVpnReceiptAnchored } from "../anchored.js";
import { fail, parseJsonBytes } from "../http.js";
import { isPlainObject } from "../util.js";
import { TransportError, getBounded, openUpgrade, type ExitTarget, type Lookup } from "./transport.js";
import { TunnelStream, type VpnStream } from "./stream.js";

export interface VpnClientTimeouts {
  /** Whole attestation / proof fetch (default 15 s). */
  attestMs: number;
  /** Tunnel upgrade + CONNECT until CONNECT_OK / CONNECT_ERR (default 30 s: covers the exit's DNS + 10 s dial). */
  connectMs: number;
  /** Wait for the RECEIPT after both FINs (default and max 10 s, SPEC-VPN §4.3). */
  receiptMs: number;
  /** Tunnel socket inactivity limit (default: the exit's 300 s idle limit + 5 s). */
  idleMs: number;
}

export interface VpnClientOptions {
  /** Exit base URL (`http:` / `https:`), e.g. `http://127.0.0.1:18200`. */
  exitUrl: string;
  /** The **VPN** registry (a separate deployment from the LLM router registry). */
  registry: RegistryReader;
  /** Pinned attestation root, 64-byte P-256 `x‖y`. */
  trustedRoot: Uint8Array;
  /** Quote verifier (default: {@link MockVerifier} pinned to `trustedRoot`). */
  verifier?: QuoteVerifier;
  /** Reuse a verified attestation for at most this long (default 60 000; 0 = fresh attestation per connection). */
  attestTtlMs?: number;
  /** DNS lookup used for the exit URL host (default `node:dns` lookup). Destinations are never resolved. */
  lookup?: Lookup;
  timeouts?: Partial<VpnClientTimeouts>;
  /** Monotonic clock in ms for the attestation cache (default `performance.now`). Tests only. */
  clock?: () => number;
}

/** Default reuse window of a verified exit attestation (SPEC-VPN §7). */
export const VPN_ATTEST_TTL_MS = 60_000;
const MAX_ATTEST_TTL_MS = 3_600_000;
const MAX_ATTESTATION_BODY = 256 * 1024;
const MAX_PROOF_BODY = 16 * 1024;
const DEFAULT_TIMEOUTS: VpnClientTimeouts = {
  attestMs: 15_000,
  connectMs: 3 * TUNNEL_STEP_TIMEOUT_MS,
  receiptMs: TUNNEL_STEP_TIMEOUT_MS,
  idleMs: TUNNEL_IDLE_TIMEOUT_MS + 5_000,
};

/** CONNECT_ERR answers and input errors: the exit behaved correctly, the attestation stays valid. */
const KEEP_SESSION: ReadonlySet<PlrErrorCode> = new Set<PlrErrorCode>(["E_BAD_INPUT", "E_DNS", "E_EGRESS_DENIED", "E_CONNECT_FAILED"]);

function normalizeExitUrl(u: unknown): URL {
  if (typeof u !== "string") return fail("E_BAD_INPUT", "exitUrl must be a string");
  let url: URL;
  try {
    url = new URL(u);
  } catch {
    return fail("E_BAD_INPUT", "exitUrl must be a URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") fail("E_BAD_INPUT", "exitUrl must be http(s)");
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    fail("E_BAD_INPUT", "exitUrl must not carry credentials, query or fragment");
  }
  return new URL(url.origin + url.pathname.replace(/\/+$/, ""));
}

function boundedMs(v: unknown, dflt: number, min: number, max: number): number {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) return fail("E_BAD_INPUT", "bad timeout");
  return v;
}

export class VpnClient {
  /** Normalised exit base URL (no trailing slash). */
  readonly exitUrl: string;
  readonly registry: RegistryReader;
  readonly #target: ExitTarget;
  readonly #verifier: QuoteVerifier;
  readonly #timeouts: VpnClientTimeouts;
  readonly #attestation: AttestationCache;

  constructor(o: VpnClientOptions) {
    if (!isPlainObject(o)) fail("E_BAD_INPUT", "options required");
    const base = normalizeExitUrl(o.exitUrl);
    this.exitUrl = base.href.replace(/\/+$/, "");
    const r: unknown = o.registry;
    if (typeof r !== "object" || r === null) fail("E_BAD_INPUT", "registry required");
    this.registry = o.registry;
    if (!isValidP256Pub(o.trustedRoot)) fail("E_ROOT_UNTRUSTED", "trustedRoot must be a valid 64-byte P-256 key");
    const trustedRoot = o.trustedRoot.slice();
    this.#verifier = o.verifier ?? new MockVerifier(trustedRoot);
    if (o.lookup !== undefined && typeof o.lookup !== "function") fail("E_BAD_INPUT", "lookup must be a function");
    this.#target = { base, lookup: o.lookup };
    const t = o.timeouts ?? {};
    this.#timeouts = {
      attestMs: boundedMs(t.attestMs, DEFAULT_TIMEOUTS.attestMs, 1, MAX_ATTEST_TTL_MS),
      connectMs: boundedMs(t.connectMs, DEFAULT_TIMEOUTS.connectMs, 1, MAX_ATTEST_TTL_MS),
      receiptMs: boundedMs(t.receiptMs, DEFAULT_TIMEOUTS.receiptMs, 1, TUNNEL_STEP_TIMEOUT_MS),
      idleMs: boundedMs(t.idleMs, DEFAULT_TIMEOUTS.idleMs, 1, MAX_ATTEST_TTL_MS),
    };
    this.#attestation = new AttestationCache({
      fetchBundle: (nonce) => this.#fetchAttestation(nonce),
      verifier: this.#verifier,
      registry: this.registry,
      trustedRoot,
      ttlMs: boundedMs(o.attestTtlMs, VPN_ATTEST_TTL_MS, 0, MAX_ATTEST_TTL_MS),
      clock: o.clock ?? (() => performance.now()),
    });
  }

  /** Root kind of the configured verifier ("MOCK" | "INTEL"). */
  get rootKind(): QuoteVerifier["rootKind"] {
    return this.#verifier.rootKind;
  }

  /** Fetches and verifies a fresh attestation (new random nonce, SPEC §9 against the VPN registry). @throws PlrError */
  async attest(): Promise<VerifiedRouter> {
    return (await this.#attestation.attest()).verified;
  }

  /** Like {@link attest}, also returning the verified `app-compose.json` (for reports such as `plr vpn verify`). */
  async attestSession(): Promise<AttestationSession> {
    return this.#attestation.attest();
  }

  /** Forgets the cached attestation; the next connection re-attests. */
  invalidate(): void {
    this.#attestation.invalidate();
  }

  /**
   * Opens a tunnel to `host:port` through the exit (SPEC-VPN §7): validates the destination, verifies the exit
   * (cached attestation ≤ `attestTtlMs`) and re-checks the registry, then hello + CONNECT and waits for
   * CONNECT_OK. On any failure before CONNECT_OK the destination is never contacted by this client.
   * @throws PlrError E_BAD_INPUT, any SPEC §9 code, the exit's CONNECT_ERR code (E_DNS / E_EGRESS_DENIED /
   *         E_CONNECT_FAILED / E_BAD_INPUT), E_DECRYPT, E_TUNNEL_PROTOCOL, E_BAD_RESPONSE (exit unreachable)
   */
  async connect(host: string, port: number): Promise<VpnStream> {
    let connectPayload: Uint8Array;
    try {
      validateDestination(host, port);
      connectPayload = encodeConnect(host, port);
    } catch {
      return fail("E_BAD_INPUT", "invalid destination");
    }
    try {
      const session = await this.#attestation.current();
      await recheckRegistry(this.registry, session.verified);
      return await this.#openTunnel(session, connectPayload);
    } catch (e) {
      const err = isPlrError(e) ? e : new PlrError("E_TUNNEL_PROTOCOL");
      if (!KEEP_SESSION.has(err.code)) this.#attestation.invalidate(); // fail closed: re-verify next time
      throw err;
    } finally {
      connectPayload.fill(0);
    }
  }

  /**
   * Checks that a verified session receipt is included in an on-chain anchor of the VPN registry: fetches the
   * exit's proof (`/v1/receipts/proof`) and verifies it against `get_anchor` with the CHAIN's
   * `first_seq` / `count` / `root`. Resolves `true`.
   * @throws PlrError E_NOT_ANCHORED (retry later), E_ANCHOR_MISMATCH, E_BAD_RESPONSE, E_REGISTRY_UNAVAILABLE, E_BAD_INPUT
   */
  async verifyAnchored(r: VpnReceipt): Promise<boolean> {
    if (!isVpnReceipt(r)) fail("E_BAD_INPUT", "malformed receipt");
    let res: { status: number; body: Uint8Array };
    try {
      res = await getBounded(this.#target, `/v1/receipts/proof?seq=${r.seq}`, { timeoutMs: this.#timeouts.attestMs, maxBytes: MAX_PROOF_BODY });
    } catch {
      return fail("E_BAD_RESPONSE", "exit unreachable");
    }
    if (res.status === 404) fail("E_NOT_ANCHORED");
    if (res.status !== 200) fail("E_BAD_RESPONSE", "proof HTTP status");
    await verifyVpnReceiptAnchored({ receipt: r, reply: parseJsonBytes(res.body), registry: this.registry });
    return true;
  }

  // ---------------------------------------------------------------- internals

  async #fetchAttestation(nonce: Uint8Array): Promise<AttestationBundle> {
    let res: { status: number; body: Uint8Array };
    try {
      res = await getBounded(this.#target, `/v1/attestation?nonce=${toHex(nonce)}`, {
        timeoutMs: this.#timeouts.attestMs,
        maxBytes: MAX_ATTESTATION_BODY,
      });
    } catch (e) {
      return fail("E_BAD_RESPONSE", e instanceof TransportError && e.kind === "too-large" ? "attestation too large" : "exit unreachable");
    }
    if (res.status !== 200) fail("E_BAD_RESPONSE", "attestation HTTP status");
    const j = parseJsonBytes(res.body);
    if (!isPlainObject(j)) fail("E_BAD_RESPONSE", "attestation is not a JSON object");
    // Full shape validation happens in verifyAttestation (step 1, E_BAD_RESPONSE).
    return j as unknown as AttestationBundle;
  }

  async #openTunnel(session: AttestationSession, connectPayload: Uint8Array): Promise<VpnStream> {
    const v = session.verified;
    const keys = tunnelClientInit({ xp: v.x25519, ep: v.ed25519, attNonce: session.attNonce });
    try {
      let up: Awaited<ReturnType<typeof openUpgrade>>;
      try {
        up = await openUpgrade(this.#target, "/v1/tunnel", { timeoutMs: this.#timeouts.connectMs });
      } catch (e) {
        return fail(e instanceof TransportError && (e.kind === "status" || e.kind === "bad-upgrade") ? "E_TUNNEL_PROTOCOL" : "E_BAD_RESPONSE", "tunnel upgrade failed");
      }
      const stream = new TunnelStream({
        socket: up.socket,
        verified: v,
        th: keys.th,
        kC2s: keys.kC2s,
        kS2c: keys.kS2c,
        receiptTimeoutMs: this.#timeouts.receiptMs,
        idleTimeoutMs: this.#timeouts.idleMs,
        onFailure: () => this.#attestation.invalidate(),
      });
      await stream.open(keys.hello, connectPayload, up.head, this.#timeouts.connectMs);
      return stream;
    } finally {
      keys.kC2s.fill(0);
      keys.kS2c.fill(0);
    }
  }
}
