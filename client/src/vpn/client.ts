/**
 * PLR-VPN client (SPEC-VPN §7, §9.2): before any byte leaves for a destination, the exit's attestation is
 * verified (SPEC §9 checks 1–10) against the pinned root and the **VPN registry**, and on every new connection —
 * even with a cached attestation — the registry is re-checked (compose / OS allowed, instance registered with
 * matching keys), so a revocation applies to the very next connection. Only then is a tunnel opened (handshake
 * v2, §4.1), end-to-end encrypted to the attested X25519 key and to a fresh exit ephemeral key.
 *
 * The client never resolves destinations (remote DNS, SPEC-VPN §1.4): the host travels in the encrypted CONNECT
 * frame. Its only own lookups (the exit URL host) go through `o.lookup` when given. Errors are `PlrError`s with
 * a code only — never a destination, address, port or payload.
 */
import {
  encodeConnect,
  isVpnReceipt,
  validateDestination,
  type QuoteVerifier,
  type RegistryReader,
  type VerifiedRouter,
  type VpnReceipt,
} from "@plr/shared";
import type { AttestationSession } from "../attestation.js";
import { verifyVpnReceiptAnchored } from "../anchored.js";
import { fail, parseJsonBytes } from "../http.js";
import { isPlainObject } from "../util.js";
import type { Lookup } from "./transport.js";
import type { VpnStream } from "./stream.js";
import { ExitHop, normalizeExitUrl, resolveTimeouts, VPN_ATTEST_TTL_MS, type VpnClientTimeouts } from "./hop.js";

export { VPN_ATTEST_TTL_MS, type VpnClientTimeouts };

export interface VpnClientOptions {
  /** Exit base URL (`http:` / `https:`), e.g. `http://127.0.0.1:18200`. */
  exitUrl: string;
  /** The **VPN** registry (a separate deployment from the LLM router registry). */
  registry: RegistryReader;
  /** Pinned attestation root, 64-byte P-256 `x‖y`. */
  trustedRoot: Uint8Array;
  /** Quote verifier (default: MockVerifier pinned to `trustedRoot`). */
  verifier?: QuoteVerifier;
  /** Reuse a verified attestation for at most this long (default 60 000; 0 = fresh attestation per connection). */
  attestTtlMs?: number;
  /** DNS lookup used for the exit URL host (default `node:dns` lookup). Destinations are never resolved. */
  lookup?: Lookup;
  timeouts?: Partial<VpnClientTimeouts>;
  /** Monotonic clock in ms for the attestation cache (default `performance.now`). Tests only. */
  clock?: () => number;
}

/**
 * Validates a destination and encodes the CONNECT payload (caller zeroes it after use).
 * @throws PlrError E_BAD_INPUT
 */
export function connectPayloadFor(host: unknown, port: unknown): Uint8Array {
  try {
    validateDestination(host as string, port as number);
    return encodeConnect(host as string, port as number);
  } catch {
    return fail("E_BAD_INPUT", "invalid destination");
  }
}

export class VpnClient {
  /** Normalised exit base URL (no trailing slash). */
  readonly exitUrl: string;
  readonly registry: RegistryReader;
  readonly #hop: ExitHop;

  constructor(o: VpnClientOptions) {
    if (!isPlainObject(o)) fail("E_BAD_INPUT", "options required");
    const base = normalizeExitUrl(o.exitUrl);
    this.exitUrl = base.href.replace(/\/+$/, "");
    this.#hop = new ExitHop({
      base,
      registry: o.registry,
      trustedRoot: o.trustedRoot,
      verifier: o.verifier,
      attestTtlMs: o.attestTtlMs,
      lookup: o.lookup,
      timeouts: resolveTimeouts(o.timeouts),
      clock: o.clock ?? (() => performance.now()),
    });
    this.registry = this.#hop.registry;
  }

  /** Root kind of the configured verifier ("MOCK" | "INTEL"). */
  get rootKind(): QuoteVerifier["rootKind"] {
    return this.#hop.verifier.rootKind;
  }

  /** Fetches and verifies a fresh attestation (new random nonce, SPEC §9 against the VPN registry). @throws PlrError */
  async attest(): Promise<VerifiedRouter> {
    return (await this.#hop.attest()).verified;
  }

  /** Like {@link attest}, also returning the verified `app-compose.json` (for reports such as `plr vpn verify`). */
  async attestSession(): Promise<AttestationSession> {
    return this.#hop.attest();
  }

  /** Forgets the cached attestation; the next connection re-attests. */
  invalidate(): void {
    this.#hop.invalidate();
  }

  /**
   * Opens a tunnel to `host:port` through the exit (SPEC-VPN §7): validates the destination, verifies the exit
   * (cached attestation ≤ `attestTtlMs`) and re-checks the registry, then handshake v2 + CONNECT and waits for
   * CONNECT_OK. On any failure before CONNECT_OK the destination is never contacted by this client.
   * @throws PlrError E_BAD_INPUT, any SPEC §9 code, the exit's CONNECT_ERR code (E_DNS / E_EGRESS_DENIED /
   *         E_CONNECT_FAILED / E_BAD_INPUT), E_DECRYPT, E_TUNNEL_PROTOCOL, E_BAD_RESPONSE (exit unreachable)
   */
  async connect(host: string, port: number): Promise<VpnStream> {
    const connectPayload = connectPayloadFor(host, port);
    try {
      const { session } = await this.#hop.checked();
      return await this.#hop.openTunnel(session, connectPayload);
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
    const res = await this.#hop.fetchProof(r.seq);
    if (res.status === 404) fail("E_NOT_ANCHORED");
    if (res.status !== 200) fail("E_BAD_RESPONSE", "proof HTTP status");
    await verifyVpnReceiptAnchored({ receipt: r, reply: parseJsonBytes(res.body), registry: this.registry });
    return true;
  }
}
