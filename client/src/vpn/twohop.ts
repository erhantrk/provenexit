/**
 * Two-hop VPN client (SPEC-VPN §10): the client tunnels to an **entry** exit and, through that tunnel, opens a
 * second, nested tunnel to an **exit** exit, which reaches the destination. The entry sees the client's IP and the
 * exit's address — never the destination, DNS names or payload (the inner tunnel is end-to-end encrypted to the
 * exit); the exit sees the entry's IP, never the client's.
 *
 * 1. The entry is attested directly (SPEC-VPN §7); its instance must carry a non-null `org_id`
 *    (E_OPERATOR_UNAPPROVED).
 * 2. The exit's attestation is fetched THROUGH an entry tunnel (CONNECT to the exit's host:port from `exitUrl`,
 *    fresh nonce, HTTP/1.1) and verified (§7); its `org_id` must be non-null (E_OPERATOR_UNAPPROVED) and differ
 *    from the entry's (E_SAME_OPERATOR). The exit is never contacted directly and its host is never resolved by
 *    the client.
 * 3. Every `connect()` re-checks both hops' registry state incl. the org rules (so a revocation or org change
 *    applies to the very next connection, even with cached attestations), opens a new entry tunnel to the exit,
 *    upgrades `/v1/tunnel` over it, runs handshake v2 with the exit and CONNECTs inside the inner tunnel.
 * 4. The stream's `receipt()` is the exit's receipt, `entryReceipt()` the entry tunnel's; both are verified.
 */
import { PlrError, isPlrError, isVpnReceipt, validateDestination, type InstanceRecord, type QuoteVerifier, type RegistryReader, type VerifiedRouter, type VpnReceipt } from "@plr/shared";
import type { AttestationSession } from "../attestation.js";
import { verifyVpnReceiptAnchored } from "../anchored.js";
import { fail, parseJsonBytes } from "../http.js";
import { isPlainObject } from "../util.js";
import { urlHost, urlPort, type Lookup } from "./transport.js";
import type { TwoHopStream, VpnStream } from "./stream.js";
import { ExitHop, normalizeExitUrl, resolveTimeouts, type VpnClientTimeouts } from "./hop.js";
import { connectPayloadFor } from "./client.js";

export interface TwoHopClientOptions {
  /** Entry exit base URL (contacted directly). */
  entryUrl: string;
  /** Exit base URL — reached only through the entry; its host is resolved by the entry (DoH), never locally. */
  exitUrl: string;
  /** The VPN registry (both hops must be instances on it). */
  registry: RegistryReader;
  /** Pinned attestation root, 64-byte P-256 `x‖y`. */
  trustedRoot: Uint8Array;
  verifier?: QuoteVerifier;
  /** Reuse window of each hop's verified attestation (default 60 000; 0 = fresh per connection). */
  attestTtlMs?: number;
  /** DNS lookup for the entry URL host (the only lookup the client performs). */
  lookup?: Lookup;
  timeouts?: Partial<VpnClientTimeouts>;
  /** Monotonic clock in ms for the attestation caches. Tests only. */
  clock?: () => number;
  /** `PLR_PCCS_URL`: fetch fresh Intel collateral from this PCCS instead of using each hop's copy (INTEL mode). */
  pccsUrl?: string;
}

export interface TwoHopAttestation {
  entry: VerifiedRouter;
  exit: VerifiedRouter;
  entryOrg: string;
  exitOrg: string;
}

const noop = (): void => undefined;

/** SPEC-VPN §10 step 1: the entry's operator must be approved. @throws PlrError E_OPERATOR_UNAPPROVED */
export function entryOrgOf(inst: InstanceRecord): string {
  if (typeof inst.org_id !== "string") throw new PlrError("E_OPERATOR_UNAPPROVED", "entry operator not approved");
  return inst.org_id;
}

/** SPEC-VPN §10 step 2: approved exit operator of another organization. @throws PlrError E_OPERATOR_UNAPPROVED / E_SAME_OPERATOR */
export function exitOrgOf(inst: InstanceRecord, entryOrg: string): string {
  if (typeof inst.org_id !== "string") throw new PlrError("E_OPERATOR_UNAPPROVED", "exit operator not approved");
  if (inst.org_id === entryOrg) throw new PlrError("E_SAME_OPERATOR");
  return inst.org_id;
}

export class TwoHopClient {
  readonly entryUrl: string;
  readonly exitUrl: string;
  readonly registry: RegistryReader;
  readonly #entry: ExitHop;
  readonly #exit: ExitHop;
  readonly #exitHost: string;
  readonly #exitPort: number;

  constructor(o: TwoHopClientOptions) {
    if (!isPlainObject(o)) fail("E_BAD_INPUT", "options required");
    const entryBase = normalizeExitUrl(o.entryUrl, "entryUrl");
    const exitBase = normalizeExitUrl(o.exitUrl, "exitUrl");
    this.entryUrl = entryBase.href.replace(/\/+$/, "");
    this.exitUrl = exitBase.href.replace(/\/+$/, "");
    this.#exitHost = urlHost(exitBase);
    this.#exitPort = urlPort(exitBase);
    try {
      validateDestination(this.#exitHost, this.#exitPort);
    } catch {
      fail("E_BAD_INPUT", "exitUrl host is not a valid tunnel destination");
    }
    const timeouts = resolveTimeouts(o.timeouts);
    const clock = o.clock ?? (() => performance.now());
    this.#entry = new ExitHop({
      base: entryBase,
      registry: o.registry,
      trustedRoot: o.trustedRoot,
      verifier: o.verifier,
      attestTtlMs: o.attestTtlMs,
      lookup: o.lookup,
      timeouts,
      clock,
      ...(o.pccsUrl !== undefined ? { pccsUrl: o.pccsUrl } : {}),
    });
    this.registry = this.#entry.registry;
    this.#exit = new ExitHop({
      base: exitBase,
      registry: o.registry,
      trustedRoot: o.trustedRoot,
      verifier: this.#entry.verifier,
      attestTtlMs: o.attestTtlMs,
      lookup: undefined,
      createConnection: () => this.#dialExit(),
      // An exit attestation fetch includes dialing through the entry (entry attestation + tunnel open).
      timeouts: { ...timeouts, attestMs: Math.min(2 * timeouts.attestMs + timeouts.connectMs, 3_600_000) },
      clock,
      ...(o.pccsUrl !== undefined ? { pccsUrl: o.pccsUrl } : {}),
    });
  }

  /** Root kind of the configured verifier ("MOCK" | "INTEL"). */
  get rootKind(): QuoteVerifier["rootKind"] {
    return this.#entry.verifier.rootKind;
  }

  /** Fresh attestation of both hops plus the org rules (SPEC-VPN §10 steps 1–2). @throws PlrError */
  async attest(): Promise<TwoHopAttestation> {
    const entry = await this.attestEntrySession();
    const entryOrg = await this.checkEntry(entry);
    const exit = await this.attestExitSession();
    const exitOrg = await this.checkExit(exit, entryOrg);
    return { entry: entry.verified, exit: exit.verified, entryOrg, exitOrg };
  }

  /** Fresh attestation of the entry (SPEC §9 checks, direct). @throws PlrError */
  attestEntrySession(): Promise<AttestationSession> {
    return this.#entry.attest();
  }

  /** Entry registry re-check + approved operator; returns the entry's org. @throws PlrError */
  async checkEntry(session: AttestationSession): Promise<string> {
    return entryOrgOf(await this.#entry.recheck(session));
  }

  /** Fresh attestation of the exit, fetched through an (attested, re-checked) entry tunnel. @throws PlrError */
  attestExitSession(): Promise<AttestationSession> {
    return this.#exit.attest();
  }

  /** Exit registry re-check + org rules against `entryOrg`; returns the exit's org. @throws PlrError */
  async checkExit(session: AttestationSession, entryOrg: string): Promise<string> {
    return exitOrgOf(await this.#exit.recheck(session), entryOrg);
  }

  /**
   * Opens a two-hop connection to `host:port` (SPEC-VPN §10 step 3). Nothing reaches the destination unless both
   * hops verified and passed the org rules on this very call.
   * @throws PlrError E_BAD_INPUT, any SPEC §9 code of either hop, E_OPERATOR_UNAPPROVED, E_SAME_OPERATOR, a
   *         CONNECT_ERR code (of the entry reaching the exit, or of the exit reaching the destination),
   *         E_DECRYPT, E_TUNNEL_PROTOCOL, E_BAD_RESPONSE
   */
  async connect(host: string, port: number): Promise<TwoHopStream> {
    const payload = connectPayloadFor(host, port);
    let outer: VpnStream | undefined;
    try {
      const entry = await this.#entryChecked();
      const exit = await this.#exit.checked(); // a stale exit attestation is refreshed through the entry
      exitOrgOf(exit.instance, entry.org);
      outer = await this.#openEntryTunnel(entry.session);
      return (await this.#exit.openTunnel(exit.session, payload, outer)) as unknown as TwoHopStream;
    } catch (e) {
      outer?.destroy();
      throw isPlrError(e) ? e : new PlrError("E_TUNNEL_PROTOCOL");
    } finally {
      payload.fill(0);
    }
  }

  /**
   * As `VpnClient.verifyAnchored`, for a receipt of the exit (proof fetched through the entry) or of the entry.
   * @throws PlrError E_NOT_ANCHORED, E_ANCHOR_MISMATCH, E_ANCHOR_SIG (tier B/C), E_BAD_RESPONSE, E_REGISTRY_UNAVAILABLE, E_BAD_INPUT
   */
  async verifyAnchored(r: VpnReceipt, hop: "exit" | "entry" = "exit"): Promise<boolean> {
    if (!isVpnReceipt(r)) fail("E_BAD_INPUT", "malformed receipt");
    if (hop !== "exit" && hop !== "entry") fail("E_BAD_INPUT", "bad hop");
    const h = hop === "exit" ? this.#exit : this.#entry;
    const res = await h.fetchProof(r.seq);
    if (res.status === 404) fail("E_NOT_ANCHORED");
    if (res.status !== 200) fail("E_BAD_RESPONSE", "proof HTTP status");
    await verifyVpnReceiptAnchored({ receipt: r, reply: parseJsonBytes(res.body), registry: this.registry, signer: h.verifiedKeys });
    return true;
  }

  // ---------------------------------------------------------------- internals

  /** Entry: cached / fresh attestation, registry re-check, approved operator. */
  async #entryChecked(): Promise<{ session: AttestationSession; org: string }> {
    const c = await this.#entry.checked();
    return { session: c.session, org: entryOrgOf(c.instance) };
  }

  /** A fresh entry tunnel whose destination is the exit's host:port. */
  async #openEntryTunnel(session: AttestationSession): Promise<VpnStream> {
    const p = connectPayloadFor(this.#exitHost, this.#exitPort);
    try {
      const s = await this.#entry.openTunnel(session, p);
      // Failures surface through whoever uses the stream (HTTP request / inner tunnel); never unhandled.
      s.on("error", noop);
      s.receipt().catch(noop);
      return s;
    } finally {
      p.fill(0);
    }
  }

  /** Dialer of the exit hop: every exit HTTP request runs over a new, fully checked entry tunnel. */
  async #dialExit(): Promise<VpnStream> {
    const entry = await this.#entryChecked();
    return this.#openEntryTunnel(entry.session);
  }
}
