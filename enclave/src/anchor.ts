/**
 * Registration (SPEC §5, §7) and receipt anchoring (SPEC §8), shared by the LLM router and the VPN exit
 * (SPEC-VPN §5: same `register_instance` / `anchor_receipts` on the VPN registry; only the receipt kind differs,
 * and the Anchorer only ever sees leaf hashes).
 *
 * - At boot the instance obtains a registration quote over `key_hash ‖ registration_nonce(contract_id, operator_id)`
 *   (SPEC §5 rev 1.3: bound to the registry and to this anchorer's own operator account, which the contract checks
 *   against `current_account_id` / `predecessor_account_id`) and calls `register_instance`. On failure it keeps
 *   serving (clients refuse an unregistered instance), logs only the error code and retries with exponential backoff.
 *   Successful registrations are refreshed periodically. The registration quote of the latest successful registration
 *   is kept ({@link Anchorer.registrationQuote}) and served in `/v1/attestation` (SPEC-CHAINS §4); writers that set
 *   `reuseRegistrationQuote` (tier C, which commits only its hash) refresh with that same quote.
 * - Every `intervalMs`, when receipts are pending, the next contiguous batch (≤ 10 000) is committed as an
 *   RFC 6962 root via `anchor_receipts`, signed with the instance Ed25519 key, with a storage deposit attached
 *   by the chain writer (PLR_ANCHOR_DEPOSIT; the contract refunds the excess and never pays storage from its own
 *   balance). On `E_DEPOSIT` the instance re-registers, which tops up its prepaid anchor credit. A failed batch stays pending
 *   and is retried. On `E_SEQ` the local state is resynchronised from the chain (verifying roots); if the
 *   chain disagrees with the local log, anchoring halts (fail closed: no proofs are served for it).
 * - With `onOperatorMismatch` set (the VPN exit, whose on-chain operator decides its `org_id`, SPEC §7 rev 1.2 /
 *   SPEC-VPN §10), every successful registration is read back: if the instance's recorded `operator` is not this
 *   anchorer's own account, the instance is permanently mis-attributed. Since rev 1.3 the operator-bound registration
 *   quote already prevents that on-chain; the read-back stays as defense in depth (e.g. a faulty registry).
 *   The anchorer then stops for good (no retries: the record's operator never changes), logs
 *   `registration_failed code=E_OPERATOR_MISMATCH` and calls `onOperatorMismatch` so the service stops serving.
 */
import { PlrError, anchorMessage, equalBytes, fromHex, toHex, type Attester, type TdxEvent } from "@plr/shared";
import type { EnclaveKeys } from "./keys.js";
import { Logger, code as codeField, codeOf, hex as hexField, type Code } from "./log.js";
import type { AnchorView, RegistryWriter } from "./registry-writer.js";
import type { LeafLog } from "./receipts.js";

export interface AnchorerOptions {
  chain: RegistryWriter;
  attester: Attester;
  /** The instance keys (router or VPN exit). */
  keys: EnclaveKeys;
  /** The instance receipt log (any receipt kind: only leaf hashes are anchored). */
  receipts: LeafLog;
  composeBytes: Uint8Array;
  log?: Logger;
  /** Anchor period (SPEC: PLR_ANCHOR_INTERVAL_MS, default 3000). */
  intervalMs?: number;
  /** Registration retry backoff bounds. */
  retryMinMs?: number;
  retryMaxMs?: number;
  /** Re-register (refresh expiry) this often after a success. Default 6 h. */
  refreshMs?: number;
  /** How many anchors to scan back when looking up our own anchor ids. */
  scanLimit?: number;
  /** Enables the operator read-back after each registration; called once if the on-chain operator is not ours. */
  onOperatorMismatch?: () => void;
}

export type RegistrationState = "pending" | "registered" | "failed";

export class Anchorer {
  readonly #o: Required<Omit<AnchorerOptions, "log" | "onOperatorMismatch">> & { log: Logger; onOperatorMismatch: (() => void) | null };
  readonly #keyHashHex: string;
  #state: RegistrationState = "pending";
  #lastError: Code | null = null;
  #halted = false;
  #stopped = false;
  #busy: Promise<void> = Promise.resolve();
  #anchorTimer: NodeJS.Timeout | null = null;
  #regTimer: NodeJS.Timeout | null = null;
  #retryMs: number;
  #regQuote: { quote: Uint8Array; eventLog: TdxEvent[] } | null = null;

  constructor(o: AnchorerOptions) {
    this.#o = {
      intervalMs: 3000,
      retryMinMs: 5000,
      retryMaxMs: 300_000,
      refreshMs: 6 * 3600_000,
      scanLimit: 1000,
      ...o,
      log: o.log ?? new Logger("plr-router"),
      onOperatorMismatch: o.onOperatorMismatch ?? null,
    };
    this.#retryMs = this.#o.retryMinMs;
    this.#keyHashHex = toHex(o.keys.keyHash);
  }

  get state(): RegistrationState {
    return this.#state;
  }
  get lastError(): Code | null {
    return this.#lastError;
  }
  get halted(): boolean {
    return this.#halted;
  }
  /** The quote of the latest successful registration (a copy), or null before the first one. */
  get registrationQuote(): Uint8Array | null {
    return this.#regQuote === null ? null : this.#regQuote.quote.slice();
  }

  /** Starts registration (with retries) and the periodic anchor loop. */
  start(): void {
    this.#stopped = false;
    this.#scheduleRegistration(0);
    this.#scheduleAnchor();
  }

  stop(): void {
    this.#stopped = true;
    if (this.#anchorTimer) clearTimeout(this.#anchorTimer);
    if (this.#regTimer) clearTimeout(this.#regTimer);
    this.#anchorTimer = this.#regTimer = null;
  }

  /** Serialises chain operations (one transaction in flight per instance). */
  #exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#busy.then(fn, fn);
    this.#busy = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  #scheduleRegistration(delayMs: number): void {
    if (this.#stopped) return;
    if (this.#regTimer) clearTimeout(this.#regTimer);
    this.#regTimer = setTimeout(() => {
      this.#regTimer = null;
      void this.register().then((ok) => {
        if (ok) {
          this.#retryMs = this.#o.retryMinMs;
          this.#scheduleRegistration(this.#o.refreshMs);
        } else {
          const d = this.#retryMs;
          this.#retryMs = Math.min(this.#retryMs * 2, this.#o.retryMaxMs);
          this.#scheduleRegistration(d);
        }
      });
    }, delayMs);
  }

  #scheduleAnchor(): void {
    if (this.#stopped) return;
    this.#anchorTimer = setTimeout(() => {
      this.#anchorTimer = null;
      void this.anchorOnce().finally(() => this.#scheduleAnchor());
    }, this.#o.intervalMs);
  }

  /** One registration attempt. Never throws; logs only the outcome code. */
  register(): Promise<boolean> {
    return this.#exclusive(async () => {
      if (this.#lastError === "E_OPERATOR_MISMATCH") return false; // permanent
      try {
        await this.#o.chain.prepare?.();
        const rd = this.#o.keys.registrationReportData(this.#o.chain.contractId, this.#o.chain.operatorId);
        const { quote, eventLog } =
          this.#o.chain.reuseRegistrationQuote === true && this.#regQuote !== null ? this.#regQuote : await this.#o.attester.getQuote(rd);
        await this.#o.chain.registerInstance({
          quote: toHex(quote),
          event_log: eventLog,
          app_compose: new TextDecoder("utf-8", { fatal: true }).decode(this.#o.composeBytes),
          x25519: toHex(this.#o.keys.x25519),
          ed25519: toHex(this.#o.keys.ed25519),
        });
        if (this.#o.onOperatorMismatch) {
          // Read back who the chain thinks operates this key (a lookup failure throws: retried like any failure).
          const op = await this.#o.chain.getInstanceOperator(this.#keyHashHex);
          if (op === null) throw new PlrError("E_INSTANCE_NOT_REGISTERED", "registration not visible");
          if (op !== this.#o.chain.operatorId) {
            this.#operatorMismatch();
            return false;
          }
        }
        const first = this.#state !== "registered";
        this.#regQuote = { quote: quote.slice(), eventLog };
        this.#state = "registered";
        this.#lastError = null;
        if (first) this.#o.log.info("registered", { key_hash: hexField(this.#keyHashHex) });
        else this.#o.log.info("registration_refreshed", {});
        await this.#resync();
        return true;
      } catch (e) {
        const c = codeOf(e, "E_REGISTRY_UNAVAILABLE");
        if (this.#state !== "registered") this.#state = "failed";
        this.#lastError = c;
        this.#o.log.info("registration_failed", { code: c });
        return false;
      }
    });
  }

  /** One anchoring attempt for the next pending batch (no-op if nothing is pending). Never throws. */
  anchorOnce(): Promise<void> {
    return this.#exclusive(async () => {
      if (this.#state !== "registered" || this.#halted) return;
      const batch = this.#o.receipts.pendingBatch();
      if (!batch) return;
      const { firstSeq, count, root } = batch;
      try {
        const msg = anchorMessage({
          contractId: this.#o.chain.contractId,
          keyHash: this.#o.keys.keyHash,
          root,
          firstSeq: BigInt(firstSeq),
          count: BigInt(count),
        });
        const sig = this.#o.keys.sign(msg);
        const result = await this.#o.chain.anchorReceipts({
          key_hash: this.#keyHashHex,
          root: toHex(root),
          first_seq: firstSeq,
          count,
          sig: toHex(sig),
        });
        const anchor = await this.#findAnchor(firstSeq, typeof result === "number" ? result : null);
        if (!anchor || !this.#matches(anchor, firstSeq, count, root)) {
          this.#o.log.info("anchor_unconfirmed", { first_seq: firstSeq, count });
          return; // will resolve via E_SEQ + resync on the next attempt
        }
        this.#o.receipts.markAnchored({ anchorId: anchor.id, firstSeq, count, root });
        this.#o.log.info("anchored", { anchor_id: anchor.id, first_seq: firstSeq, count });
      } catch (e) {
        const c = codeOf(e, "E_REGISTRY_UNAVAILABLE");
        this.#o.log.info("anchor_failed", { code: c, first_seq: firstSeq, count });
        if (c === "E_SEQ") await this.#resync().catch(() => undefined);
        if (c === "E_DEPOSIT" && this.#state === "registered") {
          // Storage not covered: a refresh registration (with its deposit) tops up the prepaid anchor credit.
          this.#scheduleRegistration(0);
        }
        if (c === "E_INSTANCE_NOT_REGISTERED") {
          // Expired or never registered: re-register (keeps next_seq for a known key).
          this.#state = "failed";
          this.#scheduleRegistration(0);
        }
      }
    });
  }

  #matches(a: AnchorView, firstSeq: number, count: number, root: Uint8Array): boolean {
    return a.key_hash === this.#keyHashHex && a.first_seq === firstSeq && a.count === count && equalBytes(fromHex(a.root, 32), root);
  }

  /** Finds our anchor starting at `firstSeq` (checking `hint` first, then scanning back from the newest). */
  async #findAnchor(firstSeq: number, hint: number | null): Promise<AnchorView | null> {
    const chain = this.#o.chain;
    if (hint !== null && Number.isSafeInteger(hint) && hint >= 0) {
      const a = await chain.getAnchor(hint);
      if (a && a.id === hint && a.key_hash === this.#keyHashHex && a.first_seq === firstSeq) return a;
    }
    const n = await chain.anchorCount();
    for (let id = n - 1, k = 0; id >= 0 && k < this.#o.scanLimit; id--, k++) {
      const a = await chain.getAnchor(id);
      if (a && a.id === id && a.key_hash === this.#keyHashHex && a.first_seq === firstSeq) return a;
    }
    return null;
  }

  /** Brings the local anchored prefix up to the chain's `next_seq`, verifying every adopted root. */
  async #resync(): Promise<void> {
    const next = await this.#o.chain.getInstanceNextSeq(this.#keyHashHex);
    if (next === null) return;
    const r = this.#o.receipts;
    while (r.anchoredCount < next) {
      const first = r.anchoredCount;
      const a = await this.#findAnchor(first, null);
      if (!a || a.count < 1 || first + a.count > r.size || !equalBytes(fromHex(a.root, 32), r.rootOf(first, a.count))) {
        this.#halt();
        return;
      }
      r.markAnchored({ anchorId: a.id, firstSeq: first, count: a.count, root: fromHex(a.root, 32) });
      this.#o.log.info("anchored", { anchor_id: a.id, first_seq: first, count: a.count });
    }
    if (r.anchoredCount > next) this.#halt();
  }

  /** Permanent: the key is registered under another account. Stop everything and tell the service. */
  #operatorMismatch(): void {
    const c = codeField("E_OPERATOR_MISMATCH");
    this.#state = "failed";
    this.#lastError = c;
    this.#halted = true;
    this.stop();
    this.#o.log.info("registration_failed", { code: c });
    const cb = this.#o.onOperatorMismatch;
    if (cb) queueMicrotask(cb);
  }

  #halt(): void {
    if (!this.#halted) this.#o.log.info("anchor_halted", { code: codeField("E_SEQ") });
    this.#halted = true;
  }
}
