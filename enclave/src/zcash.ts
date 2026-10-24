/**
 * Zcash tier-C registry writer (SPEC-CHAINS §4, §5). Zcash has no contracts: the registry is a log of signed
 * transparent transactions carrying one `OP_RETURN` record each (`"PLR1" ‖ type ‖ body`). This writer
 *
 * - registers with `reg_keys` / `reg_measure` / `reg_os` / `reg_quote` (the latter commits `SHA256(registration quote)`,
 *   the quote itself being bound by `registrationReportData(contractId, own t-address)` like on every chain), each a v5
 *   transaction it builds and signs itself (ZIP-244 sighash, P2PKH, ZIP-317 fee, branch id from `getblockchaininfo`),
 *   then waits (bounded) until its records are confirmed;
 * - refreshes `reg_quote` (same commitment) when its last confirmed one is older than `refreshAfterMs` of chain time;
 * - anchors with `anchor`, then — once that is confirmed, so the reader orders it first — `anchor_sig`, whose expiry
 *   height is capped at the anchor's height + `ZCASH_LOG.ANCHOR_SIG_WINDOW` (it can never land outside its window).
 *   Per key, a new anchor is never posted while an earlier anchor/anchor_sig of that key could still be mined: the
 *   earlier pair is finished first (review fix: two pending anchors for one `first_seq` could otherwise be paired
 *   with each other's signatures in a reordered block);
 * - reads everything back through its own strict {@link ZcashLog} fold over confirmed blocks (`getblockcount`,
 *   `getblockhash`, raw `getblock <hash> 0` + prevouts, see `fetchZcashBlock`), the exact rules clients apply. Chain
 *   data never makes it throw anything but a {@link PlrError}; a malformed block stops the sync (fail closed) instead
 *   of being skipped silently.
 *
 * Coins: `getaddressutxos` (confirmed outputs of the operator address). An outpoint spent by one of our submitted
 * transactions stays reserved until it disappears from the UTXO set (confirmed spend) or that transaction's expiry
 * height has passed (it can then never be mined), so a pending input is never spent twice by this process. Another
 * process sharing the key (router + exit of one operator) may pick the same coin: the node rejects the conflicting
 * transaction and the writer retries with another coin (random choice makes collisions rare).
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  PlrError, ZCASH_LOG, ZcashLog, anchorMessage, buildSignedTransparentTx, encodeZcashRecord, fetchZcashBlock, fromHex, hash160, isHex,
  keyHash, opReturnScript, osMeasurement, p2pkhScript, parseQuote, parseZcashSecretKey, registrationReportData, tAddress,
  toHex, utf8, zcashRecordOfTx, zcashTxid, zcashTxidFromRpc, zcashTxidToRpc, zip317Fee, type InstanceRecord, type ZcashNetwork, type ZcashRecord,
} from "@plr/shared";
import { isUint, type AnchorArgs, type AnchorView, type RegisterArgs, type RegistryWriter } from "./registry-writer.js";

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

// ------------------------------------------------------------------------------------------------- JSON-RPC

export interface ZebraRpcOptions {
  /** Per-call timeout (default 15 s). */
  timeoutMs?: number;
  /** Response size bound (default 8 MiB: a raw 2 MB block is 4 MB of hex). Enforced while streaming. */
  maxResponseBytes?: number;
}

/** Minimal Zebra JSON-RPC client. Every failure is a PlrError E_REGISTRY_UNAVAILABLE without node-supplied text. */
export class ZebraRpc {
  readonly #url: string;
  readonly #auth: string | null;
  readonly #timeoutMs: number;
  readonly #maxBytes: number;
  #id = 0;

  constructor(url: string, o: ZebraRpcOptions = {}) {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      throw new PlrError("E_BAD_INPUT", "zcash rpc url");
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new PlrError("E_BAD_INPUT", "zcash rpc url");
    // fetch refuses URLs with credentials: move them to a basic-auth header.
    this.#auth = u.username !== "" || u.password !== "" ? `Basic ${Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")}` : null;
    u.username = "";
    u.password = "";
    this.#url = u.toString();
    this.#timeoutMs = o.timeoutMs ?? 15_000;
    this.#maxBytes = o.maxResponseBytes ?? 8 * 1024 * 1024;
  }

  async call(method: string, params: unknown[] = []): Promise<unknown> {
    const id = ++this.#id;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.#auth) headers.authorization = this.#auth;
    let text: string;
    try {
      const res = await fetch(this.#url, {
        method: "POST",
        headers,
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      const len = Number(res.headers.get("content-length") ?? "0");
      if (Number.isFinite(len) && len > this.#maxBytes) throw new Error("too large");
      text = new TextDecoder().decode(await readLimited(res, this.#maxBytes));
    } catch {
      throw new PlrError("E_REGISTRY_UNAVAILABLE", `zcash rpc ${method}`);
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new PlrError("E_REGISTRY_UNAVAILABLE", `zcash rpc ${method}: bad response`);
    }
    if (!isPlainObject(body)) throw new PlrError("E_REGISTRY_UNAVAILABLE", `zcash rpc ${method}: bad response`);
    if (body.error !== undefined && body.error !== null) throw new PlrError("E_REGISTRY_UNAVAILABLE", `zcash rpc ${method}: error`);
    if (!("result" in body)) throw new PlrError("E_REGISTRY_UNAVAILABLE", `zcash rpc ${method}: no result`);
    return body.result;
  }
}

/** Reads a response body, aborting as soon as it exceeds `max` bytes (chunked replies have no content-length). */
async function readLimited(res: Response, max: number): Promise<Uint8Array> {
  if (res.body === null) return new Uint8Array(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      throw new Error("too large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

// ------------------------------------------------------------------------------------------------- writer

/** A spendable coin of the operator address. */
export interface ZcashUtxo {
  /** RPC (display-order) txid hex */
  txid: string;
  vout: number;
  amount: bigint;
  height: number;
}

export interface ZcashWriterOptions {
  /** Zebra RPC URL or client. */
  rpc: string | ZebraRpc;
  network: ZcashNetwork;
  /** Registry owner t-address (`contractId` = `zcash:<network>:<owner>`). */
  owner: string;
  /** Operator secret key (WIF or 64 hex). */
  key: string | Uint8Array;
  /** First height scanned (PLR_ZCASH_START_HEIGHT). Default 0. */
  startHeight?: number;
  /** Max wait for submitted records to be confirmed (default 120 s). */
  confirmTimeoutMs?: number;
  /** Max wait for a spendable coin (default 60 s). */
  coinTimeoutMs?: number;
  /** Poll period while waiting (default 500 ms). */
  pollMs?: number;
  /** Re-post `reg_quote` when the last confirmed one is older than this, in chain time (default 3 h; TTL is 24 h). */
  refreshAfterMs?: number;
  /** Transaction expiry = tip + this (default 40 blocks). */
  expiryDelta?: number;
  /** Coins below fee + this are never spent (default 10 000 zats, so change is never dust). */
  minChange?: bigint;
  /** Coin choice among eligible ones, in [0, 1) (default Math.random). */
  random?: () => number;
  /** Submissions tried with different coins before giving up (default 6). */
  maxSubmitAttempts?: number;
}

interface MyRegistration {
  keys: boolean;
  compose: string | null;
  os: string | null;
  quote: string | null;
  /** chain time (ms) of the latest confirmed reg_quote */
  quoteAtMs: number;
}

interface Inflight {
  /** RPC txid hex */
  txid: string;
  expiryHeight: number;
  confirmed: boolean;
  /** height of the block that confirmed it */
  height?: number;
}

/** One anchor attempt: its `anchor` and `anchor_sig` transactions (slots unique per attempt). */
interface AnchorPair {
  keyHash: string;
  root: string;
  firstSeq: number;
  count: number;
  sig: string;
  anchorSlot: string;
  sigSlot: string;
}

/** RPC txid of a `getblock … 2` transaction: its `txid`, else computed from its raw `hex`; null if neither is usable. */
function txidOf(tx: Record<string, unknown>): string | null {
  if (isTxidHex(tx.txid)) return tx.txid;
  if (typeof tx.hex !== "string" || !isHex(tx.hex)) return null;
  try {
    return zcashTxidToRpc(zcashTxid(fromHex(tx.hex)));
  } catch {
    return null;
  }
}
const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));
const unavailable = (d: string): never => {
  throw new PlrError("E_REGISTRY_UNAVAILABLE", d);
};
const isTxidHex = (s: unknown): s is string => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);

/** SPEC-CHAINS §4/§5 writer for the Zcash record log. */
export class ZcashRegistryWriter implements RegistryWriter {
  readonly contractId: string;
  readonly operatorId: string;
  readonly reuseRegistrationQuote = true;
  readonly network: ZcashNetwork;
  readonly owner: string;
  readonly #rpc: ZebraRpc;
  readonly #sk: Uint8Array;
  readonly #myHash: string;
  readonly #myScript: Uint8Array;
  readonly #myScriptHex: string;
  readonly #startHeight: number;
  readonly #confirmTimeoutMs: number;
  readonly #coinTimeoutMs: number;
  readonly #pollMs: number;
  readonly #refreshAfterMs: number;
  readonly #expiryDelta: number;
  readonly #minChange: bigint;
  readonly #random: () => number;
  readonly #maxAttempts: number;
  #log: ZcashLog;
  #lastHash: string | null = null;
  #tip = -1;
  #syncing: Promise<void> | null = null;
  #mine = new Map<string, MyRegistration>();
  /** slot ("reg_keys:<K>", "anchor:<K>:<first_seq>", …) → our latest submitted transaction for it */
  readonly #inflight = new Map<string, Inflight>();
  /** outpoint "<rpc txid>:<vout>" → expiry height of our transaction spending it */
  readonly #reserved = new Map<string, number>();
  /** key hash → latest anchor attempt */
  readonly #anchorPairs = new Map<string, AnchorPair>();
  #pairSeq = 0;
  #closed = false;

  constructor(o: ZcashWriterOptions) {
    this.#rpc = typeof o.rpc === "string" ? new ZebraRpc(o.rpc) : o.rpc;
    this.#log = new ZcashLog({ network: o.network, owner: o.owner, strict: true });
    this.network = o.network;
    this.owner = o.owner;
    this.contractId = this.#log.contractId;
    this.#sk = typeof o.key === "string" ? parseZcashSecretKey(o.key) : o.key.slice();
    if (this.#sk.length !== 32 || !secp256k1.utils.isValidSecretKey(this.#sk)) throw new PlrError("E_BAD_INPUT", "zcash key");
    const h160 = hash160(secp256k1.getPublicKey(this.#sk, true));
    this.#myHash = toHex(h160);
    this.#myScript = p2pkhScript(h160);
    this.#myScriptHex = toHex(this.#myScript);
    this.operatorId = tAddress(h160, o.network);
    const n = (v: number | undefined, def: number, min: number, max: number, what: string): number => {
      const x = v ?? def;
      if (!isUint(x) || x < min || x > max) throw new PlrError("E_BAD_INPUT", `zcash writer ${what}`);
      return x;
    };
    this.#startHeight = n(o.startHeight, 0, 0, 1_000_000_000, "startHeight");
    this.#confirmTimeoutMs = n(o.confirmTimeoutMs, 120_000, 1, 900_000, "confirmTimeoutMs");
    this.#coinTimeoutMs = n(o.coinTimeoutMs, 60_000, 0, 900_000, "coinTimeoutMs");
    this.#pollMs = n(o.pollMs, 500, 1, 60_000, "pollMs");
    this.#refreshAfterMs = n(o.refreshAfterMs, 3 * 3600_000, 0, 86_400_000, "refreshAfterMs");
    this.#expiryDelta = n(o.expiryDelta, 40, 4, 10_000, "expiryDelta");
    this.#maxAttempts = n(o.maxSubmitAttempts, 6, 1, 100, "maxSubmitAttempts");
    this.#minChange = o.minChange ?? 10_000n;
    if (this.#minChange < 1n) throw new PlrError("E_BAD_INPUT", "zcash writer minChange");
    this.#random = o.random ?? Math.random;
  }

  /** The reader state this writer folded so far (for tests / diagnostics; do not mutate). */
  get log(): ZcashLog {
    return this.#log;
  }

  /** Outpoints currently reserved by submitted, not yet confirmed or expired transactions. */
  get reservedOutpoints(): string[] {
    return [...this.#reserved.keys()];
  }

  close(): void {
    this.#closed = true;
  }

  // ----------------------------------------------------------------------------------------------- reads

  /** Applies every new confirmed block (handles a reorg by refolding from the start height). */
  sync(): Promise<void> {
    if (!this.#syncing) {
      this.#syncing = this.#syncInner().finally(() => {
        this.#syncing = null;
      });
    }
    return this.#syncing;
  }

  async #syncInner(): Promise<void> {
    const tip = await this.#rpc.call("getblockcount");
    if (!isUint(tip)) unavailable("getblockcount");
    this.#tip = tip as number;
    if (this.#lastHash !== null && this.#log.height >= 0) {
      const h = this.#log.height <= this.#tip ? await this.#blockHash(this.#log.height) : null;
      if (h !== this.#lastHash) this.#reset();
    }
    for (let h = Math.max(this.#log.height + 1, this.#startHeight); h <= this.#tip && !this.#closed; h++) {
      const hash = await this.#blockHash(h);
      const { block, prev } = await fetchZcashBlock((m, p) => this.#rpc.call(m, p), h, hash);
      if (this.#lastHash !== null && prev !== this.#lastHash) {
        this.#reset(); // the chain changed under us: refold on the next sync
        return;
      }
      this.#log.apply(block);
      if (this.#log.height !== h) unavailable("getblock: malformed block");
      this.#lastHash = hash;
      this.#scanMine(block.tx, block.time, h);
    }
  }

  async #blockHash(h: number): Promise<string> {
    const hash = await this.#rpc.call("getblockhash", [h]);
    if (!isTxidHex(hash)) unavailable("getblockhash");
    return hash as string;
  }

  #reset(): void {
    this.#log = new ZcashLog({ network: this.network, owner: this.owner, strict: true });
    this.#lastHash = null;
    this.#mine = new Map();
    for (const f of this.#inflight.values()) f.confirmed = false;
  }

  /** Tracks our own confirmed records and transactions. Never throws on chain data. */
  #scanMine(txs: unknown[], time: number, height: number): void {
    const byTxid = new Map<string, Inflight>();
    for (const f of this.#inflight.values()) if (!f.confirmed) byTxid.set(f.txid, f);
    for (const tx of txs) {
      if (!isPlainObject(tx)) continue;
      const f = byTxid.get(txidOf(tx) ?? "");
      if (f) {
        f.confirmed = true;
        f.height = height;
      }
      const r = zcashRecordOfTx(tx, { strict: true });
      if (r === null || r.author !== this.#myHash) continue;
      const rec = r.record;
      try {
        switch (rec.type) {
          case "reg_keys":
            this.#my(toHex(keyHash(fromHex(rec.x25519, 32), fromHex(rec.ed25519, 32)))).keys = true;
            break;
          case "reg_measure":
            this.#my(rec.key_hash).compose ??= rec.compose_hash;
            break;
          case "reg_os":
            this.#my(rec.key_hash).os ??= rec.os_measurement;
            break;
          case "reg_quote": {
            const m = this.#my(rec.key_hash);
            m.quote = rec.quote_sha256;
            m.quoteAtMs = time * 1000;
            break;
          }
          default:
            break;
        }
      } catch {
        // malformed record fields: ignored like the reader does
      }
    }
  }

  #my(kh: string): MyRegistration {
    let m = this.#mine.get(kh);
    if (!m) {
      if (this.#mine.size >= 10_000) this.#mine.clear(); // bound (only our own keys ever land here)
      m = { keys: false, compose: null, os: null, quote: null, quoteAtMs: 0 };
      this.#mine.set(kh, m);
    }
    return m;
  }

  /** The live instance `kh` as every reader selects it (SPEC-CHAINS §5), else null. */
  #instance(kh: string): InstanceRecord | null {
    return this.#log.getInstance(kh);
  }

  async getInstanceNextSeq(kh: string): Promise<number | null> {
    await this.sync();
    return this.#instance(kh)?.next_seq ?? null;
  }

  async getInstanceOperator(kh: string): Promise<string | null> {
    await this.sync();
    return this.#instance(kh)?.operator ?? null;
  }

  async anchorCount(): Promise<number> {
    await this.sync();
    return this.#log.anchorCount();
  }

  async getAnchor(id: number): Promise<AnchorView | null> {
    const a = this.#log.getAnchor(id);
    return a === null ? null : { id: a.id, key_hash: a.key_hash, root: a.root, first_seq: a.first_seq, count: a.count };
  }

  // ----------------------------------------------------------------------------------------------- writes

  /**
   * Posts whichever of `reg_keys` / `reg_measure` / `reg_os` / `reg_quote` are not yet confirmed for this key (and
   * `reg_quote` again when due for refresh), then waits until they are. @throws PlrError
   */
  async registerInstance(a: RegisterArgs): Promise<void> {
    if (!isHex(a.x25519, 32) || !isHex(a.ed25519, 32) || !isHex(a.quote) || typeof a.app_compose !== "string") {
      throw new PlrError("E_BAD_INPUT", "register args");
    }
    const xp = fromHex(a.x25519, 32);
    const ep = fromHex(a.ed25519, 32);
    const quote = fromHex(a.quote);
    const report = parseQuote(quote).report;
    // Same binding a tier-A contract enforces: never commit a quote clients would reject.
    if (toHex(report.reportData) !== toHex(registrationReportData(xp, ep, this.contractId, this.operatorId))) {
      throw new PlrError("E_REPORT_DATA", "registration quote not bound to this registry/operator");
    }
    const kh = toHex(keyHash(xp, ep));
    const compose = toHex(sha256(utf8(a.app_compose)));
    const os = toHex(osMeasurement(report));
    const qh = toHex(sha256(quote));

    await this.sync();
    const m = this.#mine.get(kh);
    const due: { slot: string; record: ZcashRecord }[] = [];
    if (!m?.keys) due.push({ slot: `reg_keys:${kh}`, record: { type: "reg_keys", x25519: a.x25519, ed25519: a.ed25519 } });
    if (m?.compose !== compose) due.push({ slot: `reg_measure:${kh}`, record: { type: "reg_measure", key_hash: kh, compose_hash: compose } });
    if (m?.os !== os) due.push({ slot: `reg_os:${kh}`, record: { type: "reg_os", key_hash: kh, os_measurement: os } });
    const quoteFresh = m?.quote === qh && this.#log.time * 1000 - m.quoteAtMs < this.#refreshAfterMs;
    if (!quoteFresh) due.push({ slot: `reg_quote:${kh}:${qh}`, record: { type: "reg_quote", key_hash: kh, quote_sha256: qh } });
    if (due.length === 0) return;

    const slots: string[] = [];
    for (const d of due) {
      // A transaction of ours for this slot may still be pending from an earlier (timed-out) attempt: wait for it.
      const f = this.#inflight.get(d.slot);
      if (!f || f.confirmed || this.#tip > f.expiryHeight) await this.#submit(d.slot, d.record);
      slots.push(d.slot);
    }
    await this.#waitConfirmed(slots);
    const after = this.#mine.get(kh);
    if (!after?.keys || after.compose !== compose || after.os !== os || after.quote !== qh) unavailable("registration records not visible");
  }

  /**
   * Posts `anchor` (key_hash, root, first_seq, count), waits for it, then posts `anchor_sig` and waits for that.
   * Returns the reader's anchor id, or null if the anchor was not accepted (the caller resynchronises).
   * @throws PlrError E_INSTANCE_NOT_REGISTERED | E_SEQ | E_ANCHOR_SIG | E_REGISTRY_UNAVAILABLE | E_BAD_INPUT
   */
  async anchorReceipts(a: AnchorArgs): Promise<unknown> {
    if (!isHex(a.key_hash, 32) || !isHex(a.root, 32) || !isHex(a.sig, 64) || !isUint(a.first_seq) || !isUint(a.count) || a.count < 1 || a.count > 10_000) {
      throw new PlrError("E_BAD_INPUT", "anchor args");
    }
    await this.sync();
    const inst = this.#instance(a.key_hash);
    // Readers accept anchors only from the selected instance's operator (SPEC-CHAINS §5): anything else would be ignored.
    if (!inst || inst.operator !== this.operatorId) throw new PlrError("E_INSTANCE_NOT_REGISTERED");
    // An earlier attempt for this key that could still be mined is finished first, never raced (see module doc).
    const prior = this.#anchorPairs.get(a.key_hash);
    if (prior !== undefined && this.#pairMayLand(prior)) {
      await this.#finishPair(prior);
      const same = prior.firstSeq === a.first_seq && prior.root === a.root && prior.count === a.count;
      return same ? this.#findAnchorId(prior) : null; // null: the caller resynchronises
    }
    if (inst.next_seq !== a.first_seq) throw new PlrError("E_SEQ");
    const msg = anchorMessage({ contractId: this.contractId, keyHash: fromHex(a.key_hash, 32), root: fromHex(a.root, 32), firstSeq: BigInt(a.first_seq), count: BigInt(a.count) });
    if (!ed25519.verify(fromHex(a.sig, 64), msg, fromHex(inst.ed25519, 32))) throw new PlrError("E_ANCHOR_SIG");

    const n = ++this.#pairSeq;
    const pair: AnchorPair = {
      keyHash: a.key_hash, root: a.root, firstSeq: a.first_seq, count: a.count, sig: a.sig,
      anchorSlot: `anchor:${a.key_hash}:${a.first_seq}:${n}`, sigSlot: `anchor_sig:${a.key_hash}:${a.first_seq}:${n}`,
    };
    this.#anchorPairs.set(a.key_hash, pair);
    await this.#finishPair(pair);
    return this.#findAnchorId(pair);
  }

  #findAnchorId(p: AnchorPair): number | null {
    for (let id = this.#log.anchorCount() - 1, k = 0; id >= 0 && k < 1000; id--, k++) {
      const x = this.#log.getAnchor(id);
      if (x && x.key_hash === p.keyHash && x.first_seq === p.firstSeq && x.root === p.root && x.count === p.count) return id;
    }
    return null;
  }

  /** True while a transaction of this attempt could still be mined (or its signature can still be posted in time). */
  #pairMayLand(p: AnchorPair): boolean {
    const a = this.#inflight.get(p.anchorSlot);
    if (a === undefined) return false;
    if (!a.confirmed) return this.#tip <= a.expiryHeight;
    const s = this.#inflight.get(p.sigSlot);
    if (s === undefined) return a.height !== undefined && this.#tip + 1 <= a.height + ZCASH_LOG.ANCHOR_SIG_WINDOW;
    return !s.confirmed && this.#tip <= s.expiryHeight;
  }

  /** Drives one anchor attempt to the end: `anchor` confirmed, then `anchor_sig` (expiry capped to the window). */
  async #finishPair(p: AnchorPair): Promise<void> {
    const a = this.#inflight.get(p.anchorSlot);
    if (a === undefined || (!a.confirmed && this.#tip > a.expiryHeight)) {
      await this.#submit(p.anchorSlot, { type: "anchor", key_hash: p.keyHash, root: p.root, first_seq: p.firstSeq, count: p.count });
    }
    await this.#waitConfirmed([p.anchorSlot]);
    const ah = this.#inflight.get(p.anchorSlot)?.height;
    if (ah === undefined) return unavailable("anchor height unknown");
    const s = this.#inflight.get(p.sigSlot);
    if (s === undefined || (!s.confirmed && this.#tip > s.expiryHeight)) {
      const maxExpiry = ah + ZCASH_LOG.ANCHOR_SIG_WINDOW;
      if (this.#tip + 1 > maxExpiry) unavailable("anchor signature window passed");
      await this.#submit(p.sigSlot, { type: "anchor_sig", key_prefix: p.keyHash.slice(0, 16), sig: p.sig }, maxExpiry);
    }
    await this.#waitConfirmed([p.sigSlot]);
  }

  /** Waits (bounded) until every slot's transaction is in a block; fails early if one expired unmined. */
  async #waitConfirmed(slots: string[]): Promise<void> {
    const deadline = Date.now() + this.#confirmTimeoutMs;
    for (;;) {
      await this.sync();
      let pending = false;
      for (const s of slots) {
        const f = this.#inflight.get(s);
        if (!f) unavailable("no transaction for slot");
        if (f!.confirmed) continue;
        if (this.#tip > f!.expiryHeight) unavailable("transaction expired unmined");
        pending = true;
      }
      if (!pending) return;
      if (this.#closed || Date.now() >= deadline) unavailable("records not confirmed in time");
      await sleep(this.#pollMs);
    }
  }

  /** Builds, signs and submits one record transaction (retrying with other coins if the node rejects it). */
  async #submit(slot: string, record: ZcashRecord, maxExpiry?: number): Promise<string> {
    const opret = opReturnScript(encodeZcashRecord(record));
    const fee = zip317Fee({ inputs: 1, outputScripts: [opret, this.#myScript] });
    let last: unknown = null;
    for (let attempt = 0; attempt < this.#maxAttempts; attempt++) {
      const coin = await this.#waitForCoin(fee + this.#minChange);
      const branchId = await this.#branchId();
      const expiryHeight = Math.min(this.#tip + this.#expiryDelta, maxExpiry ?? Number.MAX_SAFE_INTEGER);
      const raw = buildSignedTransparentTx({
        branchId,
        expiryHeight,
        inputs: [{ txid: zcashTxidFromRpc(coin.txid), vout: coin.vout, amount: coin.amount, secretKey: this.#sk }],
        outputs: [
          { amount: 0n, script: opret },
          { amount: coin.amount - fee, script: this.#myScript },
        ],
      });
      const txid = zcashTxidToRpc(zcashTxid(raw));
      // Reserved before submission: whatever the node answers, this coin is never offered again while the
      // transaction could still be mined.
      this.#reserved.set(`${coin.txid}:${coin.vout}`, expiryHeight);
      try {
        const r = await this.#rpc.call("sendrawtransaction", [toHex(raw)]);
        if (typeof r === "string" && r !== txid) unavailable("sendrawtransaction: txid mismatch");
        this.#inflight.set(slot, { txid, expiryHeight, confirmed: false });
        return txid;
      } catch (e) {
        last = e;
      }
    }
    throw last instanceof PlrError ? last : new PlrError("E_REGISTRY_UNAVAILABLE", "sendrawtransaction");
  }

  async #branchId(): Promise<number> {
    const info = await this.#rpc.call("getblockchaininfo");
    const nb = isPlainObject(info) && isPlainObject(info.consensus) ? info.consensus.nextblock : undefined;
    if (typeof nb !== "string" || !/^[0-9a-f]{8}$/.test(nb)) return unavailable("getblockchaininfo: consensus.nextblock");
    const id = Number.parseInt(nb, 16);
    if (id === 0) return unavailable("getblockchaininfo: no branch id");
    return id;
  }

  async #waitForCoin(min: bigint): Promise<ZcashUtxo> {
    const deadline = Date.now() + this.#coinTimeoutMs;
    for (;;) {
      await this.sync();
      const c = this.selectCoin(await this.listUtxos(), min);
      if (c) return c;
      if (this.#closed || Date.now() >= deadline) return unavailable("no spendable coin");
      await sleep(this.#pollMs);
    }
  }

  /**
   * The operator's confirmed P2PKH coins (`getaddressutxos`), shape-checked; malformed entries are skipped. Releases
   * reservations whose coin is gone (spent on chain) or whose transaction can no longer be mined (expired).
   */
  async listUtxos(): Promise<ZcashUtxo[]> {
    const r = await this.#rpc.call("getaddressutxos", [{ addresses: [this.operatorId] }]);
    if (!Array.isArray(r)) return unavailable("getaddressutxos");
    const out: ZcashUtxo[] = [];
    for (const u of r.slice(0, 100_000) as unknown[]) {
      if (!isPlainObject(u)) continue;
      const { txid, outputIndex, script, satoshis, height } = u;
      if (!isTxidHex(txid) || !isUint(outputIndex) || outputIndex > 0xffffffff || script !== this.#myScriptHex) continue;
      if (!isUint(satoshis) || !isUint(height)) continue;
      if (u.address !== undefined && u.address !== this.operatorId) continue;
      out.push({ txid, vout: outputIndex, amount: BigInt(satoshis), height });
    }
    const present = new Set(out.map((c) => `${c.txid}:${c.vout}`));
    for (const [k, exp] of this.#reserved) if (!present.has(k) || this.#tip > exp) this.#reserved.delete(k);
    return out;
  }

  /** A random coin worth at least `min` that no pending transaction of ours spends, or null. */
  selectCoin(coins: ZcashUtxo[], min: bigint): ZcashUtxo | null {
    const ok = coins
      .filter((c) => c.amount >= min && !this.#reserved.has(`${c.txid}:${c.vout}`))
      .sort((x, y) => (x.txid < y.txid ? -1 : x.txid > y.txid ? 1 : x.vout - y.vout));
    if (ok.length === 0) return null;
    const r = this.#random();
    const i = Number.isFinite(r) && r >= 0 && r < 1 ? Math.floor(r * ok.length) : 0;
    return ok[i]!;
  }
}
