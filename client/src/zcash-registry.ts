/**
 * {@link RegistryReader} for the Zcash tier-C registry (SPEC-CHAINS §1, §5): a strict {@link ZcashLog} folded over the
 * blocks of a Zcash node's JSON-RPC (Zebra: `getblockcount`, `getblockhash`, `getblock <hash> 0`, and
 * `getrawtransaction <txid> 0` for the coins spent by record transactions).
 *
 * Review fixes over the literal §5 reader source: blocks are fetched RAW (`getblock <hash> 0`, at most 2 × the 2 MB
 * consensus block size in hex) and parsed by the shared bounded parser, instead of the verbose JSON whose size is not
 * bounded by consensus (one large block must never stop every client); each record's spent coins must be
 * `P2PKH(author)` and each 0x21 a valid instance signature (see `ZcashLog` strict mode).
 *
 * Nothing about the registry is validated by Zcash consensus beyond transaction signatures, so this reader is
 * `verifiesOnChain = false`: clients additionally check the registration evidence (SPEC-CHAINS §2) and each
 * anchor's Ed25519 signature.
 *
 * Every query first catches up with the node (bounded in time — `syncTimeoutMs`, progress kept — and optionally in
 * blocks; concurrent queries share one catch-up;
 * results are cached for `cacheMs`). Any transport error, RPC error, timeout, malformed reply, chain discontinuity
 * that cannot be resolved, or a catch-up that does not reach the tip rejects (⇒ E_REGISTRY_UNAVAILABLE in
 * `verifyAttestation`): a reader that is behind could miss a revocation, so it never answers from stale state.
 * Malformed transactions inside well-formed blocks are skipped by {@link ZcashLog} (never throw).
 *
 * TRUST: as with NEAR views, the node is part of the client's trusted base (no SPV proofs here), so it must be
 * reached over an authenticated channel: `https:` for a remote host, plain `http:` only to a loopback address.
 * Reorgs: the hash of the last applied block is re-checked on every catch-up (and each new block must link to it);
 * on a mismatch the log is rebuilt from `startHeight`. `minConfirmations` (default 1 = the tip) trades freshness
 * for reorg safety on public networks.
 *
 * TIME: liveness (expiry, SPEC-CHAINS §5) is decided in CHAIN time by {@link ZcashLog}. Block times need not track
 * the wall clock (Zebra regtest blocks carry 2011 timestamps; testnet may lag), so the `*_ms` fields returned here
 * are rebased to the local clock by the tip offset: `t_local = now + (t_chain − tip_time)`. A live instance therefore
 * always has `expires_at_ms > now` with exactly its remaining chain-time lifetime, as SPEC §9 step 9 expects.
 */
import { createHash } from "node:crypto";
import {
  PlrError,
  ZcashLog,
  fetchZcashBlock,
  isHash32,
  isTAddress,
  isZcashNetwork,
  type AnchorRecord,
  type InstanceRecord,
  type RegistryReader,
  type RegistryRoot,
  type ZcashBlock,
  type ZcashNetwork,
} from "@plr/shared";
import { checkRpcUrl } from "./near-registry.js";
import { BodyTooLargeError, parseJsonBytes, readBodyLimited } from "./http.js";
import { isPlainObject } from "./util.js";

export interface ZcashRegistryOptions {
  /** Zebra JSON-RPC URL (https, or http to a loopback host only). */
  rpcUrl: string;
  network: ZcashNetwork;
  /** Owner t-address: the registry is `zcash:<network>:<owner>`. */
  owner: string;
  /** First block height scanned (`PLR_ZCASH_START_HEIGHT`, default 0). */
  startHeight?: number;
  /** Per-RPC-call timeout (default 10 s). */
  timeoutMs?: number;
  /** Max wall time of one catch-up before the query fails (default 60 s). */
  syncTimeoutMs?: number;
  /** Max blocks applied by one catch-up before the query fails (default: unbounded, `syncTimeoutMs` bounds it; progress is kept). */
  maxBlocksPerSync?: number;
  /** A catch-up younger than this is reused (default 250 ms; 0 = every query asks the node). */
  cacheMs?: number;
  /** Blocks are applied once they have this many confirmations (default 1: the tip itself). */
  minConfirmations?: number;
  /** Parallel block fetches during a catch-up (default 8). */
  concurrency?: number;
  /** Registration lifetime (default 86 400 000 ms, SPEC-CHAINS §5). */
  ttlMs?: number;
  /** Injectable clock (ms) for the cache. */
  now?: () => number;
}

export class ZcashRegistryError extends Error {
  constructor(detail: string) {
    super(`ZcashRegistry: ${detail}`);
    this.name = "ZcashRegistryError";
  }
}

const DEFAULTS = Object.freeze({
  timeoutMs: 10_000,
  syncTimeoutMs: 60_000,
  maxBlocksPerSync: 10_000_000,
  cacheMs: 250,
  minConfirmations: 1,
  concurrency: 8,
});
/** Largest JSON-RPC reply we parse: a raw 2 MB block (4 MB hex) or transaction, plus JSON framing. */
const MAX_REPLY_BYTES = 5 * 1024 * 1024;
/** Upper bound on log rebuilds within one catch-up (reorgs while syncing). */
const MAX_RESETS_PER_SYNC = 3;
const MAX_HEIGHT = 2 ** 31 - 1;
const BLOCK_HASH_RE = /^[0-9a-f]{64}$/;

const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

function intOpt(v: unknown, dflt: number, min: number, max: number, what: string): number {
  const n = v ?? dflt;
  if (!Number.isSafeInteger(n) || (n as number) < min || (n as number) > max) throw new PlrError("E_BAD_INPUT", `bad ${what}`);
  return n as number;
}

export class ZcashRegistry implements RegistryReader {
  readonly chain = "zcash";
  /** Tier C: the chain does not verify registration quotes (SPEC-CHAINS §1). */
  readonly verifiesOnChain = false;
  readonly contractId: string;
  readonly rpcUrl: string;
  readonly network: ZcashNetwork;
  readonly owner: string;
  readonly startHeight: number;
  readonly #o: {
    timeoutMs: number;
    syncTimeoutMs: number;
    maxBlocksPerSync: number;
    cacheMs: number;
    minConfirmations: number;
    concurrency: number;
    ttlMs: number | undefined;
  };
  readonly #now: () => number;
  #log: ZcashLog;
  /** Hash of the last applied block (null before any). */
  #lastHash: string | null = null;
  #syncedAt = -Infinity;
  #pending: Promise<void> | undefined;
  #rpcId = 0;

  constructor(o: ZcashRegistryOptions) {
    if (!isPlainObject(o)) throw new PlrError("E_BAD_INPUT", "ZcashRegistry options required");
    const url = checkRpcUrl(o.rpcUrl);
    if (!isZcashNetwork(o.network)) throw new PlrError("E_BAD_INPUT", "network must be regtest, testnet or mainnet");
    if (!isTAddress(o.owner, o.network)) throw new PlrError("E_BAD_INPUT", "owner is not a P2PKH t-address of this network");
    this.startHeight = intOpt(o.startHeight, 0, 0, MAX_HEIGHT, "startHeight");
    if (o.ttlMs !== undefined && (!Number.isSafeInteger(o.ttlMs) || o.ttlMs < 1)) throw new PlrError("E_BAD_INPUT", "bad ttlMs");
    if (o.now !== undefined && typeof o.now !== "function") throw new PlrError("E_BAD_INPUT", "bad now");
    this.#o = {
      timeoutMs: intOpt(o.timeoutMs, DEFAULTS.timeoutMs, 1, 600_000, "timeoutMs"),
      syncTimeoutMs: intOpt(o.syncTimeoutMs, DEFAULTS.syncTimeoutMs, 1, 900_000, "syncTimeoutMs"),
      maxBlocksPerSync: intOpt(o.maxBlocksPerSync, DEFAULTS.maxBlocksPerSync, 1, 10_000_000, "maxBlocksPerSync"),
      cacheMs: intOpt(o.cacheMs, DEFAULTS.cacheMs, 0, 600_000, "cacheMs"),
      minConfirmations: intOpt(o.minConfirmations, DEFAULTS.minConfirmations, 1, 10_000, "minConfirmations"),
      concurrency: intOpt(o.concurrency, DEFAULTS.concurrency, 1, 64, "concurrency"),
      ttlMs: o.ttlMs,
    };
    this.#now = o.now ?? Date.now;
    this.rpcUrl = url.href;
    this.network = o.network;
    this.owner = o.owner;
    this.#log = this.#newLog();
    this.contractId = this.#log.contractId;
  }

  /** Height of the last applied block (-1 before any). */
  get height(): number {
    return this.#log.height;
  }

  // ---------------------------------------------------------------- RegistryReader

  async getRoot(): Promise<RegistryRoot> {
    await this.sync();
    const r = this.#log.getRoot();
    if (r === null) throw new ZcashRegistryError("no root set by the owner");
    return r;
  }

  async isComposeAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    await this.sync();
    return this.#log.isComposeAllowed(h);
  }

  async isOsAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    await this.sync();
    return this.#log.isOsAllowed(h);
  }

  async getInstance(keyHash: string): Promise<InstanceRecord | null> {
    if (!isHash32(keyHash)) return null;
    await this.sync();
    const r = this.#log.getInstance(keyHash);
    if (r === null) return null;
    return { ...r, registered_at_ms: this.#toLocal(r.registered_at_ms), expires_at_ms: this.#toLocal(r.expires_at_ms) };
  }

  /** The owner-approved `org_id` of an operator t-address, or null (SPEC-CHAINS §5 `approve_operator`). */
  async getOperator(address: string): Promise<string | null> {
    if (!isTAddress(address, this.network)) return null;
    await this.sync();
    return this.#log.getOperator(address);
  }

  async getAnchor(id: number): Promise<AnchorRecord | null> {
    if (!isUint(id)) return null;
    await this.sync();
    const a = this.#log.getAnchor(id);
    return a === null ? null : { ...a, at_ms: this.#toLocal(a.at_ms) };
  }

  async anchorCount(): Promise<number> {
    await this.sync();
    return this.#log.anchorCount();
  }

  /**
   * SPEC-CHAINS §2 tier C: returns a copy of `offered` iff SHA-256(offered) equals the `reg_quote` commitment of
   * the live instance `keyHash`; null otherwise (no commitment, nothing offered, or a mismatch).
   */
  async getRegistrationQuote(keyHash: string, offered?: Uint8Array): Promise<Uint8Array | null> {
    if (!isHash32(keyHash)) return null;
    await this.sync();
    if (!(offered instanceof Uint8Array) || offered.length === 0) return null;
    const committed = this.#log.registrationQuoteHash(keyHash);
    if (committed === null) return null;
    const copy = offered.slice();
    const digest = createHash("sha256").update(copy).digest("hex");
    return digest === committed ? copy : null;
  }

  /** Chain-time ms → local-clock ms via the tip offset (see TIME above). Never negative. */
  #toLocal(chainMs: number): number {
    const v = this.#now() + (chainMs - this.#log.time * 1000);
    return Number.isSafeInteger(v) && v > 0 ? v : 0;
  }

  // ---------------------------------------------------------------- catch-up

  /**
   * Catches up with the node (reused if the last catch-up is younger than `cacheMs`; concurrent callers share
   * one). Rejects with {@link ZcashRegistryError} if the node is unreachable/malformed or the tip is not reached
   * within the configured bounds.
   */
  async sync(): Promise<void> {
    if (this.#pending !== undefined) return this.#pending;
    if (this.#o.cacheMs > 0 && this.#now() - this.#syncedAt < this.#o.cacheMs) return;
    const p = this.#catchUp().finally(() => {
      if (this.#pending === p) this.#pending = undefined;
    });
    this.#pending = p;
    return p;
  }

  async #catchUp(): Promise<void> {
    const deadline = Date.now() + this.#o.syncTimeoutMs;
    let applied = 0;
    let resets = 0;
    const reset = (why: string): void => {
      if (++resets > MAX_RESETS_PER_SYNC) throw new ZcashRegistryError(`chain keeps changing (${why})`);
      this.#log = this.#newLog();
      this.#lastHash = null;
    };
    for (;;) {
      if (Date.now() > deadline) throw new ZcashRegistryError("catch-up timed out");
      const count = await this.#rpc("getblockcount", []);
      if (!isUint(count) || count > MAX_HEIGHT) throw new ZcashRegistryError("getblockcount: malformed reply");
      const target = count - (this.#o.minConfirmations - 1);
      // Reorg / reset detection on the last applied block.
      if (this.#lastHash !== null) {
        if (this.#log.height > count) {
          reset("tip below the applied height");
          continue;
        }
        const h = await this.#blockHash(this.#log.height);
        if (h !== this.#lastHash) {
          reset("last applied block replaced");
          continue;
        }
      }
      const from = Math.max(this.startHeight, this.#log.height + 1);
      if (from > target) {
        this.#syncedAt = this.#now();
        return;
      }
      if (applied >= this.#o.maxBlocksPerSync) throw new ZcashRegistryError("catch-up block budget exhausted");
      const to = Math.min(target, from + this.#o.concurrency - 1, from + (this.#o.maxBlocksPerSync - applied) - 1);
      const heights: number[] = [];
      for (let h = from; h <= to; h++) heights.push(h);
      const blocks = await Promise.all(heights.map((h) => this.#fetchBlock(h)));
      let relinked = false;
      for (const b of blocks) {
        if (this.#lastHash !== null && b.prev !== undefined && b.prev !== this.#lastHash) {
          reset("block does not link to the applied chain");
          relinked = true;
          break;
        }
        this.#log.apply(b.block);
        if (this.#log.height !== b.block.height) throw new ZcashRegistryError("block was not applied");
        this.#lastHash = b.hash;
        applied++;
      }
      if (relinked) continue;
      if (to >= target) {
        // Caught up with the tip reported by this round's getblockcount.
        this.#syncedAt = this.#now();
        return;
      }
    }
  }

  async #blockHash(height: number): Promise<string> {
    const h = await this.#rpc("getblockhash", [height]);
    if (typeof h !== "string" || !BLOCK_HASH_RE.test(h)) throw new ZcashRegistryError("getblockhash: malformed reply");
    return h;
  }

  /**
   * `getblockhash h` + `getblock <hash> 0` (raw, parsed by the shared bounded parser; its header must hash to
   * `hash`) + the prevouts of record-shaped transactions. Any failure rejects (never a silently skipped record).
   */
  async #fetchBlock(height: number): Promise<{ block: ZcashBlock; hash: string; prev: string | undefined }> {
    const hash = await this.#blockHash(height);
    try {
      const { block, prev } = await fetchZcashBlock((m, p) => this.#rpc(m, p), height, hash, { concurrency: this.#o.concurrency });
      return { block, hash, prev: height === 0 ? undefined : prev };
    } catch (e) {
      if (e instanceof ZcashRegistryError) throw e;
      throw new ZcashRegistryError(`block ${height}: ${e instanceof PlrError ? e.message : "unusable"}`);
    }
  }

  /** One JSON-RPC call. Rejects on transport error, HTTP status, RPC error, timeout, oversize or malformed reply. */
  async #rpc(method: string, params: unknown[]): Promise<unknown> {
    const id = ++this.#rpcId;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.#o.timeoutMs);
    timer.unref?.();
    try {
      let res: Response;
      try {
        res = await fetch(this.rpcUrl, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
          redirect: "error",
          signal: ac.signal,
        });
      } catch {
        throw new ZcashRegistryError(`${method}: RPC unreachable`);
      }
      let bytes: Uint8Array;
      try {
        bytes = await readBodyLimited(res, MAX_REPLY_BYTES);
      } catch (e) {
        throw new ZcashRegistryError(`${method}: ${e instanceof BodyTooLargeError ? "reply too large" : "RPC read failed"}`);
      }
      const j = parseJsonBytes(bytes);
      if (!isPlainObject(j)) throw new ZcashRegistryError(`${method}: malformed RPC reply (HTTP ${res.status})`);
      if (j.error !== undefined && j.error !== null) throw new ZcashRegistryError(`${method}: RPC error`);
      if (res.status !== 200) throw new ZcashRegistryError(`${method}: HTTP ${res.status}`);
      if (j.id !== id || !("result" in j)) throw new ZcashRegistryError(`${method}: malformed RPC reply`);
      return j.result;
    } finally {
      clearTimeout(timer);
    }
  }

  #newLog(): ZcashLog {
    return new ZcashLog({ network: this.network, owner: this.owner, strict: true, ...(this.#o.ttlMs !== undefined ? { ttlMs: this.#o.ttlMs } : {}) });
  }
}

/** `zcash:<network>:<owner t-address>` (SPEC-CHAINS §3) → its parts, or null if malformed. */
export function parseZcashContractId(id: unknown): { network: ZcashNetwork; owner: string } | null {
  if (typeof id !== "string" || id.length > 64) return null;
  const m = /^zcash:(regtest|testnet|mainnet):([1-9A-HJ-NP-Za-km-z]+)$/.exec(id);
  if (m === null) return null;
  const network = m[1] as ZcashNetwork;
  return isTAddress(m[2], network) ? { network, owner: m[2]! } : null;
}
