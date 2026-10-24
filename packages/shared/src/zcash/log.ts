/**
 * Zcash tier-C registry state (SPEC-CHAINS §5): a deterministic fold over confirmed blocks (the Zebra `getblock`
 * transaction JSON shape) of signed `OP_RETURN` records. Never throws on chain data: malformed blocks, transactions
 * and records are skipped. Pure; the RPC polling lives in the callers.
 *
 * STRICT MODE (`strict: true`, SPEC-CHAINS §7; every production reader and writer uses it):
 * - Authorship. Zcash consensus runs the spent coin's script, not a P2PKH template, so a `<sig> <pubkey>` scriptSig
 *   alone proves nothing (a coin locked by e.g. `OP_2DROP OP_1` accepts any such scriptSig). A record counts only if
 *   every input carries `prevout.scriptPubKey` = `P2PKH(hash160(pubkey))` and a SIGHASH_ALL signature (hash-type
 *   byte 0x01): then consensus has verified that key's signature over the whole transaction. Inputs without prevout
 *   data make the transaction a non-record (callers must attach it, see `fetchZcashBlock`).
 * - Anchors. An `anchor_sig` is accepted only if it is a valid Ed25519 signature by K's registered `ed25519` over
 *   SPEC §7 `anchorMessage(contractId, …)`, matched against every pending (unsigned) anchor of that operator and key
 *   (newest matching one), so a retried or reordered anchor never picks up another batch's signature.
 * Both modes: anchors come only from the selected instance's operator and registrations are selected per §5
 * (earliest completed whose operator is currently approved).
 * In both modes, registration slots of authors that are not approved when the record lands share a small, separately
 * capped store (oldest evicted first), so record spam by strangers can never block an approved operator.
 */
import { PlrError } from "../errors.js";
import { fromHex, isHex, isPlainObject, isUint, toHex } from "../bytes.js";
import { keyHash } from "../tdx/measure.js";
import { isHash32, type AnchorRecord, type InstanceRecord, type RegistryRoot } from "../registry.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { anchorMessage } from "../receipts/receipt.js";
import { hash160, isZcashNetwork, opReturnData, p2pkhScript, parsePushes, parseTAddress, tAddress, type ZcashNetwork } from "./script.js";
import { decodeZcashRecord, ZCASH_MAX_ANCHOR_COUNT, type ZcashRecord } from "./record.js";

/** The subset of Zebra `getblock <hash> 2` used by {@link ZcashLog}. */
export interface ZcashBlock {
  height: number;
  /** block time, seconds */
  time: number;
  tx: {
    txid: string;
    vin: {
      coinbase?: string;
      scriptSig?: { hex: string };
      txid?: string;
      vout?: number;
      /** the spent coin (Bitcoin Core verbosity-3 shape); required by a strict log */
      prevout?: { scriptPubKey: { hex: string } };
    }[];
    vout: { scriptPubKey: { hex: string } }[];
  }[];
}

export interface ZcashLogOptions {
  network: ZcashNetwork;
  /** owner t-address (the `contractId` part) */
  owner: string;
  /** registration lifetime (default 86 400 000 ms) */
  ttlMs?: number;
  /** Strict mode (see the module comment). Default false = the literal SPEC-CHAINS §5/§7 rules. */
  strict?: boolean;
}

/** A record extracted from a transaction: author hash160 (hex) + record. */
export interface AuthoredZcashRecord {
  author: string;
  record: ZcashRecord;
}

export const ZCASH_LOG = Object.freeze({
  DEFAULT_TTL_MS: 86_400_000,
  /** an anchor needs its 0x21 signature within this many blocks */
  ANCHOR_SIG_WINDOW: 10,
  /**
   * Bound on tracked (author, key) registration slots of authors NOT approved when their record landed (oldest
   * evicted first). Slots of approved authors are not bounded here: the owner controls that set.
   */
  MAX_UNAPPROVED_REGISTRATIONS: 10_000,
  /** strict mode: pending (unsigned) anchors kept per (operator, key) */
  MAX_PENDING_ANCHORS: 8,
  MAX_TX_PER_BLOCK: 100_000,
  MAX_SCRIPT_HEX: 20_000,
} as const);

interface Registration {
  operator: string; // hash160 hex
  keyHash: string;
  x25519?: string;
  ed25519?: string;
  compose?: string;
  os?: string;
  quote?: string;
  /** completion order (global), set once complete */
  completedOrder?: number;
  registeredAtMs: number;
  expiresAtMs: number;
}

interface PendingAnchor {
  keyHash: string;
  root: string;
  firstSeq: number;
  count: number;
  height: number;
}

const isCompressedPub = (b: Uint8Array) => b.length === 33 && (b[0] === 0x02 || b[0] === 0x03);

/**
 * Extracts the PLR record of one `getblock … 2` transaction per SPEC-CHAINS §7: no coinbase input, ≥ 1 input,
 * every scriptSig exactly `<sig> <33-byte compressed pubkey>` with one pubkey, exactly one `0x6a…` output whose
 * single push decodes as a record. Null otherwise. Never throws.
 */
export function zcashRecordOfTx(tx: unknown, o: { strict?: boolean } = {}): AuthoredZcashRecord | null {
  try {
    if (!isPlainObject(tx) || !Array.isArray(tx.vin) || !Array.isArray(tx.vout) || tx.vin.length === 0) return null;
    const strict = isPlainObject(o) && o.strict === true;
    let pub: Uint8Array | null = null;
    let lockHex = "";
    for (const i of tx.vin as unknown[]) {
      if (!isPlainObject(i) || i.coinbase !== undefined || !isPlainObject(i.scriptSig)) return null;
      const h = i.scriptSig.hex;
      if (!isHex(h) || h.length > ZCASH_LOG.MAX_SCRIPT_HEX) return null;
      const pushes = parsePushes(fromHex(h));
      if (pushes === null || pushes.length !== 2 || pushes[0]!.length === 0 || !isCompressedPub(pushes[1]!)) return null;
      if (pub === null) {
        pub = pushes[1]!;
        lockHex = toHex(p2pkhScript(hash160(pub)));
      } else if (toHex(pub) !== toHex(pushes[1]!)) return null;
      if (strict) {
        // The chain verified this key's signature only if the spent coin is P2PKH(hash160(pub)); SIGHASH_ALL only.
        const sig = pushes[0]!;
        if (sig[sig.length - 1] !== 0x01) return null;
        const prev = i.prevout;
        if (!isPlainObject(prev) || !isPlainObject(prev.scriptPubKey) || prev.scriptPubKey.hex !== lockHex) return null;
      }
    }
    let data: Uint8Array | null = null;
    let opReturns = 0;
    for (const o of tx.vout as unknown[]) {
      if (!isPlainObject(o) || !isPlainObject(o.scriptPubKey)) return null;
      const h = o.scriptPubKey.hex;
      if (typeof h !== "string") return null;
      if (!h.startsWith("6a")) continue;
      opReturns++;
      if (opReturns > 1 || !isHex(h) || h.length > ZCASH_LOG.MAX_SCRIPT_HEX) return null;
      data = opReturnData(fromHex(h));
    }
    if (opReturns !== 1 || data === null || pub === null) return null;
    const record = decodeZcashRecord(data);
    return record === null ? null : { author: toHex(hash160(pub)), record };
  } catch {
    return null;
  }
}

const OWNER_TYPES: ReadonlySet<string> = new Set([
  "allow_compose", "revoke_compose", "allow_os", "revoke_os", "set_root", "approve_operator", "revoke_operator", "transfer_owner",
]);

export class ZcashLog {
  readonly contractId: string;
  readonly network: ZcashNetwork;
  readonly strict: boolean;
  readonly #ttlMs: number;
  #owner: string; // hash160 hex
  #height = -1;
  #time = 0;
  #root: RegistryRoot | null = null;
  readonly #compose = new Set<string>();
  readonly #os = new Set<string>();
  /** operator hash160 → org_id */
  readonly #operators = new Map<string, string>();
  /** `${operator}:${keyHash}` → registration */
  readonly #regs = new Map<string, Registration>();
  /** slot keys created by authors not approved at the time, oldest first (capped) */
  readonly #unapproved = new Set<string>();
  /** keyHash → next contiguous receipt seq */
  readonly #nextSeq = new Map<string, number>();
  /** keyHash → completed registrations in completion order */
  readonly #completed = new Map<string, Registration[]>();
  #completions = 0;
  /** `${operator}:${keyHash}` → unsigned anchors, oldest first (non-strict: only the latest) */
  readonly #pending = new Map<string, PendingAnchor[]>();
  readonly #anchors: AnchorRecord[] = [];

  constructor(o: ZcashLogOptions) {
    if (!isPlainObject(o) || !isZcashNetwork(o.network)) throw new PlrError("E_BAD_INPUT", "zcash log: bad network");
    const a = parseTAddress(o.owner);
    if (a.network !== (o.network === "mainnet" ? "mainnet" : "test")) throw new PlrError("E_BAD_INPUT", "zcash log: owner network mismatch");
    const ttl = o.ttlMs ?? ZCASH_LOG.DEFAULT_TTL_MS;
    if (!isUint(ttl) || ttl === 0) throw new PlrError("E_BAD_INPUT", "zcash log: bad ttl");
    if (o.strict !== undefined && typeof o.strict !== "boolean") throw new PlrError("E_BAD_INPUT", "zcash log: bad strict");
    this.network = o.network;
    this.strict = o.strict === true;
    this.#ttlMs = ttl;
    this.#owner = toHex(a.hash160);
    this.contractId = `zcash:${o.network}:${o.owner}`;
  }

  /** Height of the last applied block (-1 before any). */
  get height(): number {
    return this.#height;
  }
  /** Time (seconds) of the last applied block. */
  get time(): number {
    return this.#time;
  }
  /** Current owner t-address (changes with `transfer_owner`). */
  get owner(): string {
    return tAddress(fromHex(this.#owner, 20), this.network);
  }

  /**
   * Applies one block. Blocks must come in increasing height; a block at or below the last applied height is a
   * no-op, as is a malformed block. Never throws.
   */
  apply(b: ZcashBlock): void {
    try {
      if (!isPlainObject(b) || !isUint(b.height) || !isUint(b.time) || !Array.isArray(b.tx)) return;
      if (b.height <= this.#height) return;
      this.#height = b.height;
      this.#time = b.time;
      const txs = b.tx as unknown[];
      const n = Math.min(txs.length, ZCASH_LOG.MAX_TX_PER_BLOCK);
      for (let i = 0; i < n; i++) {
        const r = zcashRecordOfTx(txs[i], { strict: this.strict });
        if (r !== null) this.#applyRecord(r.author, r.record);
      }
      // expire unsigned anchors that ran out of their window
      for (const [k, list] of this.#pending) {
        const live = list.filter((p) => this.#height <= p.height + ZCASH_LOG.ANCHOR_SIG_WINDOW);
        if (live.length === 0) this.#pending.delete(k);
        else if (live.length !== list.length) this.#pending.set(k, live);
      }
    } catch {
      // never throws on chain data
    }
  }

  #applyRecord(author: string, r: ZcashRecord): void {
    if (OWNER_TYPES.has(r.type)) {
      if (author === this.#owner) this.#applyOwner(r);
      return;
    }
    const nowMs = this.#time * 1000;
    switch (r.type) {
      case "reg_keys": {
        const kh = toHex(keyHash(fromHex(r.x25519, 32), fromHex(r.ed25519, 32)));
        const g = this.#reg(author, kh);
        if (g.completedOrder === undefined) {
          g.x25519 = r.x25519;
          g.ed25519 = r.ed25519;
          this.#maybeComplete(g, nowMs);
        }
        return;
      }
      case "reg_measure":
      case "reg_os": {
        if (!isHash32(r.key_hash)) return;
        const v = r.type === "reg_measure" ? r.compose_hash : r.os_measurement;
        if (!isHash32(v)) return;
        const g = this.#reg(author, r.key_hash);
        if (g.completedOrder === undefined) {
          if (r.type === "reg_measure") g.compose = v;
          else g.os = v;
          this.#maybeComplete(g, nowMs);
        }
        return;
      }
      case "reg_quote": {
        if (!isHash32(r.key_hash) || !isHash32(r.quote_sha256)) return;
        const g = this.#reg(author, r.key_hash);
        g.quote = r.quote_sha256;
        if (g.completedOrder === undefined) this.#maybeComplete(g, nowMs);
        else g.expiresAtMs = nowMs + this.#ttlMs; // refresh
        return;
      }
      case "anchor": {
        if (!isHash32(r.key_hash) || !this.#mayAnchor(author, r.key_hash)) return;
        const next = this.#seq(r.key_hash);
        if (r.first_seq !== next || r.count < 1 || r.count > ZCASH_MAX_ANCHOR_COUNT) return;
        if (next + r.count > 0xffffffff) return;
        const k = `${author}:${r.key_hash}`;
        const p: PendingAnchor = { keyHash: r.key_hash, root: r.root, firstSeq: r.first_seq, count: r.count, height: this.#height };
        if (!this.strict) {
          this.#pending.set(k, [p]);
          return;
        }
        const list = [...(this.#pending.get(k) ?? []), p];
        this.#pending.set(k, list.slice(-ZCASH_LOG.MAX_PENDING_ANCHORS));
        return;
      }
      case "anchor_sig": {
        // non-strict (§5 literally): the operator's latest unsigned anchor whose key starts with the prefix.
        // strict: the newest pending anchor of that operator and key prefix that this signature actually signs.
        let best: { k: string; i: number; p: PendingAnchor } | null = null;
        const tried: { k: string; i: number; p: PendingAnchor }[] = [];
        for (const [k, list] of this.#pending) {
          if (!k.startsWith(`${author}:`)) continue;
          list.forEach((p, i) => {
            if (!p.keyHash.startsWith(r.key_prefix) || this.#height > p.height + ZCASH_LOG.ANCHOR_SIG_WINDOW) return;
            tried.push({ k, i, p });
          });
        }
        if (!this.strict) {
          for (const e of tried) if (best === null || e.p.height >= best.p.height) best = e;
        } else {
          tried.sort((a, b) => b.p.height - a.p.height || b.i - a.i);
          best = tried.find((e) => e.p.firstSeq === this.#seq(e.p.keyHash) && this.#mayAnchor(author, e.p.keyHash) && this.#sigValid(e.p, r.sig)) ?? null;
        }
        if (best === null) return;
        const rest = this.#pending.get(best.k)!.filter((_, i) => i !== best!.i);
        if (rest.length === 0) this.#pending.delete(best.k);
        else this.#pending.set(best.k, rest);
        const p = best.p;
        if (!this.#mayAnchor(author, p.keyHash) || this.#seq(p.keyHash) !== p.firstSeq) return;
        this.#nextSeq.set(p.keyHash, p.firstSeq + p.count);
        this.#anchors.push({ id: this.#anchors.length, key_hash: p.keyHash, root: p.root, first_seq: p.firstSeq, count: p.count, at_ms: nowMs, sig: r.sig });
        return;
      }
      default:
        return;
    }
  }

  #applyOwner(r: ZcashRecord): void {
    switch (r.type) {
      case "allow_compose":
        this.#compose.add(r.hash);
        return;
      case "revoke_compose":
        this.#compose.delete(r.hash);
        return;
      case "allow_os":
        this.#os.add(r.hash);
        return;
      case "revoke_os":
        this.#os.delete(r.hash);
        return;
      case "set_root":
        this.#root = { kind: r.kind, p256: r.p256 };
        return;
      case "approve_operator":
        this.#operators.set(r.hash160, r.org_id);
        return;
      case "revoke_operator":
        this.#operators.delete(r.hash160);
        return;
      case "transfer_owner":
        this.#owner = r.hash160;
        return;
      default:
        return;
    }
  }

  /**
   * Registration slot for (operator, key). Slots of authors that are not approved right now live in a separately
   * capped store (oldest evicted); an approved author's touch moves its slot out of it. Never null.
   */
  #reg(operator: string, kh: string): Registration {
    const k = `${operator}:${kh}`;
    const approved = this.#operators.has(operator);
    let g = this.#regs.get(k);
    if (g === undefined) {
      g = { operator, keyHash: kh, registeredAtMs: 0, expiresAtMs: 0 };
      this.#regs.set(k, g);
      if (!approved) {
        this.#unapproved.add(k);
        if (this.#unapproved.size > ZCASH_LOG.MAX_UNAPPROVED_REGISTRATIONS) this.#evict(this.#unapproved.values().next().value as string);
      }
    } else if (approved) this.#unapproved.delete(k);
    return g;
  }

  #evict(k: string): void {
    this.#unapproved.delete(k);
    const g = this.#regs.get(k);
    this.#regs.delete(k);
    if (g === undefined || g.completedOrder === undefined) return;
    const list = (this.#completed.get(g.keyHash) ?? []).filter((x) => x !== g);
    if (list.length === 0) this.#completed.delete(g.keyHash);
    else this.#completed.set(g.keyHash, list);
  }

  #seq(kh: string): number {
    return this.#nextSeq.get(kh) ?? 0;
  }

  /** Whether `author` may anchor key `kh` now (§5: the selected live instance's operator). */
  #mayAnchor(author: string, kh: string): boolean {
    return this.#live(kh)?.operator === author;
  }

  /** Ed25519 check of an anchor signature under the key's registered `ed25519` (strict mode). Never throws. */
  #sigValid(p: PendingAnchor, sigHex: string): boolean {
    try {
      const g = this.#live(p.keyHash);
      if (g === null || !isHex(sigHex, 64)) return false;
      const msg = anchorMessage({ contractId: this.contractId, keyHash: fromHex(p.keyHash, 32), root: fromHex(p.root, 32), firstSeq: BigInt(p.firstSeq), count: BigInt(p.count) });
      return ed25519.verify(fromHex(sigHex, 64), msg, fromHex(g.ed25519!, 32));
    } catch {
      return false;
    }
  }

  #maybeComplete(g: Registration, nowMs: number): void {
    if (g.completedOrder !== undefined || !g.x25519 || !g.ed25519 || !g.compose || !g.os || !g.quote) return;
    g.completedOrder = this.#completions++;
    g.registeredAtMs = nowMs;
    g.expiresAtMs = nowMs + this.#ttlMs;
    const list = this.#completed.get(g.keyHash) ?? [];
    list.push(g);
    this.#completed.set(g.keyHash, list);
  }

  /** The earliest completed registration of `kh` whose operator is currently approved (expired or not). */
  #selected(kh: string): Registration | null {
    for (const g of this.#completed.get(kh) ?? []) if (this.#operators.has(g.operator)) return g;
    return null;
  }

  /** {@link ZcashLog.#selected}, unless expired at the current block time. */
  #live(kh: string): Registration | null {
    const g = this.#selected(kh);
    return g !== null && g.expiresAtMs > this.#time * 1000 ? g : null;
  }

  #record(g: Registration): InstanceRecord {
    return {
      compose_hash: g.compose!,
      os_measurement: g.os!,
      x25519: g.x25519!,
      ed25519: g.ed25519!,
      operator: tAddress(fromHex(g.operator, 20), this.network),
      org_id: this.#operators.get(g.operator) ?? null,
      registered_at_ms: g.registeredAtMs,
      expires_at_ms: g.expiresAtMs,
      next_seq: this.#seq(g.keyHash),
    };
  }

  // ---------------------------------------------------------------- reads

  getRoot(): RegistryRoot | null {
    return this.#root === null ? null : { kind: this.#root.kind, p256: this.#root.p256 };
  }
  isComposeAllowed(h: string): boolean {
    return isHash32(h) && this.#compose.has(h);
  }
  isOsAllowed(h: string): boolean {
    return isHash32(h) && this.#os.has(h);
  }
  /** Live org of an operator t-address (null if not approved). */
  getOperator(address: string): string | null {
    try {
      const a = parseTAddress(address);
      return this.#operators.get(toHex(a.hash160)) ?? null;
    } catch {
      return null;
    }
  }
  getInstance(kh: string): InstanceRecord | null {
    if (!isHash32(kh)) return null;
    const g = this.#live(kh);
    return g === null ? null : this.#record(g);
  }
  /** SHA-256 of the registration quote of the live instance `kh` (hex), else null. */
  registrationQuoteHash(kh: string): string | null {
    if (!isHash32(kh)) return null;
    return this.#live(kh)?.quote ?? null;
  }
  getAnchor(id: number): AnchorRecord | null {
    if (!isUint(id)) return null;
    const a = this.#anchors[id];
    return a === undefined ? null : { ...a };
  }
  anchorCount(): number {
    return this.#anchors.length;
  }
}
