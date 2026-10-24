/**
 * Raw Zcash blocks and transactions of every version (v1–v5), parsed only as far as the PLR record log needs: the
 * transparent inputs/outputs and the transaction id. Shielded parts are length-checked and skipped. Used by readers
 * that fetch `getblock <hash> 0` (raw hex, bounded by the 2 MB consensus block size) instead of the verbose JSON,
 * whose size is not bounded by consensus (SPEC-CHAINS §5 reader source; review fix).
 *
 * Also the prevout enrichment of record candidates (review fix, critical): Zcash consensus runs the *spent output's*
 * script, not a fixed P2PKH template, so a `<sig> <pubkey>` scriptSig proves nothing unless the coin it spends is
 * `P2PKH(hash160(pubkey))`. {@link fetchZcashBlock} attaches each candidate input's prevout `scriptPubKey`
 * (`vin[i].prevout`, the Bitcoin Core verbosity-3 shape), which a `strict` {@link ZcashLog} requires.
 *
 * Parsing throws `PlrError(E_BAD_INPUT)` on malformed bytes; the fetch helper maps every failure to
 * `E_REGISTRY_UNAVAILABLE` (a block the node accepted must parse: anything else means a broken or lying node).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { PlrError } from "../errors.js";
import { concatBytes, fromHex, isBytes, isHex, toHex } from "../bytes.js";
import { ZCASH_TX, ZcashByteReader, compactSize, readV5Tx, txidDigest, zcashTxidFromRpc, zcashTxidToRpc, type ZcashTxIn, type ZcashTxOut } from "./tx.js";
import { zcashRecordOfTx, type ZcashBlock } from "./log.js";

export const ZCASH_BLOCK = Object.freeze({
  /** consensus `MAX_BLOCK_SIZE` */
  MAX_BLOCK_BYTES: 2_000_000,
  HEADER_FIXED_LEN: 140,
  /** Equihash solutions are 1344 (mainnet/testnet) or 36 (regtest) bytes */
  MAX_SOLUTION_LEN: 2_000,
  JOINSPLIT_PHGR_LEN: 1802,
  JOINSPLIT_GROTH_LEN: 1698,
  SPEND_V4_LEN: 384,
  OUTPUT_V4_LEN: 948,
  VGID_OVERWINTER: 0x03c48270,
  VGID_SAPLING: 0x892f2085,
} as const);

/** The transparent view of one transaction of any version. */
export interface ZcashTxView {
  /** txid, internal byte order */
  txid: Uint8Array;
  coinbase: boolean;
  vin: ZcashTxIn[];
  vout: ZcashTxOut[];
}

export interface ZcashRawBlock {
  /** block hash, RPC (display) hex: SHA256d of the header incl. the Equihash solution, reversed */
  hash: string;
  /** previous block hash, RPC hex */
  prev: string;
  /** header time, seconds */
  time: number;
  tx: ZcashTxView[];
}

const bad = (d: string): never => {
  throw new PlrError("E_BAD_INPUT", d);
};
const sha256d = (b: Uint8Array): Uint8Array => sha256(sha256(b));
const rpcHex = (internal: Uint8Array): string => zcashTxidToRpc(internal);

function readTransparent(r: ZcashByteReader, MAXN: number): { vin: ZcashTxIn[]; vout: ZcashTxOut[] } {
  const nIn = r.compact(MAXN);
  const vin: ZcashTxIn[] = [];
  for (let i = 0; i < nIn; i++) {
    const prevTxid = r.bytes(32);
    const prevIndex = r.u32();
    const scriptSig = r.bytes(r.compact(MAXN));
    vin.push({ prevTxid, prevIndex, scriptSig, sequence: r.u32() });
  }
  const nOut = r.compact(MAXN);
  const vout: ZcashTxOut[] = [];
  for (let i = 0; i < nOut; i++) {
    const value = r.i64();
    vout.push({ value, script: r.bytes(r.compact(MAXN)) });
  }
  return { vin, vout };
}

function skipJoinSplits(r: ZcashByteReader, MAXN: number, len: number): void {
  const n = r.compact(MAXN);
  r.skip(n * len);
  if (n > 0) r.skip(32 + 64); // joinSplitPubKey, joinSplitSig
}

const isNullOutpoint = (i: ZcashTxIn): boolean => i.prevIndex === 0xffffffff && i.prevTxid.every((b) => b === 0);

/** Reads one transaction of any version (v1–v5) at the reader's position. @throws PlrError E_BAD_INPUT */
export function readAnyZcashTx(r: ZcashByteReader, MAXN: number): ZcashTxView {
  const start = r.offset;
  const b = r.b;
  if (b.length - start < 4) bad("truncated transaction");
  const header = new DataView(b.buffer, b.byteOffset + start, Math.min(4, b.length - start)).getUint32(0, true);
  const overwintered = (header & 0x80000000) !== 0;
  const version = header & 0x7fffffff;
  let vin: ZcashTxIn[];
  let vout: ZcashTxOut[];
  let txid: Uint8Array;
  if (overwintered && version === 5) {
    const t = readV5Tx(r, MAXN);
    vin = t.vin;
    vout = t.vout;
    txid = txidDigest(t);
  } else {
    r.u32(); // header
    if (overwintered) {
      const vgid = r.u32();
      if (version === 3 ? vgid !== ZCASH_BLOCK.VGID_OVERWINTER : version === 4 ? vgid !== ZCASH_BLOCK.VGID_SAPLING : true) bad("bad version group id");
    } else if (version < 1 || version > 2) bad("bad transaction version");
    ({ vin, vout } = readTransparent(r, MAXN));
    r.u32(); // lockTime
    if (overwintered) r.u32(); // expiryHeight
    if (overwintered && version === 4) {
      r.i64(); // valueBalanceSapling
      const nS = r.compact(MAXN);
      r.skip(nS * ZCASH_BLOCK.SPEND_V4_LEN);
      const nO = r.compact(MAXN);
      r.skip(nO * ZCASH_BLOCK.OUTPUT_V4_LEN);
      skipJoinSplits(r, MAXN, ZCASH_BLOCK.JOINSPLIT_GROTH_LEN);
      if (nS + nO > 0) r.skip(64); // bindingSig
    } else if (version >= 2) {
      skipJoinSplits(r, MAXN, ZCASH_BLOCK.JOINSPLIT_PHGR_LEN);
    }
    txid = sha256d(b.subarray(start, r.offset));
  }
  const coinbase = vin.length === 1 && isNullOutpoint(vin[0]!);
  return { txid, coinbase, vin, vout };
}

/** Parses one serialized transaction of any version (no trailing bytes). @throws PlrError E_BAD_INPUT */
export function parseAnyZcashTx(raw: Uint8Array): ZcashTxView {
  if (!isBytes(raw)) return bad("transaction must be bytes");
  if (raw.length > ZCASH_TX.MAX_TX_BYTES) return bad("transaction too large");
  const r = new ZcashByteReader(raw);
  const t = readAnyZcashTx(r, raw.length);
  if (!r.done) bad("trailing bytes");
  return t;
}

/** Parses a serialized block (header with Equihash solution, then its transactions). @throws PlrError E_BAD_INPUT */
export function parseZcashBlock(raw: Uint8Array): ZcashRawBlock {
  if (!isBytes(raw)) return bad("block must be bytes");
  if (raw.length > ZCASH_BLOCK.MAX_BLOCK_BYTES) return bad("block too large");
  const r = new ZcashByteReader(raw);
  r.u32(); // version
  const prev = r.bytes(32);
  r.skip(32 + 32); // merkle root, block commitments
  const time = r.u32();
  r.skip(4 + 32); // bits, nonce
  r.skip(r.compact(ZCASH_BLOCK.MAX_SOLUTION_LEN));
  const headerEnd = r.offset;
  const n = r.compact(raw.length);
  if (n === 0) bad("block without transactions");
  const tx: ZcashTxView[] = [];
  for (let i = 0; i < n; i++) tx.push(readAnyZcashTx(r, raw.length));
  if (!r.done) bad("trailing bytes");
  return { hash: rpcHex(sha256d(raw.subarray(0, headerEnd))), prev: rpcHex(prev), time, tx };
}

/** The {@link ZcashBlock} JSON shape of a parsed block (`vin[i].prevout` is added by {@link fetchZcashBlock}). */
export function zcashBlockJson(height: number, b: ZcashRawBlock): ZcashBlock {
  return {
    height,
    time: b.time,
    tx: b.tx.map((t) => ({
      txid: rpcHex(t.txid),
      vin: t.coinbase
        ? [{ coinbase: toHex(t.vin[0]!.scriptSig) }]
        : t.vin.map((i) => ({ txid: rpcHex(i.prevTxid), vout: i.prevIndex, scriptSig: { hex: toHex(i.scriptSig) } })),
      vout: t.vout.map((o) => ({ scriptPubKey: { hex: toHex(o.script) } })),
    })),
  };
}

/** A JSON-RPC call (`method`, `params`) → `result`; rejects on any failure. */
export type ZcashRpcCall = (method: string, params: unknown[]) => Promise<unknown>;

export interface FetchZcashBlockOptions {
  /** Parallel `getrawtransaction` calls for prevouts (default 8). */
  concurrency?: number;
}

const unavailable = (d: string): never => {
  throw new PlrError("E_REGISTRY_UNAVAILABLE", d);
};

/** `getblock <hash> 0` → raw block bytes (bounded), checked against `hash`. */
async function rawBlock(call: ZcashRpcCall, hash: string): Promise<ZcashRawBlock> {
  const hex = await call("getblock", [hash, 0]);
  if (typeof hex !== "string" || hex.length > 2 * ZCASH_BLOCK.MAX_BLOCK_BYTES || !isHex(hex)) return unavailable("getblock: malformed raw block");
  let b: ZcashRawBlock;
  try {
    b = parseZcashBlock(fromHex(hex));
  } catch {
    return unavailable("getblock: unparsable block");
  }
  if (b.hash !== hash) unavailable("getblock: wrong block");
  return b;
}

/**
 * Fetches block `hash` at `height` as raw bytes and returns its {@link ZcashBlock} view, with `vin[i].prevout`
 * attached to every input of every record-shaped transaction (prevouts from the same block are resolved locally,
 * others with `getrawtransaction <txid> 0`, whose txid is re-computed and checked). Every failure (RPC, malformed or
 * mismatching reply, missing prevout) rejects with PlrError E_REGISTRY_UNAVAILABLE: skipping a record silently
 * could hide a revocation.
 */
export async function fetchZcashBlock(call: ZcashRpcCall, height: number, hash: string, o: FetchZcashBlockOptions = {}): Promise<{ block: ZcashBlock; prev: string }> {
  const raw = await rawBlock(call, hash);
  const block = zcashBlockJson(height, raw);
  // Outputs of this block, by RPC txid.
  const local = new Map<string, ZcashTxOut[]>();
  for (const t of raw.tx) local.set(rpcHex(t.txid), t.vout);
  const need = new Set<string>();
  const candidates: number[] = [];
  block.tx.forEach((t, i) => {
    if (zcashRecordOfTx(t) === null) return; // not record-shaped (shape-only check): no prevouts needed
    candidates.push(i);
    for (const v of t.vin as { txid: string }[]) if (!local.has(v.txid)) need.add(v.txid);
  });
  const fetched = new Map<string, ZcashTxOut[]>();
  const ids = [...need];
  const conc = Math.max(1, Math.min(64, o.concurrency ?? 8));
  for (let k = 0; k < ids.length; k += conc) {
    await Promise.all(ids.slice(k, k + conc).map(async (id) => {
      const hex = await call("getrawtransaction", [id, 0]);
      if (typeof hex !== "string" || hex.length > 2 * ZCASH_TX.MAX_TX_BYTES || !isHex(hex)) return unavailable("getrawtransaction: malformed reply");
      let t: ZcashTxView;
      try {
        t = parseAnyZcashTx(fromHex(hex));
      } catch {
        return unavailable("getrawtransaction: unparsable transaction");
      }
      if (rpcHex(t.txid) !== id) unavailable("getrawtransaction: wrong transaction");
      fetched.set(id, t.vout);
    }));
  }
  for (const i of candidates) {
    for (const v of block.tx[i]!.vin as { txid: string; vout: number; prevout?: { scriptPubKey: { hex: string } } }[]) {
      const outs = local.get(v.txid) ?? fetched.get(v.txid);
      const out = outs?.[v.vout];
      if (out === undefined) return unavailable("prevout not found");
      v.prevout = { scriptPubKey: { hex: toHex(out.script) } };
    }
  }
  return { block, prev: raw.prev };
}

/**
 * Serializes a block from raw transactions (for tests and fakes: a real node computes the merkle root / commitments
 * and the Equihash solution; here the merkle field is SHA256d of the transactions so the hash still commits to them). Returns the bytes and the block hash (RPC hex).
 */
export function buildZcashBlock(p: { prev: string; time: number; txs: Uint8Array[]; solution?: Uint8Array }): { raw: Uint8Array; hash: string } {
  const sol = p.solution ?? new Uint8Array(36);
  const head = new Uint8Array(ZCASH_BLOCK.HEADER_FIXED_LEN);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, 4, true);
  head.set(zcashTxidFromRpc(p.prev), 4);
  head.set(sha256d(concatBytes(...p.txs)), 36); // stand-in for the merkle root: commits to the transactions
  dv.setUint32(100, p.time >>> 0, true);
  const header = concatBytes(head, compactSize(sol.length), sol);
  const raw = concatBytes(header, compactSize(p.txs.length), ...p.txs);
  return { raw, hash: rpcHex(sha256d(header)) };
}
