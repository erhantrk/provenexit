/**
 * Zcash v5 transactions (ZIP-225 encoding) and their ZIP-244 digests: transaction id, signature digest
 * (transparent inputs and shielded), authorizing-data commitment. Pure; never does I/O.
 */
import { blake2b } from "@noble/hashes/blake2.js";
import { PlrError } from "../errors.js";
import { concatBytes, isBytes, utf8 } from "../bytes.js";

export const ZCASH_TX = Object.freeze({
  /** `fOverwintered | 5` */
  HEADER_V5: 0x80000005,
  VERSION_GROUP_ID_V5: 0x26a7270a,
  /** Upper bound on a serialized transaction we parse (Zcash block size limit is 2 MB). */
  MAX_TX_BYTES: 2_000_000,
  /** consensus `MAX_MONEY` in zatoshi */
  MAX_MONEY: 21_000_000n * 100_000_000n,
  SEQUENCE_FINAL: 0xffffffff,
  SPEND_LEN: 96,
  OUTPUT_LEN: 756,
  ACTION_LEN: 820,
  SPEND_PROOF_LEN: 192,
  OUTPUT_PROOF_LEN: 192,
  SIG_LEN: 64,
  ENC_CIPHERTEXT_LEN: 580,
  OUT_CIPHERTEXT_LEN: 80,
} as const);

/** Legacy script sighash types (ZIP-244 §S.2a). */
export const SIGHASH = Object.freeze({ ALL: 1, NONE: 2, SINGLE: 3, ANYONECANPAY: 0x80 } as const);

export interface ZcashTxIn {
  /** previous txid, internal byte order (as serialized) */
  prevTxid: Uint8Array;
  prevIndex: number;
  scriptSig: Uint8Array;
  sequence: number;
}
export interface ZcashTxOut {
  value: bigint;
  script: Uint8Array;
}
export interface SaplingSpend { cv: Uint8Array; nullifier: Uint8Array; rk: Uint8Array }
export interface SaplingOutput { cv: Uint8Array; cmu: Uint8Array; ephemeralKey: Uint8Array; encCiphertext: Uint8Array; outCiphertext: Uint8Array }
export interface OrchardAction {
  cv: Uint8Array; nullifier: Uint8Array; rk: Uint8Array; cmx: Uint8Array; ephemeralKey: Uint8Array;
  encCiphertext: Uint8Array; outCiphertext: Uint8Array;
}

/** A parsed v5 transaction (ZIP-225). */
export interface ZcashTx {
  header: number;
  versionGroupId: number;
  consensusBranchId: number;
  lockTime: number;
  expiryHeight: number;
  vin: ZcashTxIn[];
  vout: ZcashTxOut[];
  sapling: {
    spends: SaplingSpend[];
    outputs: SaplingOutput[];
    valueBalance: bigint;
    anchor: Uint8Array | null;
    spendProofs: Uint8Array[];
    spendAuthSigs: Uint8Array[];
    outputProofs: Uint8Array[];
    bindingSig: Uint8Array | null;
  };
  orchard: {
    actions: OrchardAction[];
    flags: number;
    valueBalance: bigint;
    anchor: Uint8Array | null;
    proofs: Uint8Array;
    spendAuthSigs: Uint8Array[];
    bindingSig: Uint8Array | null;
  };
}

const bad = (d: string): never => {
  throw new PlrError("E_BAD_INPUT", d);
};

// ---------------------------------------------------------------- encoding helpers

/** Bitcoin CompactSize encoding of `n` (0 ≤ n < 2^53). */
export function compactSize(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) return bad("compactSize out of range");
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >>> 8);
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0xfe;
    new DataView(b.buffer).setUint32(1, n, true);
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = 0xff;
  new DataView(b.buffer).setBigUint64(1, BigInt(n), true);
  return b;
}

const le32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};
const le64s = (n: bigint): Uint8Array => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, n, true);
  return b;
};

/** Bounds-checked little-endian reader; every overrun is `E_BAD_INPUT`. (Internal; shared with `block.ts`.) */
export class ZcashByteReader {
  #o = 0;
  readonly #dv: DataView;
  constructor(readonly b: Uint8Array) {
    this.#dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  get done(): boolean {
    return this.#o === this.b.length;
  }
  /** Current read offset. */
  get offset(): number {
    return this.#o;
  }
  /** Skips `n` bytes (bounds-checked, no copy). */
  skip(n: number): void {
    this.#need(n);
    this.#o += n;
  }
  #need(n: number): void {
    if (!Number.isSafeInteger(n) || n < 0 || this.#o + n > this.b.length) bad("truncated transaction");
  }
  bytes(n: number): Uint8Array {
    this.#need(n);
    const out = this.b.slice(this.#o, this.#o + n);
    this.#o += n;
    return out;
  }
  u8(): number {
    this.#need(1);
    return this.b[this.#o++]!;
  }
  u32(): number {
    this.#need(4);
    const v = this.#dv.getUint32(this.#o, true);
    this.#o += 4;
    return v;
  }
  i64(): bigint {
    this.#need(8);
    const v = this.#dv.getBigInt64(this.#o, true);
    this.#o += 8;
    return v;
  }
  /** Canonical CompactSize, bounded by `max`. */
  compact(max: number): number {
    const t = this.u8();
    let v: number;
    if (t < 0xfd) v = t;
    else if (t === 0xfd) {
      v = this.u8() | (this.u8() << 8);
      if (v < 0xfd) bad("non-canonical compactSize");
    } else if (t === 0xfe) {
      v = this.u32();
      if (v <= 0xffff) bad("non-canonical compactSize");
    } else {
      this.#need(8);
      const big = this.#dv.getBigUint64(this.#o, true);
      this.#o += 8;
      if (big <= 0xffffffffn) bad("non-canonical compactSize");
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) bad("compactSize too large");
      v = Number(big);
    }
    if (v > max) bad("count too large");
    return v;
  }
  /** `count` items of `len` bytes, with an up-front bounds check (no huge allocations from a forged count). */
  items(count: number, len: number): Uint8Array[] {
    this.#need(count * len);
    const out: Uint8Array[] = [];
    for (let i = 0; i < count; i++) out.push(this.bytes(len));
    return out;
  }
}

// ---------------------------------------------------------------- parse / serialize

/**
 * Parses a v5 transaction (ZIP-225). @throws PlrError E_BAD_INPUT on any malformed, truncated or trailing data.
 */
export function parseZcashTx(raw: Uint8Array): ZcashTx {
  if (!isBytes(raw)) return bad("transaction must be bytes");
  if (raw.length > ZCASH_TX.MAX_TX_BYTES) return bad("transaction too large");
  const r = new ZcashByteReader(raw);
  const t = readV5Tx(r, raw.length);
  if (!r.done) bad("trailing bytes");
  return t;
}

/** Reads one v5 transaction at the reader's position (no trailing-data check). `MAXN` bounds every count. */
export function readV5Tx(r: ZcashByteReader, MAXN: number): ZcashTx {
  const header = r.u32();
  if (header !== ZCASH_TX.HEADER_V5) bad("not a v5 transaction");
  const versionGroupId = r.u32();
  if (versionGroupId !== ZCASH_TX.VERSION_GROUP_ID_V5) bad("bad version group id");
  const consensusBranchId = r.u32();
  const lockTime = r.u32();
  const expiryHeight = r.u32();
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
  // Sapling
  const nS = r.compact(MAXN);
  const spends: SaplingSpend[] = r.items(nS, ZCASH_TX.SPEND_LEN).map((s) => ({ cv: s.slice(0, 32), nullifier: s.slice(32, 64), rk: s.slice(64, 96) }));
  const nO = r.compact(MAXN);
  const outputs: SaplingOutput[] = r.items(nO, ZCASH_TX.OUTPUT_LEN).map((o) => ({
    cv: o.slice(0, 32), cmu: o.slice(32, 64), ephemeralKey: o.slice(64, 96), encCiphertext: o.slice(96, 676), outCiphertext: o.slice(676, 756),
  }));
  const anySapling = nS + nO > 0;
  const sValueBalance = anySapling ? r.i64() : 0n;
  const sAnchor = nS > 0 ? r.bytes(32) : null;
  const spendProofs = r.items(nS, ZCASH_TX.SPEND_PROOF_LEN);
  const spendAuthSigs = r.items(nS, ZCASH_TX.SIG_LEN);
  const outputProofs = r.items(nO, ZCASH_TX.OUTPUT_PROOF_LEN);
  const sBinding = anySapling ? r.bytes(64) : null;
  // Orchard
  const nA = r.compact(MAXN);
  const actions: OrchardAction[] = r.items(nA, ZCASH_TX.ACTION_LEN).map((a) => ({
    cv: a.slice(0, 32), nullifier: a.slice(32, 64), rk: a.slice(64, 96), cmx: a.slice(96, 128), ephemeralKey: a.slice(128, 160),
    encCiphertext: a.slice(160, 740), outCiphertext: a.slice(740, 820),
  }));
  let flags = 0;
  let oValueBalance = 0n;
  let oAnchor: Uint8Array | null = null;
  let proofs: Uint8Array = new Uint8Array(0);
  let oSigs: Uint8Array[] = [];
  let oBinding: Uint8Array | null = null;
  if (nA > 0) {
    flags = r.u8();
    oValueBalance = r.i64();
    oAnchor = r.bytes(32);
    proofs = r.bytes(r.compact(MAXN));
    oSigs = r.items(nA, ZCASH_TX.SIG_LEN);
    oBinding = r.bytes(64);
  }
  return {
    header, versionGroupId, consensusBranchId, lockTime, expiryHeight, vin, vout,
    sapling: { spends, outputs, valueBalance: sValueBalance, anchor: sAnchor, spendProofs, spendAuthSigs, outputProofs, bindingSig: sBinding },
    orchard: { actions, flags, valueBalance: oValueBalance, anchor: oAnchor, proofs, spendAuthSigs: oSigs, bindingSig: oBinding },
  };
}

/** Serializes a transaction with only transparent parts (shielded bundles must be empty). */
export function serializeTransparentTx(t: ZcashTx): Uint8Array {
  if (t.sapling.spends.length + t.sapling.outputs.length + t.orchard.actions.length > 0) bad("shielded serialization unsupported");
  const parts: Uint8Array[] = [le32(t.header), le32(t.versionGroupId), le32(t.consensusBranchId), le32(t.lockTime), le32(t.expiryHeight)];
  parts.push(compactSize(t.vin.length));
  for (const i of t.vin) parts.push(i.prevTxid, le32(i.prevIndex), compactSize(i.scriptSig.length), i.scriptSig, le32(i.sequence));
  parts.push(compactSize(t.vout.length));
  for (const o of t.vout) parts.push(le64s(o.value), compactSize(o.script.length), o.script);
  parts.push(Uint8Array.of(0, 0, 0)); // nSpendsSapling, nOutputsSapling, nActionsOrchard
  return concatBytes(...parts);
}

// ---------------------------------------------------------------- ZIP-244 digests

const P = (s: string): Uint8Array => {
  const b = utf8(s);
  if (b.length !== 16) throw new PlrError("E_BAD_INPUT", "personalization must be 16 bytes");
  return b;
};
const H = (pers: Uint8Array, ...data: Uint8Array[]): Uint8Array => blake2b(concatBytes(...data), { dkLen: 32, personalization: pers });
const branchPers = (prefix: string, branchId: number): Uint8Array => concatBytes(utf8(prefix), le32(branchId));

const PERS = {
  HEADERS: P("ZTxIdHeadersHash"),
  TRANSPARENT: P("ZTxIdTranspaHash"),
  PREVOUTS: P("ZTxIdPrevoutHash"),
  SEQUENCE: P("ZTxIdSequencHash"),
  OUTPUTS: P("ZTxIdOutputsHash"),
  AMOUNTS: P("ZTxTrAmountsHash"),
  SCRIPTS: P("ZTxTrScriptsHash"),
  TXIN: P("Zcash___TxInHash"),
  SAPLING: P("ZTxIdSaplingHash"),
  S_SPENDS: P("ZTxIdSSpendsHash"),
  S_SPEND_C: P("ZTxIdSSpendCHash"),
  S_SPEND_N: P("ZTxIdSSpendNHash"),
  S_OUTPUTS: P("ZTxIdSOutputHash"),
  S_OUT_C: P("ZTxIdSOutC__Hash"),
  S_OUT_M: P("ZTxIdSOutM__Hash"),
  S_OUT_N: P("ZTxIdSOutN__Hash"),
  ORCHARD: P("ZTxIdOrchardHash"),
  O_C: P("ZTxIdOrcActCHash"),
  O_M: P("ZTxIdOrcActMHash"),
  O_N: P("ZTxIdOrcActNHash"),
  AUTH_TRANS: P("ZTxAuthTransHash"),
  AUTH_SAPLING: P("ZTxAuthSapliHash"),
  AUTH_ORCHARD: P("ZTxAuthOrchaHash"),
} as const;

const outpoint = (i: ZcashTxIn): Uint8Array => concatBytes(i.prevTxid, le32(i.prevIndex));
const txOutBytes = (o: ZcashTxOut): Uint8Array => concatBytes(le64s(o.value), compactSize(o.script.length), o.script);

function headerDigest(t: ZcashTx): Uint8Array {
  return H(PERS.HEADERS, le32(t.header), le32(t.versionGroupId), le32(t.consensusBranchId), le32(t.lockTime), le32(t.expiryHeight));
}
const prevoutsDigest = (t: ZcashTx) => H(PERS.PREVOUTS, ...t.vin.map(outpoint));
const sequenceDigest = (t: ZcashTx) => H(PERS.SEQUENCE, ...t.vin.map((i) => le32(i.sequence)));
const outputsDigest = (t: ZcashTx) => H(PERS.OUTPUTS, ...t.vout.map(txOutBytes));

function transparentDigest(t: ZcashTx): Uint8Array {
  if (t.vin.length + t.vout.length === 0) return H(PERS.TRANSPARENT);
  return H(PERS.TRANSPARENT, prevoutsDigest(t), sequenceDigest(t), outputsDigest(t));
}

function saplingDigest(t: ZcashTx): Uint8Array {
  const s = t.sapling;
  if (s.spends.length + s.outputs.length === 0) return H(PERS.SAPLING);
  const anchor = s.anchor ?? new Uint8Array(32);
  const spends = s.spends.length === 0
    ? H(PERS.S_SPENDS)
    : H(PERS.S_SPENDS,
      H(PERS.S_SPEND_C, ...s.spends.map((x) => x.nullifier)),
      H(PERS.S_SPEND_N, ...s.spends.flatMap((x) => [x.cv, anchor, x.rk])));
  const outputs = s.outputs.length === 0
    ? H(PERS.S_OUTPUTS)
    : H(PERS.S_OUTPUTS,
      H(PERS.S_OUT_C, ...s.outputs.flatMap((o) => [o.cmu, o.ephemeralKey, o.encCiphertext.subarray(0, 52)])),
      H(PERS.S_OUT_M, ...s.outputs.map((o) => o.encCiphertext.subarray(52, 564))),
      H(PERS.S_OUT_N, ...s.outputs.flatMap((o) => [o.cv, o.encCiphertext.subarray(564), o.outCiphertext])));
  return H(PERS.SAPLING, spends, outputs, le64s(s.valueBalance));
}

function orchardDigest(t: ZcashTx): Uint8Array {
  const o = t.orchard;
  if (o.actions.length === 0) return H(PERS.ORCHARD);
  return H(PERS.ORCHARD,
    H(PERS.O_C, ...o.actions.flatMap((a) => [a.nullifier, a.cmx, a.ephemeralKey, a.encCiphertext.subarray(0, 52)])),
    H(PERS.O_M, ...o.actions.map((a) => a.encCiphertext.subarray(52, 564))),
    H(PERS.O_N, ...o.actions.flatMap((a) => [a.cv, a.rk, a.encCiphertext.subarray(564), a.outCiphertext])),
    Uint8Array.of(o.flags), le64s(o.valueBalance), o.anchor ?? new Uint8Array(32));
}

/** True for the coinbase shape: one input spending the null outpoint. */
export function isCoinbaseTx(t: ZcashTx): boolean {
  if (t.vin.length !== 1) return false;
  const i = t.vin[0]!;
  return i.prevIndex === 0xffffffff && i.prevTxid.every((b) => b === 0);
}

/** ZIP-244 txid digest of a parsed transaction (internal byte order). */
export function txidDigest(t: ZcashTx): Uint8Array {
  return H(branchPers("ZcashTxHash_", t.consensusBranchId), headerDigest(t), transparentDigest(t), saplingDigest(t), orchardDigest(t));
}

/**
 * ZIP-244 transaction id of a serialized v5 transaction, in internal byte order (the order of the ZIP-244 test
 * vectors and of `prevout` fields; RPC hex strings are the byte reverse, see {@link zcashTxidToRpc}).
 * @throws PlrError E_BAD_INPUT for a malformed transaction
 */
export function zcashTxid(tx: Uint8Array): Uint8Array {
  return txidDigest(parseZcashTx(tx));
}

/** ZIP-244 authorizing data commitment (`auth_digest`). */
export function zcashAuthDigest(tx: Uint8Array): Uint8Array {
  const t = parseZcashTx(tx);
  const transScripts = t.vin.length === 0 ? H(PERS.AUTH_TRANS) : H(PERS.AUTH_TRANS, ...t.vin.map((i) => concatBytes(compactSize(i.scriptSig.length), i.scriptSig)));
  const s = t.sapling;
  const sap = s.spends.length + s.outputs.length === 0
    ? H(PERS.AUTH_SAPLING)
    : H(PERS.AUTH_SAPLING, ...s.spendProofs, ...s.spendAuthSigs, ...s.outputProofs, s.bindingSig ?? new Uint8Array(64));
  const o = t.orchard;
  const orch = o.actions.length === 0
    ? H(PERS.AUTH_ORCHARD)
    : H(PERS.AUTH_ORCHARD, o.proofs, ...o.spendAuthSigs, o.bindingSig ?? new Uint8Array(64));
  return H(branchPers("ZTxAuthHash_", t.consensusBranchId), transScripts, sap, orch);
}

/** RPC display hex of a txid (byte-reversed, Bitcoin style). */
export function zcashTxidToRpc(txid: Uint8Array): string {
  if (!isBytes(txid) || txid.length !== 32) return bad("txid must be 32 bytes");
  return Array.from(txid).reverse().map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Internal-order txid bytes from an RPC display hex string. @throws PlrError E_BAD_INPUT */
export function zcashTxidFromRpc(h: string): Uint8Array {
  if (typeof h !== "string" || !/^[0-9a-fA-F]{64}$/.test(h)) return bad("bad rpc txid");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[31 - i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface SighashParams {
  /** null ⇒ the shielded signature digest (Sapling spends / Orchard actions); else a transparent input index. */
  inputIndex: number | null;
  hashType: number;
  /** values of the coins spent by every transparent input, in input order */
  amounts: bigint[];
  /** scriptPubKeys of the coins spent by every transparent input, in input order */
  scriptPubKeys: Uint8Array[];
}

const VALID_HASH_TYPES: ReadonlySet<number> = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

/** ZIP-244 signature digest of a parsed transaction. */
export function sighashDigest(t: ZcashTx, p: SighashParams): Uint8Array {
  const { inputIndex, hashType } = p;
  if (!Number.isInteger(hashType) || !VALID_HASH_TYPES.has(hashType)) bad("bad hash type");
  if (inputIndex !== null && (!Number.isSafeInteger(inputIndex) || inputIndex < 0 || inputIndex >= t.vin.length)) bad("bad input index");
  if (inputIndex === null && hashType !== SIGHASH.ALL) bad("shielded sighash is SIGHASH_ALL");
  const pers = branchPers("ZcashTxHash_", t.consensusBranchId);
  const hd = headerDigest(t);
  const sd = saplingDigest(t);
  const od = orchardDigest(t);
  if (t.vin.length === 0 || isCoinbaseTx(t)) {
    if (inputIndex !== null) bad("no signable transparent input");
    return H(pers, hd, transparentDigest(t), sd, od);
  }
  if (!Array.isArray(p.amounts) || !Array.isArray(p.scriptPubKeys) || p.amounts.length !== t.vin.length || p.scriptPubKeys.length !== t.vin.length) {
    bad("amounts/scriptPubKeys must cover every input");
  }
  for (const a of p.amounts) if (typeof a !== "bigint" || a < 0n || a > ZCASH_TX.MAX_MONEY) bad("bad amount");
  for (const s of p.scriptPubKeys) if (!isBytes(s)) bad("bad scriptPubKey");
  const anyone = (hashType & SIGHASH.ANYONECANPAY) !== 0;
  const base = hashType & 0x7f;
  const prevouts = anyone ? H(PERS.PREVOUTS) : prevoutsDigest(t);
  const amounts = anyone ? H(PERS.AMOUNTS) : H(PERS.AMOUNTS, ...p.amounts.map(le64s));
  const scripts = anyone ? H(PERS.SCRIPTS) : H(PERS.SCRIPTS, ...p.scriptPubKeys.map((s) => concatBytes(compactSize(s.length), s)));
  const sequence = anyone ? H(PERS.SEQUENCE) : sequenceDigest(t);
  let outputs: Uint8Array;
  if (base === SIGHASH.ALL) outputs = outputsDigest(t);
  else if (base === SIGHASH.SINGLE && inputIndex !== null && inputIndex < t.vout.length) outputs = H(PERS.OUTPUTS, txOutBytes(t.vout[inputIndex]!));
  else outputs = H(PERS.OUTPUTS);
  let txin: Uint8Array;
  if (inputIndex === null) txin = H(PERS.TXIN);
  else {
    const i = t.vin[inputIndex]!;
    const spk = p.scriptPubKeys[inputIndex]!;
    txin = H(PERS.TXIN, outpoint(i), le64s(p.amounts[inputIndex]!), compactSize(spk.length), spk, le32(i.sequence));
  }
  const transparentSig = H(PERS.TRANSPARENT, Uint8Array.of(hashType), prevouts, amounts, scripts, sequence, outputs, txin);
  return H(pers, hd, transparentSig, sd, od);
}

/**
 * ZIP-244 signature digest of a serialized v5 transaction (`inputIndex` null ⇒ the shielded digest).
 * @throws PlrError E_BAD_INPUT
 */
export function zcashSighash(tx: Uint8Array, p: SighashParams): Uint8Array {
  return sighashDigest(parseZcashTx(tx), p);
}
