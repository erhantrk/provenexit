/**
 * Solana tier-B registry writer (SPEC-CHAINS §4, §11; program in `contracts/solana`).
 *
 * - `registerInstance` submits `RegisterInstance{x, ed, compose, os, quote[828]}` signed by the operator key, the
 *   quote bound by `registrationReportData(contractId, own base58 address)` (checked here first: a quote the program
 *   or clients would reject is never sent). The instruction data alone is 957 bytes, so a legacy transaction with
 *   its five accounts would exceed the 1232-byte packet limit: the writer keeps one address lookup table per key
 *   (state, operator PDA, instance PDA, system program; created and extended in one transaction, then used once
 *   active) and sends a v0 transaction. Re-registration (refresh) is the same instruction: the program refreshes
 *   the expiry and replaces the quote, keeping `next_seq`. When the stored record belongs to another operator, that
 *   operator's op PDA is appended (static key, optional account 5) so the program can hand the key over if the owner
 *   has revoked that operator (squat recovery, see contracts/solana rules::register).
 * - `anchorReceipts` submits `AnchorReceipts{key_hash, root, first_seq, count, sig}` at the next anchor id (read
 *   from the state account); the signature is checked locally against the registered key first.
 * - Reads decode the program accounts directly (`getMultipleAccountsInfo`, commitment `confirmed`), with the
 *   Clock sysvar for expiry. Liveness follows chain time like the program.
 *
 * Every transaction is simulated first (program errors map to their PLR code: `Custom(n)` = SPEC-CHAINS §10
 * numbering), then sent without preflight and polled with `getSignatureStatuses` until confirmed (re-sent every
 * `resendMs`), bounded by `confirmTimeoutMs` and by the blockhash's `lastValidBlockHeight`. No websocket is used.
 * RPC failures surface as PlrError E_REGISTRY_UNAVAILABLE without node-supplied text; the key never leaves memory.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  AddressLookupTableAccount,
  AddressLookupTableProgram,
  Connection,
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
  type AccountInfo,
  type Commitment,
} from "@solana/web3.js";
import { PlrError, anchorMessage, fromHex, isHex, isPlrErrorCode, keyHash, osMeasurement, parseQuote, registrationReportData, toHex, utf8 } from "@plr/shared";
import { isUint, type AnchorArgs, type AnchorView, type RegisterArgs, type RegistryWriter } from "../registry-writer.js";

// ------------------------------------------------------------------------------------------------- program codec

/** Account layouts of contracts/solana/src/state.rs. */
export const SOLANA_LAYOUT = Object.freeze({
  TAG_STATE: 1,
  TAG_OPERATOR: 4,
  TAG_INSTANCE: 5,
  TAG_ANCHOR: 6,
  STATE_LEN: 147,
  OPERATOR_LEN: 67,
  INSTANCE_LEN: 1013,
  ANCHOR_LEN: 153,
  QUOTE_OFF: 185,
  QUOTE_LEN: 828,
});

/** Instruction tags (SPEC-CHAINS §11). */
export const SOLANA_IX = Object.freeze({
  INIT: 0,
  ALLOW_COMPOSE: 1,
  REVOKE_COMPOSE: 2,
  ALLOW_OS: 3,
  REVOKE_OS: 4,
  SET_ROOT: 5,
  APPROVE_OPERATOR: 6,
  REVOKE_OPERATOR: 7,
  PROPOSE_OWNER: 8,
  ACCEPT_OWNER: 9,
  REGISTER_INSTANCE: 10,
  ANCHOR_RECEIPTS: 11,
});

/** `ProgramError::Custom(n)` → PLR code name (SPEC-CHAINS §10 numbering). */
export const SOLANA_ERROR_CODES: readonly string[] = Object.freeze([
  "E_UNAUTHORIZED",
  "E_ZERO_HASH",
  "E_BAD_INPUT",
  "E_OPERATOR_UNAPPROVED",
  "E_REPORT_DATA",
  "E_QUOTE_FORMAT",
  "E_SEQ",
  "E_INSTANCE_NOT_REGISTERED",
  "E_COMPOSE_NOT_ALLOWED",
]);

/**
 * A program refusal whose code is not a client-side {@link PlrErrorCode} (`E_UNAUTHORIZED`, `E_ZERO_HASH`): the
 * message is the bare code name, which the instance logger extracts (`codeOf`).
 */
export class SolanaProgramError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "SolanaProgramError";
  }
}

/** The error to throw for a program refusal `name` (a PlrError whenever the code exists there). */
export function programError(name: string): PlrError | SolanaProgramError {
  return isPlrErrorCode(name) ? new PlrError(name, "program refused the transaction") : new SolanaProgramError(name);
}

const enc = new TextEncoder();

export function u64le(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function cat(...parts: Uint8Array[]): Buffer {
  return Buffer.concat(parts.map((p) => Buffer.from(p.buffer, p.byteOffset, p.byteLength)));
}

/** `RegisterInstance` data: `10 ‖ x ‖ ed ‖ compose ‖ os ‖ quote`. */
export function encodeRegisterInstance(x: Uint8Array, ed: Uint8Array, compose: Uint8Array, os: Uint8Array, quote: Uint8Array): Buffer {
  for (const f of [x, ed, compose, os]) if (f.length !== 32) throw new PlrError("E_BAD_INPUT", "register field");
  if (quote.length !== SOLANA_LAYOUT.QUOTE_LEN) throw new PlrError("E_QUOTE_FORMAT", "registration quote length");
  return cat(Uint8Array.of(SOLANA_IX.REGISTER_INSTANCE), x, ed, compose, os, quote);
}

/** `AnchorReceipts` data: `11 ‖ key_hash ‖ root ‖ u64le first_seq ‖ u64le count ‖ sig`. */
export function encodeAnchorReceipts(kh: Uint8Array, root: Uint8Array, firstSeq: number, count: number, sig: Uint8Array): Buffer {
  if (kh.length !== 32 || root.length !== 32 || sig.length !== 64 || !isUint(firstSeq) || !isUint(count)) throw new PlrError("E_BAD_INPUT", "anchor field");
  return cat(Uint8Array.of(SOLANA_IX.ANCHOR_RECEIPTS), kh, root, u64le(firstSeq), u64le(count), sig);
}

/** PDAs of one registry (SPEC-CHAINS §11 seeds, all under the program id). */
export class SolanaPdas {
  constructor(readonly programId: PublicKey, readonly state: PublicKey) {}
  #pda(seed: string, x: Uint8Array): PublicKey {
    return PublicKey.findProgramAddressSync([enc.encode(seed), this.state.toBytes(), x], this.programId)[0];
  }
  compose(h: Uint8Array): PublicKey {
    return this.#pda("compose", h);
  }
  os(h: Uint8Array): PublicKey {
    return this.#pda("os", h);
  }
  operator(op: PublicKey): PublicKey {
    return this.#pda("op", op.toBytes());
  }
  instance(kh: Uint8Array): PublicKey {
    return this.#pda("inst", kh);
  }
  anchor(id: number | bigint): PublicKey {
    return this.#pda("anchor", u64le(id));
  }
}

const u64At = (b: Uint8Array, o: number): number => {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(o, true);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new PlrError("E_REGISTRY_UNAVAILABLE", "u64 out of range");
  return Number(v);
};

export interface SolanaInstanceView {
  x25519: string;
  ed25519: string;
  compose: string;
  os: string;
  operator: string;
  registeredAtMs: number;
  expiresAtMs: number;
  nextSeq: number;
  quote: string;
}

/** Program-owned, exact-size, right-tag account data, else E_REGISTRY_UNAVAILABLE (never misread). */
function dataOf(a: AccountInfo<Buffer> | null, program: PublicKey, len: number, tag: number): Uint8Array | null {
  if (a === null) return null;
  if (!a.owner.equals(program)) {
    if (a.owner.equals(SystemProgram.programId) && a.data.length === 0) return null; // pre-funded, not created
    throw new PlrError("E_REGISTRY_UNAVAILABLE", "account not owned by the registry program");
  }
  const d = new Uint8Array(a.data);
  if (d.length !== len || d[0] !== tag) throw new PlrError("E_REGISTRY_UNAVAILABLE", "malformed registry account");
  return d;
}

export function decodeInstanceAccount(d: Uint8Array): SolanaInstanceView {
  const key = (o: number) => new PublicKey(d.subarray(o, o + 32)).toBase58();
  return {
    x25519: toHex(d.subarray(1, 33)),
    ed25519: toHex(d.subarray(33, 65)),
    compose: toHex(d.subarray(65, 97)),
    os: toHex(d.subarray(97, 129)),
    operator: key(129),
    registeredAtMs: u64At(d, 161),
    expiresAtMs: u64At(d, 169),
    nextSeq: u64At(d, 177),
    quote: toHex(d.subarray(SOLANA_LAYOUT.QUOTE_OFF, SOLANA_LAYOUT.QUOTE_OFF + SOLANA_LAYOUT.QUOTE_LEN)),
  };
}

/** Clock sysvar `unix_timestamp` (i64 at offset 32) in ms. */
function clockMs(a: AccountInfo<Buffer> | null): number {
  if (a === null || a.data.length < 40) throw new PlrError("E_REGISTRY_UNAVAILABLE", "clock sysvar");
  const s = new DataView(a.data.buffer, a.data.byteOffset, a.data.byteLength).getBigInt64(32, true);
  if (s < 0n || s > 10n ** 12n) throw new PlrError("E_REGISTRY_UNAVAILABLE", "clock sysvar");
  return Number(s) * 1000;
}

/** Program error name of a simulation / status `err` (`{InstructionError: [i, {Custom: n}]}`), or null. */
export function programErrorCode(err: unknown): string | null {
  if (typeof err !== "object" || err === null || !("InstructionError" in err)) return null;
  const ie = (err as { InstructionError: unknown }).InstructionError;
  if (!Array.isArray(ie) || ie.length !== 2) return null;
  const c = ie[1];
  if (typeof c !== "object" || c === null || !("Custom" in c)) return null;
  const n = (c as { Custom: unknown }).Custom;
  return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= SOLANA_ERROR_CODES.length ? SOLANA_ERROR_CODES[n - 1]! : null;
}

// ------------------------------------------------------------------------------------------------- config

/** `PLR_SOLANA_*` settings (SPEC-CHAINS §11). */
export interface SolanaConfig {
  rpcUrl: string;
  programId: string;
  /** Registry state account (base58). */
  registry: string;
  /** Operator secret key, 64-byte hex (seed ‖ public key). */
  key: string;
}

type Env = Readonly<Record<string, string | undefined>>;
const bad = (what: string): never => {
  throw new PlrError("E_BAD_INPUT", `bad ${what}`);
};

/** Parses a base58 Solana address strictly (canonical text only). */
export function parseSolanaKey(s: unknown): PublicKey | null {
  if (typeof s !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s)) return null;
  try {
    const k = new PublicKey(s);
    return k.toBase58() === s ? k : null;
  } catch {
    return null;
  }
}

/** 64-byte hex secret (seed ‖ pubkey, validated) → Keypair. @throws PlrError E_BAD_INPUT */
export function parseSolanaSecret(hex: unknown): Keypair {
  if (!isHex(hex, 64)) return bad("PLR_SOLANA_KEY");
  try {
    return Keypair.fromSecretKey(fromHex(hex, 64)); // checks the public half matches the seed
  } catch {
    return bad("PLR_SOLANA_KEY");
  }
}

/**
 * Solana registration config: all of PLR_SOLANA_RPC, PLR_SOLANA_PROGRAM, the registry (`registryVar`, e.g.
 * PLR_SOLANA_REGISTRY or a VPN-specific variable) and PLR_SOLANA_KEY, or none (→ null).
 * @throws PlrError E_BAD_INPUT if partially set or invalid
 */
export function loadSolanaConfig(env: Env, registryVar = "PLR_SOLANA_REGISTRY"): SolanaConfig | null {
  const vars = ["PLR_SOLANA_RPC", "PLR_SOLANA_PROGRAM", registryVar, "PLR_SOLANA_KEY"];
  const set = vars.filter((v) => (env[v] ?? "") !== "");
  if (set.length === 0) return null;
  if (set.length !== vars.length) bad(`Solana config (PLR_SOLANA_RPC, PLR_SOLANA_PROGRAM, ${registryVar}, PLR_SOLANA_KEY must be set together)`);
  const rpcUrl = env.PLR_SOLANA_RPC!;
  checkRpc(rpcUrl, "PLR_SOLANA_RPC");
  if (parseSolanaKey(env.PLR_SOLANA_PROGRAM) === null) bad("PLR_SOLANA_PROGRAM");
  if (parseSolanaKey(env[registryVar]) === null) bad(registryVar);
  parseSolanaSecret(env.PLR_SOLANA_KEY);
  return { rpcUrl, programId: env.PLR_SOLANA_PROGRAM!, registry: env[registryVar]!, key: env.PLR_SOLANA_KEY! };
}

function checkRpc(url: string, what: string): void {
  if (typeof url !== "string" || url.length > 2048) bad(what);
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return bad(what);
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username !== "" || u.password !== "") bad(what);
}

// ------------------------------------------------------------------------------------------------- writer

export interface SolanaWriterOptions {
  rpcUrl: string;
  programId: string;
  registry: string;
  /** Operator secret: 64-byte hex or a Keypair. */
  key: string | Keypair;
  /** Read / confirmation commitment (default "confirmed"). */
  commitment?: "confirmed" | "finalized";
  /** Per-RPC-call timeout (default 15 s). */
  rpcTimeoutMs?: number;
  /** Max wait for a transaction to be confirmed (default 60 s). */
  confirmTimeoutMs?: number;
  /** Status poll period (default 400 ms). */
  pollMs?: number;
  /** Re-send period of an unconfirmed transaction (default 2 s). */
  resendMs?: number;
}

const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));
const unavailable = (d: string): never => {
  throw new PlrError("E_REGISTRY_UNAVAILABLE", d);
};

export class SolanaRegistryWriter implements RegistryWriter {
  readonly contractId: string;
  readonly operatorId: string;
  readonly programId: PublicKey;
  readonly state: PublicKey;
  readonly pdas: SolanaPdas;
  readonly #kp: Keypair;
  readonly #conn: Connection;
  readonly #commitment: Commitment;
  readonly #confirmTimeoutMs: number;
  readonly #pollMs: number;
  readonly #resendMs: number;
  /** key hash → its lookup table (state, op PDA, inst PDA, system program) */
  readonly #alts = new Map<string, PublicKey>();
  #closed = false;

  constructor(o: SolanaWriterOptions) {
    checkRpc(o.rpcUrl, "solana rpc url");
    const program = parseSolanaKey(o.programId);
    const state = parseSolanaKey(o.registry);
    if (program === null) bad("solana program id");
    if (state === null) bad("solana registry");
    this.programId = program!;
    this.state = state!;
    this.#kp = typeof o.key === "string" ? parseSolanaSecret(o.key) : o.key;
    this.operatorId = this.#kp.publicKey.toBase58();
    this.contractId = `solana:${this.state.toBase58()}`;
    this.pdas = new SolanaPdas(this.programId, this.state);
    const n = (v: number | undefined, def: number, min: number, max: number, what: string): number => {
      const x = v ?? def;
      if (!isUint(x) || x < min || x > max) bad(`solana writer ${what}`);
      return x;
    };
    const rpcTimeoutMs = n(o.rpcTimeoutMs, 15_000, 1, 600_000, "rpcTimeoutMs");
    this.#confirmTimeoutMs = n(o.confirmTimeoutMs, 60_000, 1, 900_000, "confirmTimeoutMs");
    this.#pollMs = n(o.pollMs, 400, 1, 60_000, "pollMs");
    this.#resendMs = n(o.resendMs, 2_000, 1, 60_000, "resendMs");
    const c = o.commitment ?? "confirmed";
    if (c !== "confirmed" && c !== "finalized") bad("solana writer commitment");
    this.#commitment = c;
    this.#conn = new Connection(o.rpcUrl, {
      commitment: c,
      disableRetryOnRateLimit: true,
      fetch: (input, init) => fetch(input, { ...init, redirect: "error", signal: AbortSignal.timeout(rpcTimeoutMs) }),
    });
  }

  close(): void {
    this.#closed = true;
  }

  // ----------------------------------------------------------------------------------------------- reads

  async #read(keys: PublicKey[]): Promise<(AccountInfo<Buffer> | null)[]> {
    let r: (AccountInfo<Buffer> | null)[];
    try {
      r = await this.#conn.getMultipleAccountsInfo(keys, this.#commitment);
    } catch {
      return unavailable("solana getMultipleAccounts");
    }
    if (!Array.isArray(r) || r.length !== keys.length) unavailable("solana getMultipleAccounts: malformed reply");
    return r;
  }

  /** The instance of `kh` if it exists and is unexpired in chain (Clock) time, else null. */
  async readInstance(kh: string): Promise<SolanaInstanceView | null> {
    if (!isHex(kh, 32)) throw new PlrError("E_BAD_INPUT", "key hash");
    const [inst, clock] = await this.#read([this.pdas.instance(fromHex(kh, 32)), SYSVAR_CLOCK_PUBKEY]);
    const d = dataOf(inst ?? null, this.programId, SOLANA_LAYOUT.INSTANCE_LEN, SOLANA_LAYOUT.TAG_INSTANCE);
    if (d === null) return null;
    const v = decodeInstanceAccount(d);
    return clockMs(clock ?? null) < v.expiresAtMs ? v : null;
  }

  /** The operator of `kh`'s stored record, expired or not (null if there is none). */
  async #recordOperator(instPda: PublicKey): Promise<PublicKey | null> {
    const [inst] = await this.#read([instPda]);
    const d = dataOf(inst ?? null, this.programId, SOLANA_LAYOUT.INSTANCE_LEN, SOLANA_LAYOUT.TAG_INSTANCE);
    return d === null ? null : new PublicKey(decodeInstanceAccount(d).operator);
  }

  async getInstanceNextSeq(kh: string): Promise<number | null> {
    return (await this.readInstance(kh))?.nextSeq ?? null;
  }

  async getInstanceOperator(kh: string): Promise<string | null> {
    return (await this.readInstance(kh))?.operator ?? null;
  }

  async anchorCount(): Promise<number> {
    const [s] = await this.#read([this.state]);
    const d = dataOf(s ?? null, this.programId, SOLANA_LAYOUT.STATE_LEN, SOLANA_LAYOUT.TAG_STATE);
    if (d === null) return unavailable("solana registry state account not found");
    return u64At(d, 139);
  }

  async getAnchor(id: number): Promise<AnchorView | null> {
    if (!isUint(id)) return null;
    const [a] = await this.#read([this.pdas.anchor(id)]);
    const d = dataOf(a ?? null, this.programId, SOLANA_LAYOUT.ANCHOR_LEN, SOLANA_LAYOUT.TAG_ANCHOR);
    if (d === null) return null;
    return { id, key_hash: toHex(d.subarray(1, 33)), root: toHex(d.subarray(33, 65)), first_seq: u64At(d, 65), count: u64At(d, 73) };
  }

  // ----------------------------------------------------------------------------------------------- writes

  /** @throws PlrError (program errors by their code; E_REGISTRY_UNAVAILABLE for transport / timeouts) */
  async registerInstance(a: RegisterArgs): Promise<void> {
    if (!isHex(a.x25519, 32) || !isHex(a.ed25519, 32) || !isHex(a.quote) || typeof a.app_compose !== "string") throw new PlrError("E_BAD_INPUT", "register args");
    const xp = fromHex(a.x25519, 32);
    const ep = fromHex(a.ed25519, 32);
    const quote = fromHex(a.quote);
    const report = parseQuote(quote).report;
    if (toHex(report.reportData) !== toHex(registrationReportData(xp, ep, this.contractId, this.operatorId))) {
      throw new PlrError("E_REPORT_DATA", "registration quote not bound to this registry/operator");
    }
    const khb = keyHash(xp, ep);
    const kh = toHex(khb);
    const data = encodeRegisterInstance(xp, ep, sha256(utf8(a.app_compose)), osMeasurement(report), quote);
    const opPda = this.pdas.operator(this.#kp.publicKey);
    const instPda = this.pdas.instance(khb);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: this.state, isSigner: false, isWritable: false },
        { pubkey: this.#kp.publicKey, isSigner: true, isWritable: true },
        { pubkey: opPda, isSigner: false, isWritable: false },
        { pubkey: instPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
    // A record held by another operator: pass that operator's op PDA (optional account 5) so the program can let
    // us take the key over if the owner has revoked that operator; otherwise the program refuses (E_UNAUTHORIZED).
    const holder = await this.#recordOperator(instPda);
    if (holder !== null && !holder.equals(this.#kp.publicKey)) {
      ix.keys.push({ pubkey: this.pdas.operator(holder), isSigner: false, isWritable: false });
    }
    // Fail fast (and without creating a lookup table) when the operator is not approved.
    const [op] = await this.#read([opPda]);
    const od = dataOf(op ?? null, this.programId, SOLANA_LAYOUT.OPERATOR_LEN, SOLANA_LAYOUT.TAG_OPERATOR);
    if (od === null || od[1] !== 1) throw new PlrError("E_OPERATOR_UNAPPROVED");
    const alt = await this.#lookupTable(kh, [this.state, opPda, instPda, SystemProgram.programId]);
    await this.#send([ix], [alt]);
    const v = await this.readInstance(kh);
    if (v === null || v.operator !== this.operatorId || v.quote !== a.quote) unavailable("registration not visible");
  }

  /**
   * Posts the anchor at the next anchor id and returns that id.
   * @throws PlrError E_INSTANCE_NOT_REGISTERED | E_SEQ | E_ANCHOR_SIG | E_BAD_INPUT | program codes | E_REGISTRY_UNAVAILABLE
   */
  async anchorReceipts(a: AnchorArgs): Promise<unknown> {
    if (!isHex(a.key_hash, 32) || !isHex(a.root, 32) || !isHex(a.sig, 64) || !isUint(a.first_seq) || !isUint(a.count) || a.count < 1 || a.count > 10_000) {
      throw new PlrError("E_BAD_INPUT", "anchor args");
    }
    const inst = await this.readInstance(a.key_hash);
    if (inst === null || inst.operator !== this.operatorId) throw new PlrError("E_INSTANCE_NOT_REGISTERED");
    if (inst.nextSeq !== a.first_seq) throw new PlrError("E_SEQ");
    const khb = fromHex(a.key_hash, 32);
    const root = fromHex(a.root, 32);
    const sig = fromHex(a.sig, 64);
    const msg = anchorMessage({ contractId: this.contractId, keyHash: khb, root, firstSeq: BigInt(a.first_seq), count: BigInt(a.count) });
    if (!ed25519.verify(sig, msg, fromHex(inst.ed25519, 32))) throw new PlrError("E_ANCHOR_SIG");
    const data = encodeAnchorReceipts(khb, root, a.first_seq, a.count, sig);
    // The anchor PDA is derived from the current count: a concurrent anchor by another writer of this registry
    // makes the program refuse the stale PDA (E_BAD_INPUT) — re-read and retry a few times.
    for (let attempt = 0; ; attempt++) {
      const id = await this.anchorCount();
      const ix = new TransactionInstruction({
        programId: this.programId,
        keys: [
          { pubkey: this.state, isSigner: false, isWritable: true },
          { pubkey: this.#kp.publicKey, isSigner: true, isWritable: true },
          { pubkey: this.pdas.instance(khb), isSigner: false, isWritable: true },
          { pubkey: this.pdas.anchor(id), isSigner: false, isWritable: true },
          { pubkey: this.pdas.compose(fromHex(inst.compose, 32)), isSigner: false, isWritable: false },
          { pubkey: this.pdas.os(fromHex(inst.os, 32)), isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data,
      });
      try {
        await this.#send([ix], []);
        return id;
      } catch (e) {
        if (!(e instanceof PlrError) || e.code !== "E_BAD_INPUT" || attempt >= 2) throw e;
        if ((await this.getInstanceNextSeq(a.key_hash)) !== a.first_seq) throw new PlrError("E_SEQ");
      }
    }
  }

  // ----------------------------------------------------------------------------------------------- transactions

  /** This key's lookup table holding `addresses`, created (and waited until usable) if needed. */
  async #lookupTable(kh: string, addresses: PublicKey[]): Promise<AddressLookupTableAccount> {
    const known = this.#alts.get(kh);
    if (known !== undefined) {
      const t = await this.#fetchTable(known);
      if (t !== null && t.isActive() && addresses.every((x) => t.state.addresses.some((y) => y.equals(x)))) return t;
    }
    let recentSlot: number;
    try {
      // Must be in the SlotHashes of the bank that executes the creation: a finalized slot always is (the
      // confirmed tip itself is not in its own bank's SlotHashes).
      recentSlot = await this.#conn.getSlot("finalized");
    } catch {
      return unavailable("solana getSlot");
    }
    const [create, table] = AddressLookupTableProgram.createLookupTable({ authority: this.#kp.publicKey, payer: this.#kp.publicKey, recentSlot });
    const extend = AddressLookupTableProgram.extendLookupTable({ payer: this.#kp.publicKey, authority: this.#kp.publicKey, lookupTable: table, addresses });
    await this.#send([create, extend], []);
    this.#alts.set(kh, table);
    // Addresses appended in slot N are usable from slot N + 1.
    const deadline = Date.now() + this.#confirmTimeoutMs;
    for (;;) {
      const t = await this.#fetchTable(table);
      let slot = -1;
      try {
        slot = await this.#conn.getSlot("confirmed");
      } catch {
        // retried below
      }
      if (t !== null && t.state.addresses.length === addresses.length && slot > t.state.lastExtendedSlot) return t;
      if (this.#closed || Date.now() >= deadline) return unavailable("lookup table not usable in time");
      await sleep(this.#pollMs);
    }
  }

  async #fetchTable(k: PublicKey): Promise<AddressLookupTableAccount | null> {
    try {
      return (await this.#conn.getAddressLookupTable(k, { commitment: "confirmed" })).value;
    } catch {
      return null;
    }
  }

  /**
   * Simulates (program error ⇒ its PLR code), signs, sends and polls until confirmed (bounded).
   * @throws PlrError
   */
  async #send(ixs: TransactionInstruction[], alts: AddressLookupTableAccount[]): Promise<void> {
    let bh: { blockhash: string; lastValidBlockHeight: number };
    try {
      bh = await this.#conn.getLatestBlockhash("confirmed");
    } catch {
      return unavailable("solana getLatestBlockhash");
    }
    let tx: VersionedTransaction;
    let raw: Uint8Array;
    try {
      const msg = new TransactionMessage({ payerKey: this.#kp.publicKey, recentBlockhash: bh.blockhash, instructions: ixs }).compileToV0Message(alts);
      tx = new VersionedTransaction(msg);
      tx.sign([this.#kp]);
      raw = tx.serialize();
    } catch {
      return unavailable("solana transaction too large or malformed");
    }
    if (raw.length > 1232) unavailable("solana transaction too large");
    let sim: { err: unknown };
    try {
      sim = (await this.#conn.simulateTransaction(tx, { sigVerify: false, commitment: "confirmed" })).value;
    } catch {
      return unavailable("solana simulateTransaction");
    }
    if (sim.err !== null && sim.err !== undefined) {
      const code = programErrorCode(sim.err);
      throw code ? programError(code) : new PlrError("E_REGISTRY_UNAVAILABLE", "solana simulation failed");
    }
    const sigB58 = await this.#sendRaw(raw);
    const deadline = Date.now() + this.#confirmTimeoutMs;
    let lastSend = Date.now();
    for (;;) {
      await sleep(this.#pollMs);
      try {
        const st = (await this.#conn.getSignatureStatuses([sigB58])).value[0];
        if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) {
          if (this.#commitment === "finalized" && st.confirmationStatus !== "finalized") continue;
          if (st.err !== null) {
            const code = programErrorCode(st.err);
            throw code ? programError(code) : new PlrError("E_REGISTRY_UNAVAILABLE", "solana transaction failed");
          }
          return;
        }
        if ((await this.#conn.getBlockHeight("confirmed")) > bh.lastValidBlockHeight) unavailable("solana transaction expired");
      } catch (e) {
        if (e instanceof PlrError || e instanceof SolanaProgramError) throw e;
        // transient RPC failure: keep polling until the deadline
      }
      if (this.#closed || Date.now() >= deadline) unavailable("solana transaction not confirmed in time");
      if (Date.now() - lastSend >= this.#resendMs) {
        lastSend = Date.now();
        await this.#sendRaw(raw).catch(() => undefined);
      }
    }
  }

  async #sendRaw(raw: Uint8Array): Promise<string> {
    try {
      return await this.#conn.sendRawTransaction(raw, { skipPreflight: true, maxRetries: 0 });
    } catch {
      return unavailable("solana sendTransaction");
    }
  }
}
