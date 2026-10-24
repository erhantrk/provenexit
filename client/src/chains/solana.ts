/**
 * {@link RegistryReader} for the Solana tier-B registry (SPEC-CHAINS §11, program in `contracts/solana`).
 *
 * One deployed program; a registry is a state account (`contractId = "solana:" ‖ base58(state)`) with per-item
 * PDAs under the program id: `["compose", state, hash]`, `["os", state, hash]`, `["op", state, operator]`,
 * `["inst", state, key_hash]` (record + 828-byte registration quote), `["anchor", state, u64le(id)]`. This reader
 * fetches them with the RPC `getMultipleAccounts` (base64) and decodes the fixed layouts of
 * `contracts/solana/src/state.rs`. Every account must be owned by the program and have the exact size and kind tag;
 * anything else rejects (fail closed) — a missing account is "not set".
 *
 * Tier B: the program checks owner policy, operator approval, the quote's format and its report_data binding, and
 * stores the quote, but does not verify the quote signature. So `verifiesOnChain = false`: clients verify the
 * stored quote (SPEC-CHAINS §2) and each anchor's Ed25519 signature.
 *
 * TRUST: as with NEAR views, the RPC node is part of the client's trusted base (no light-client proofs), so it
 * must be reached over `https:` (plain `http:` only to a loopback host). Reads use commitment `confirmed` by
 * default (`finalized` trades freshness for rollback safety). Expiry is judged against the local clock (the
 * program uses Clock `unix_timestamp`, which tracks wall time).
 */
import { PublicKey } from "@solana/web3.js";
import { PlrError, isHash32, toHex, type AnchorRecord, type InstanceRecord, type RegistryReader, type RegistryRoot } from "@plr/shared";
import { checkRpcUrl } from "../near-registry.js";
import { BodyTooLargeError, parseJsonBytes, readBodyLimited } from "../http.js";
import { isPlainObject } from "../util.js";

// ------------------------------------------------------------------------------------------------- layouts

/** Account kind tags and sizes (contracts/solana/src/state.rs). */
export const SOLANA_LAYOUT = Object.freeze({
  TAG_STATE: 1,
  TAG_COMPOSE: 2,
  TAG_OS: 3,
  TAG_OPERATOR: 4,
  TAG_INSTANCE: 5,
  TAG_ANCHOR: 6,
  STATE_LEN: 147,
  ITEM_LEN: 2,
  OPERATOR_LEN: 67,
  INSTANCE_LEN: 1013,
  ANCHOR_LEN: 153,
  QUOTE_OFF: 185,
  QUOTE_LEN: 828,
});

/** The §10 / §11 custom error numbering (`ProgramError::Custom(n)`). */
export const SOLANA_ERROR_CODES = Object.freeze([
  "E_UNAUTHORIZED",
  "E_ZERO_HASH",
  "E_BAD_INPUT",
  "E_OPERATOR_UNAPPROVED",
  "E_REPORT_DATA",
  "E_QUOTE_FORMAT",
  "E_SEQ",
  "E_INSTANCE_NOT_REGISTERED",
  "E_COMPOSE_NOT_ALLOWED",
] as const);
export type SolanaErrorCode = (typeof SOLANA_ERROR_CODES)[number];

/** `Custom(n)` → PLR code name, or null for an unknown number. */
export function solanaErrorCode(n: unknown): SolanaErrorCode | null {
  return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= SOLANA_ERROR_CODES.length ? SOLANA_ERROR_CODES[n - 1]! : null;
}

export interface SolanaState {
  owner: string;
  pendingOwner: string | null;
  rootKind: "MOCK" | "INTEL";
  rootP256: string;
  ttlMs: number;
  anchorCount: number;
}

export interface SolanaInstance {
  x25519: string;
  ed25519: string;
  compose_hash: string;
  os_measurement: string;
  operator: string;
  registered_at_ms: number;
  expires_at_ms: number;
  next_seq: number;
}

export interface SolanaAnchor {
  key_hash: string;
  root: string;
  first_seq: number;
  count: number;
  at_ms: number;
  sig: string;
}

class Layout {
  readonly #dv: DataView;
  constructor(readonly b: Uint8Array, len: number, tag: number, what: string) {
    if (b.length !== len || b[0] !== tag) throw new SolanaRegistryError(`${what}: malformed account`);
    this.#dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  bytes(o: number, n: number): Uint8Array {
    return this.b.slice(o, o + n);
  }
  hex(o: number, n: number): string {
    return toHex(this.b.subarray(o, o + n));
  }
  key(o: number): string {
    return new PublicKey(this.b.subarray(o, o + 32)).toBase58();
  }
  u64(o: number, what: string): number {
    const v = this.#dv.getBigUint64(o, true);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new SolanaRegistryError(`${what}: value out of range`);
    return Number(v);
  }
}

/** @throws SolanaRegistryError on a malformed account */
export function decodeSolanaState(b: Uint8Array): SolanaState {
  const L = new Layout(b, SOLANA_LAYOUT.STATE_LEN, SOLANA_LAYOUT.TAG_STATE, "state");
  if (b[33] !== 0 && b[33] !== 1) throw new SolanaRegistryError("state: malformed account");
  const kind = b[66];
  if (kind !== 1 && kind !== 2) throw new SolanaRegistryError("state: bad root kind");
  return {
    owner: L.key(1),
    pendingOwner: b[33] === 1 ? L.key(34) : null,
    rootKind: kind === 1 ? "MOCK" : "INTEL",
    rootP256: L.hex(67, 64),
    ttlMs: L.u64(131, "state"),
    anchorCount: L.u64(139, "state"),
  };
}

/** Compose / OS allowlist entry → allowed. @throws SolanaRegistryError */
export function decodeSolanaItem(b: Uint8Array, tag: number): boolean {
  new Layout(b, SOLANA_LAYOUT.ITEM_LEN, tag, "allowlist entry");
  if (b[1] !== 0 && b[1] !== 1) throw new SolanaRegistryError("allowlist entry: malformed account");
  return b[1] === 1;
}

/** Operator entry → org_id, or null if revoked. @throws SolanaRegistryError */
export function decodeSolanaOperator(b: Uint8Array): string | null {
  new Layout(b, SOLANA_LAYOUT.OPERATOR_LEN, SOLANA_LAYOUT.TAG_OPERATOR, "operator");
  const approved = b[1]!;
  const n = b[2]!;
  if (approved > 1 || n > 64 || (approved === 1) !== n > 0) throw new SolanaRegistryError("operator: malformed account");
  if (approved === 0) return null;
  const org = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(3, 3 + n));
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(org)) throw new SolanaRegistryError("operator: bad org id");
  return org;
}

/** @throws SolanaRegistryError */
export function decodeSolanaInstance(b: Uint8Array): { record: SolanaInstance; quote: Uint8Array } {
  const L = new Layout(b, SOLANA_LAYOUT.INSTANCE_LEN, SOLANA_LAYOUT.TAG_INSTANCE, "instance");
  return {
    record: {
      x25519: L.hex(1, 32),
      ed25519: L.hex(33, 32),
      compose_hash: L.hex(65, 32),
      os_measurement: L.hex(97, 32),
      operator: L.key(129),
      registered_at_ms: L.u64(161, "instance"),
      expires_at_ms: L.u64(169, "instance"),
      next_seq: L.u64(177, "instance"),
    },
    quote: L.bytes(SOLANA_LAYOUT.QUOTE_OFF, SOLANA_LAYOUT.QUOTE_LEN),
  };
}

/** @throws SolanaRegistryError */
export function decodeSolanaAnchor(b: Uint8Array): SolanaAnchor {
  const L = new Layout(b, SOLANA_LAYOUT.ANCHOR_LEN, SOLANA_LAYOUT.TAG_ANCHOR, "anchor");
  return { key_hash: L.hex(1, 32), root: L.hex(33, 32), first_seq: L.u64(65, "anchor"), count: L.u64(73, "anchor"), at_ms: L.u64(81, "anchor"), sig: L.hex(89, 64) };
}

// ------------------------------------------------------------------------------------------------- PDAs

const enc = new TextEncoder();
function hex32(h: string): Uint8Array {
  if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h)) throw new PlrError("E_BAD_INPUT", "hash must be 64 lowercase hex");
  return Uint8Array.from(Buffer.from(h, "hex"));
}

export function u64le(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

/** The per-item PDAs of one registry (SPEC-CHAINS §11 seeds). Hashes are 64 lowercase hex. */
export class SolanaPdas {
  constructor(readonly programId: PublicKey, readonly state: PublicKey) {}
  #pda(seed: string, x: Uint8Array): PublicKey {
    return PublicKey.findProgramAddressSync([enc.encode(seed), this.state.toBytes(), x], this.programId)[0];
  }
  compose(h: string): PublicKey {
    return this.#pda("compose", hex32(h));
  }
  os(h: string): PublicKey {
    return this.#pda("os", hex32(h));
  }
  operator(op: PublicKey): PublicKey {
    return this.#pda("op", op.toBytes());
  }
  instance(keyHash: string): PublicKey {
    return this.#pda("inst", hex32(keyHash));
  }
  anchor(id: number | bigint): PublicKey {
    return this.#pda("anchor", u64le(id));
  }
}

/** A base58 Solana address (32 bytes), or null. Never throws. */
export function parseSolanaKey(s: unknown): PublicKey | null {
  if (typeof s !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s)) return null;
  try {
    const k = new PublicKey(s);
    return k.toBase58() === s ? k : null;
  } catch {
    return null;
  }
}

/** `solana:<state base58>` (SPEC-CHAINS §3) → the state account, or null if malformed. */
export function parseSolanaContractId(id: unknown): string | null {
  if (typeof id !== "string" || id.length > 64 || !id.startsWith("solana:")) return null;
  return parseSolanaKey(id.slice(7))?.toBase58() ?? null;
}

// ------------------------------------------------------------------------------------------------- reader

export interface SolanaRegistryOptions {
  /** Solana JSON-RPC URL (https, or http to a loopback host only). */
  rpcUrl: string;
  /** Registry program id (base58). */
  programId: string;
  /** Registry state account (base58) — the `contractId` part. */
  registry: string;
  /** Read commitment (default "confirmed"). */
  commitment?: "processed" | "confirmed" | "finalized";
  /** Per-RPC-call timeout (default 10 s). */
  timeoutMs?: number;
  /** Clock for instance expiry (default Date.now). */
  now?: () => number;
}

export class SolanaRegistryError extends Error {
  constructor(detail: string) {
    super(`SolanaRegistry: ${detail}`);
    this.name = "SolanaRegistryError";
  }
}

/** Largest RPC reply parsed: ≤ 100 accounts of ≤ 1013 bytes in base64, plus framing. */
const MAX_REPLY_BYTES = 1024 * 1024;
const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

interface RawAccount {
  owner: string;
  data: Uint8Array;
}

export class SolanaRegistry implements RegistryReader {
  readonly chain = "solana";
  /** Tier B: the program does not verify registration quotes (SPEC-CHAINS §1). */
  readonly verifiesOnChain = false;
  readonly contractId: string;
  readonly rpcUrl: string;
  readonly programId: string;
  readonly registry: string;
  readonly pdas: SolanaPdas;
  readonly #commitment: string;
  readonly #timeoutMs: number;
  readonly #now: () => number;
  #rpcId = 0;

  constructor(o: SolanaRegistryOptions) {
    if (!isPlainObject(o)) throw new PlrError("E_BAD_INPUT", "SolanaRegistry options required");
    this.rpcUrl = checkRpcUrl(o.rpcUrl).href;
    const program = parseSolanaKey(o.programId);
    const state = parseSolanaKey(o.registry);
    if (program === null) throw new PlrError("E_BAD_INPUT", "programId must be a base58 Solana address");
    if (state === null) throw new PlrError("E_BAD_INPUT", "registry must be a base58 Solana address");
    const c = o.commitment ?? "confirmed";
    if (c !== "processed" && c !== "confirmed" && c !== "finalized") throw new PlrError("E_BAD_INPUT", "bad commitment");
    const t = o.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(t) || t < 1 || t > 600_000) throw new PlrError("E_BAD_INPUT", "bad timeoutMs");
    if (o.now !== undefined && typeof o.now !== "function") throw new PlrError("E_BAD_INPUT", "bad now");
    this.programId = program.toBase58();
    this.registry = state.toBase58();
    this.contractId = `solana:${this.registry}`;
    this.pdas = new SolanaPdas(program, state);
    this.#commitment = c;
    this.#timeoutMs = t;
    this.#now = o.now ?? Date.now;
  }

  // ---------------------------------------------------------------- RegistryReader

  async state(): Promise<SolanaState> {
    const [a] = await this.#accounts([this.registry]);
    if (a === null) throw new SolanaRegistryError("registry state account not found");
    return decodeSolanaState(a!.data);
  }

  async getRoot(): Promise<RegistryRoot> {
    const s = await this.state();
    return { kind: s.rootKind, p256: s.rootP256 };
  }

  async isComposeAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    return this.#item(this.pdas.compose(h), SOLANA_LAYOUT.TAG_COMPOSE);
  }

  async isOsAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    return this.#item(this.pdas.os(h), SOLANA_LAYOUT.TAG_OS);
  }

  /** The owner-approved `org_id` of an operator address, or null. */
  async getOperator(address: string): Promise<string | null> {
    const k = parseSolanaKey(address);
    if (k === null) return null;
    const [a] = await this.#accounts([this.pdas.operator(k).toBase58()]);
    return a ? decodeSolanaOperator(a.data) : null;
  }

  /** The instance record of `keyHash` with its live `org_id`; null if unknown, expired or its operator is unapproved. */
  async getInstance(keyHash: string): Promise<InstanceRecord | null> {
    if (!isHash32(keyHash)) return null;
    const [a] = await this.#accounts([this.pdas.instance(keyHash).toBase58()]);
    if (!a) return null;
    const { record } = decodeSolanaInstance(a.data);
    if (record.expires_at_ms <= this.#now()) return null;
    // SPEC-CHAINS §1: tier B accepts instance records only from operators the owner currently approves.
    const org = await this.getOperator(record.operator);
    if (org === null) return null;
    return {
      compose_hash: record.compose_hash,
      os_measurement: record.os_measurement,
      x25519: record.x25519,
      ed25519: record.ed25519,
      operator: record.operator,
      org_id: org,
      registered_at_ms: record.registered_at_ms,
      expires_at_ms: record.expires_at_ms,
      next_seq: record.next_seq,
    };
  }

  async anchorCount(): Promise<number> {
    return (await this.state()).anchorCount;
  }

  async getAnchor(id: number): Promise<AnchorRecord | null> {
    if (!isUint(id)) return null;
    const [a] = await this.#accounts([this.pdas.anchor(id).toBase58()]);
    if (!a) return null;
    const x = decodeSolanaAnchor(a.data);
    return { id, key_hash: x.key_hash, root: x.root, first_seq: x.first_seq, count: x.count, at_ms: x.at_ms, sig: x.sig };
  }

  /** SPEC-CHAINS §2 tier B: the registration quote stored with the instance (`offered` ignored), or null. */
  async getRegistrationQuote(keyHash: string, _offered?: Uint8Array): Promise<Uint8Array | null> {
    if (!isHash32(keyHash)) return null;
    const [a] = await this.#accounts([this.pdas.instance(keyHash).toBase58()]);
    return a ? decodeSolanaInstance(a.data).quote : null;
  }

  // ---------------------------------------------------------------- RPC

  async #item(pda: PublicKey, tag: number): Promise<boolean> {
    const [a] = await this.#accounts([pda.toBase58()]);
    return a ? decodeSolanaItem(a.data, tag) : false;
  }

  /** `getMultipleAccounts` (base64): null for a missing account; rejects on a foreign owner or malformed reply. */
  async #accounts(keys: string[]): Promise<(RawAccount | null)[]> {
    const r = await this.#rpc("getMultipleAccounts", [keys, { encoding: "base64", commitment: this.#commitment }]);
    const value = isPlainObject(r) ? r.value : undefined;
    if (!Array.isArray(value) || value.length !== keys.length) throw new SolanaRegistryError("getMultipleAccounts: malformed reply");
    return value.map((v: unknown) => {
      if (v === null) return null;
      if (!isPlainObject(v) || typeof v.owner !== "string" || !Array.isArray(v.data) || v.data[1] !== "base64" || typeof v.data[0] !== "string") {
        throw new SolanaRegistryError("getMultipleAccounts: malformed account");
      }
      if (v.owner !== this.programId) {
        // A system-owned, empty address (e.g. pre-funded by anyone) is "not set"; anything else is not ours.
        if (v.owner === "11111111111111111111111111111111" && v.data[0] === "") return null;
        throw new SolanaRegistryError("account not owned by the registry program");
      }
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(v.data[0])) throw new SolanaRegistryError("getMultipleAccounts: bad base64");
      return { owner: v.owner, data: new Uint8Array(Buffer.from(v.data[0], "base64")) };
    });
  }

  /** One JSON-RPC call. Rejects on transport error, HTTP status, RPC error, timeout, oversize or malformed reply. */
  async #rpc(method: string, params: unknown[]): Promise<unknown> {
    const id = ++this.#rpcId;
    let res: Response;
    try {
      res = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new SolanaRegistryError(`${method}: RPC unreachable`);
    }
    let bytes: Uint8Array;
    try {
      bytes = await readBodyLimited(res, MAX_REPLY_BYTES);
    } catch (e) {
      throw new SolanaRegistryError(`${method}: ${e instanceof BodyTooLargeError ? "reply too large" : "RPC read failed"}`);
    }
    const j = parseJsonBytes(bytes);
    if (!isPlainObject(j)) throw new SolanaRegistryError(`${method}: malformed RPC reply (HTTP ${res.status})`);
    if (j.error !== undefined && j.error !== null) throw new SolanaRegistryError(`${method}: RPC error`);
    if (res.status !== 200) throw new SolanaRegistryError(`${method}: HTTP ${res.status}`);
    if (j.id !== id || !("result" in j)) throw new SolanaRegistryError(`${method}: malformed RPC reply`);
    return j.result;
  }
}
