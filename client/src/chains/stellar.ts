/**
 * {@link RegistryReader} for the Stellar Soroban tier-B registry (SPEC-CHAINS §1, §10; contract in contracts/stellar).
 *
 * Views are answered by Soroban RPC `simulateTransaction` of a read-only invocation (no signing, no fee, no account:
 * the source is the all-zero account, which never needs to exist for a simulation). Every reply is decoded strictly
 * from XDR (no loose `scValToNative`): wrong types, lengths or out-of-range integers reject.
 *
 * Tier B (`verifiesOnChain = false`): the contract checks the registration quote's format and `report_data` binding and
 * stores it, but not its signature; clients verify the stored quote (SPEC-CHAINS §2) and each anchor's Ed25519 `sig`.
 *
 * Fail closed: any transport error, RPC error, timeout, simulation failure or malformed reply rejects (⇒
 * E_REGISTRY_UNAVAILABLE in `verifyAttestation`). A contract error (`Error(Contract, #n)`) is mapped back to its
 * SPEC-CHAINS §10 name ({@link stellarErrorName}).
 *
 * TRUST: like NEAR views, simulation results carry no state proof, so the RPC endpoint is part of the client's
 * trusted base and must be reached over `https:` (plain `http:` only to a loopback host).
 */
import { Account, Address, Contract, StrKey, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import {
  PlrError,
  isHash32,
  isOrgId,
  toHex,
  type AnchorRecord,
  type InstanceRecord,
  type PlrErrorCode,
  type RegistryReader,
  type RegistryRoot,
} from "@plr/shared";
import { checkRpcUrl } from "../near-registry.js";

/** Source of read-only simulations (the all-zero ed25519 key; never needs to exist). */
export const STELLAR_NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/** Local quickstart / standalone network passphrase (docs/stellar-local.md). */
export const STELLAR_STANDALONE_PASSPHRASE = "Standalone Network ; February 2017";

/** SPEC-CHAINS §10 `#[contracterror]` numbering. */
export const STELLAR_ERRORS = [
  "E_UNAUTHORIZED",
  "E_ZERO_HASH",
  "E_BAD_INPUT",
  "E_OPERATOR_UNAPPROVED",
  "E_REPORT_DATA",
  "E_QUOTE_FORMAT",
  "E_SEQ",
  "E_INSTANCE_NOT_REGISTERED",
  "E_COMPOSE_NOT_ALLOWED",
] as const;
export type StellarErrorName = (typeof STELLAR_ERRORS)[number];

/** The SPEC-CHAINS §10 name of contract error `n` (1-based), or null. */
export function stellarErrorName(n: number): StellarErrorName | null {
  return Number.isSafeInteger(n) && n >= 1 && n <= STELLAR_ERRORS.length ? STELLAR_ERRORS[n - 1]! : null;
}

/** Finds `Error(Contract, #n)` in a host error / simulation error string and maps it; null if absent or unknown. */
export function stellarContractErrorOf(text: unknown): StellarErrorName | null {
  if (typeof text !== "string") return null;
  const m = /Error\(Contract, #(\d{1,4})\)/.exec(text.slice(0, 64 * 1024));
  return m ? stellarErrorName(Number(m[1])) : null;
}

const MAX_QUOTE_BYTES = 32 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_U53 = BigInt(Number.MAX_SAFE_INTEGER);

export class StellarRegistryError extends Error {
  /** SPEC-CHAINS §10 contract error name when the failure was a contract error, else undefined. */
  readonly contractError: StellarErrorName | undefined;
  constructor(detail: string, contractError?: StellarErrorName) {
    super(`StellarRegistry: ${detail}${contractError ? ` (${contractError})` : ""}`);
    this.name = "StellarRegistryError";
    this.contractError = contractError;
  }
}

// ------------------------------------------------------------------------------------------------ strict ScVal decoding

const bad = (what: string): never => {
  throw new StellarRegistryError(`${what}: malformed reply`);
};

export function scBool(v: xdr.ScVal, what: string): boolean {
  return v.type === "scvBool" ? v.b : bad(what);
}
export function scU32(v: xdr.ScVal, what: string): number {
  return v.type === "scvU32" ? v.u32 : bad(what);
}
/** u64 as a safe integer. */
export function scU64(v: xdr.ScVal, what: string): number {
  if (v.type !== "scvU64") return bad(what);
  const n = BigInt(v.u64);
  return n >= 0n && n <= MAX_U53 ? Number(n) : bad(what);
}
export function scBytes(v: xdr.ScVal, what: string, len?: number, max = MAX_QUOTE_BYTES): Uint8Array {
  if (v.type !== "scvBytes") return bad(what);
  const b = new Uint8Array(v.bytes.value);
  if ((len !== undefined && b.length !== len) || b.length > max) return bad(what);
  return b;
}
export function scString(v: xdr.ScVal, what: string): string {
  if (v.type !== "scvString") return bad(what);
  const bytes = v.str.bytes;
  if (bytes.length > 1024) return bad(what);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return bad(what);
  }
}
export function scAddress(v: xdr.ScVal, what: string): string {
  if (v.type !== "scvAddress") return bad(what);
  try {
    return Address.fromScVal(v).toString();
  } catch {
    return bad(what);
  }
}
export const scIsVoid = (v: xdr.ScVal): boolean => v.type === "scvVoid";
/** A `#[contracttype]` struct: exactly the given symbol keys. */
export function scStruct(v: xdr.ScVal, what: string, keys: readonly string[]): Record<string, xdr.ScVal> {
  if (v.type !== "scvMap") return bad(what);
  const entries = v.map ?? [];
  if (entries.length !== keys.length) return bad(what);
  const out: Record<string, xdr.ScVal> = Object.create(null) as Record<string, xdr.ScVal>;
  for (const e of entries) {
    const k = e.key;
    if (k.type !== "scvSymbol") return bad(what);
    const name = k.sym.toString();
    if (!keys.includes(name) || name in out) return bad(what);
    out[name] = e.val;
  }
  return out;
}
export function scTuple(v: xdr.ScVal, what: string, n: number): xdr.ScVal[] {
  if (v.type !== "scvVec") return bad(what);
  const items = v.vec ?? [];
  return items.length === n ? items : bad(what);
}

export const scvBytesN = (hex: string): xdr.ScVal => xdr.ScVal.scvBytes(Uint8Array.from(Buffer.from(hex, "hex")));
export const scvU64 = (n: number | bigint): xdr.ScVal => xdr.ScVal.scvU64(BigInt(n));

const INSTANCE_KEYS = ["compose_hash", "os_measurement", "x25519", "ed25519", "operator", "registered_at_ms", "expires_at_ms", "next_seq"] as const;
const ANCHOR_KEYS = ["key_hash", "root", "first_seq", "count", "at_ms", "sig"] as const;

/** Decoded `InstanceView` (org not included: it is the live `get_operator`). */
export interface StellarInstanceView {
  compose_hash: string;
  os_measurement: string;
  x25519: string;
  ed25519: string;
  operator: string;
  registered_at_ms: number;
  expires_at_ms: number;
  next_seq: number;
}

export function decodeInstanceView(v: xdr.ScVal): StellarInstanceView | null {
  if (scIsVoid(v)) return null;
  const s = scStruct(v, "get_instance", INSTANCE_KEYS);
  const w = "get_instance";
  const operator = scAddress(s.operator!, w);
  if (!StrKey.isValidEd25519PublicKey(operator)) bad(w); // registrants are accounts (G…)
  return {
    compose_hash: toHex(scBytes(s.compose_hash!, w, 32)),
    os_measurement: toHex(scBytes(s.os_measurement!, w, 32)),
    x25519: toHex(scBytes(s.x25519!, w, 32)),
    ed25519: toHex(scBytes(s.ed25519!, w, 32)),
    operator,
    registered_at_ms: scU64(s.registered_at_ms!, w),
    expires_at_ms: scU64(s.expires_at_ms!, w),
    next_seq: scU64(s.next_seq!, w),
  };
}

/** Decoded `AnchorView` for anchor `id`. */
export function decodeAnchorView(id: number, v: xdr.ScVal): AnchorRecord | null {
  if (scIsVoid(v)) return null;
  const w = "get_anchor";
  const s = scStruct(v, w, ANCHOR_KEYS);
  return {
    id,
    key_hash: toHex(scBytes(s.key_hash!, w, 32)),
    root: toHex(scBytes(s.root!, w, 32)),
    first_seq: scU64(s.first_seq!, w),
    count: scU64(s.count!, w),
    at_ms: scU64(s.at_ms!, w),
    sig: toHex(scBytes(s.sig!, w, 64)),
  };
}

/** `C…` strkey from `"stellar:C…"` or a bare `C…`; throws PlrError E_BAD_INPUT. */
export function stellarContractAddress(id: unknown): string {
  if (typeof id !== "string") throw new PlrError("E_BAD_INPUT", "stellar registry id");
  const c = id.startsWith("stellar:") ? id.slice(8) : id;
  if (!StrKey.isValidContract(c)) throw new PlrError("E_BAD_INPUT", "stellar registry must be a C… contract strkey");
  return c;
}

// ------------------------------------------------------------------------------------------------ reader

export interface StellarRegistryOptions {
  /** Soroban RPC URL (https, or http to a loopback host only), e.g. http://localhost:8000/rpc. */
  rpcUrl: string;
  networkPassphrase: string;
  /** Registry contract: `C…` strkey or the SPEC-CHAINS §3 `stellar:C…` contractId. */
  contract: string;
  /** Per-call timeout (default 10 s). */
  timeoutMs?: number;
  /** Clock for expiry (default Date.now). */
  now?: () => number;
}

export function isStellarPassphrase(p: unknown): p is string {
  return typeof p === "string" && p.length >= 1 && p.length <= 256 && /^[\x20-\x7e]+$/.test(p);
}

export class StellarRegistry implements RegistryReader {
  readonly chain = "stellar";
  /** Tier B: the quote signature is not verified on-chain (SPEC-CHAINS §1). */
  readonly verifiesOnChain = false;
  readonly contractId: string;
  readonly contractAddress: string;
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
  readonly #server: rpc.Server;
  readonly #contract: Contract;
  readonly #timeoutMs: number;
  readonly #now: () => number;

  constructor(o: StellarRegistryOptions) {
    if (typeof o !== "object" || o === null) throw new PlrError("E_BAD_INPUT", "StellarRegistry options required");
    const url = checkRpcUrl(o.rpcUrl);
    if (!isStellarPassphrase(o.networkPassphrase)) throw new PlrError("E_BAD_INPUT", "bad networkPassphrase");
    this.contractAddress = stellarContractAddress(o.contract);
    const timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) throw new PlrError("E_BAD_INPUT", "bad timeoutMs");
    if (o.now !== undefined && typeof o.now !== "function") throw new PlrError("E_BAD_INPUT", "bad now");
    this.contractId = `stellar:${this.contractAddress}`;
    this.rpcUrl = url.href;
    this.networkPassphrase = o.networkPassphrase;
    this.#timeoutMs = timeoutMs;
    this.#now = o.now ?? Date.now;
    this.#server = new rpc.Server(url.href, { allowHttp: url.protocol === "http:", timeout: timeoutMs });
    this.#contract = new Contract(this.contractAddress);
  }

  /** Read-only invocation via `simulateTransaction`; returns the raw return value. Rejects on any failure. */
  async view(method: string, args: xdr.ScVal[] = []): Promise<xdr.ScVal> {
    const tx = new TransactionBuilder(new Account(STELLAR_NULL_ACCOUNT, "0"), { fee: "100", networkPassphrase: this.networkPassphrase })
      .addOperation(this.#contract.call(method, ...args))
      .setTimeout(0)
      .build();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new StellarRegistryError(`${method}: timeout`)), this.#timeoutMs);
      timer.unref?.();
    });
    let sim: rpc.Api.SimulateTransactionResponse;
    try {
      sim = await Promise.race([this.#server.simulateTransaction(tx), timeout]);
    } catch (e) {
      if (e instanceof StellarRegistryError) throw e;
      throw new StellarRegistryError(`${method}: RPC failed`);
    } finally {
      clearTimeout(timer);
    }
    if (rpc.Api.isSimulationError(sim)) {
      throw new StellarRegistryError(`${method}: simulation failed`, stellarContractErrorOf(sim.error) ?? undefined);
    }
    const ret = (sim as rpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (ret === undefined || !xdr.ScVal.is(ret)) throw new StellarRegistryError(`${method}: no result`);
    return ret;
  }

  async getRoot(): Promise<RegistryRoot> {
    const [k, p] = scTuple(await this.view("get_root"), "get_root", 2) as [xdr.ScVal, xdr.ScVal];
    const kind = scU32(k, "get_root");
    if (kind !== 1 && kind !== 2) bad("get_root");
    return { kind: kind === 1 ? "MOCK" : "INTEL", p256: toHex(scBytes(p, "get_root", 64)) };
  }

  async isComposeAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false; // the contract never allows malformed or zero hashes
    return scBool(await this.view("is_compose_allowed", [scvBytesN(h)]), "is_compose_allowed");
  }

  async isOsAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    return scBool(await this.view("is_os_allowed", [scvBytesN(h)]), "is_os_allowed");
  }

  /** `get_operator(op)`: the live owner-approved org of a `G…` account, or null. */
  async getOperator(account: string): Promise<string | null> {
    if (typeof account !== "string" || !StrKey.isValidEd25519PublicKey(account)) return null;
    const v = await this.view("get_operator", [new Address(account).toScVal()]);
    if (scIsVoid(v)) return null;
    const org = scString(v, "get_operator");
    return isOrgId(org) ? org : bad("get_operator");
  }

  async getInstance(keyHash: string): Promise<InstanceRecord | null> {
    if (!isHash32(keyHash)) return null;
    const i = decodeInstanceView(await this.view("get_instance", [scvBytesN(keyHash)]));
    if (i === null || i.expires_at_ms <= this.#now()) return null;
    if (!isHash32(i.compose_hash) || !isHash32(i.os_measurement)) bad("get_instance");
    // SPEC-CHAINS §1: tier B accepts instance records only from operators the owner currently approves.
    const org_id = await this.getOperator(i.operator);
    if (org_id === null) return null;
    return { ...i, org_id };
  }

  async getAnchor(id: number): Promise<AnchorRecord | null> {
    if (!Number.isSafeInteger(id) || id < 0) return null;
    const a = decodeAnchorView(id, await this.view("get_anchor", [scvU64(id)]));
    if (a !== null && !isHash32(a.key_hash)) bad("get_anchor");
    return a;
  }

  async anchorCount(): Promise<number> {
    return scU64(await this.view("anchor_count"), "anchor_count");
  }

  /** Tier B: the registration quote stored on-chain (`offered` ignored, SPEC-CHAINS §2), or null. */
  async getRegistrationQuote(keyHash: string, _offered?: Uint8Array): Promise<Uint8Array | null> {
    if (!isHash32(keyHash)) return null;
    const v = await this.view("get_registration_quote", [scvBytesN(keyHash)]);
    if (scIsVoid(v)) return null;
    const q = scBytes(v, "get_registration_quote");
    return q.length === 0 ? null : q;
  }

  /** `contract_id()` as the contract reports it (diagnostics; must equal {@link contractId}). */
  async onChainContractId(): Promise<string> {
    return scString(await this.view("contract_id"), "contract_id");
  }
}

/** Maps a contract error name to a PlrError code where one exists (E_UNAUTHORIZED / E_ZERO_HASH have none). */
export function plrCodeOfStellarError(name: StellarErrorName): PlrErrorCode | null {
  return name === "E_UNAUTHORIZED" || name === "E_ZERO_HASH" ? null : name;
}
