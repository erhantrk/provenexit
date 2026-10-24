/**
 * Stellar Soroban tier-B registry writer (SPEC-CHAINS §4, §10; contract in contracts/stellar).
 *
 * Writes (`register_instance`, `anchor_receipts`) are invocations whose source account is the operator itself
 * (`operator.require_auth()` is satisfied by source-account authorization): build → `simulateTransaction` (footprint,
 * resource fee, auth; a contract error is reported here already) → sign → `sendTransaction` → poll `getTransaction`
 * until SUCCESS / FAILED, every wait bounded. Sequence races with another process using the same operator account
 * (router + exit) are retried with a fresh sequence number. Reads are simulations, like the client reader's.
 *
 * Refresh: the Anchorer re-registers periodically; the contract refreshes the expiry of the first registrant's record
 * (keeping `next_seq`) and replaces the stored quote. Read-back: `getInstanceOperator` returns the on-chain operator.
 *
 * Archived state (protocol ≥ 23): when a write's simulation carries a restore preamble (entries such as an
 * allowlisted compose hash or an operator approval outlived their TTL), the writer submits a RestoreFootprint
 * transaction first and re-simulates (at most {@link MAX_RESTORES} per invocation). Views use the simulated result.
 *
 * Errors: contract errors become PlrError with the SPEC-CHAINS §10 code where the code exists in `@plr/shared`
 * (`E_SEQ`, `E_INSTANCE_NOT_REGISTERED`, …); `E_UNAUTHORIZED` / `E_ZERO_HASH` become a {@link StellarContractError}
 * whose message carries the code (so `codeOf` logs it). Everything else is E_REGISTRY_UNAVAILABLE without
 * node-supplied text. The secret key is never logged or included in errors.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { Account, Address, Contract, Keypair, Operation, StrKey, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import {
  PlrError, fromHex, isHex, isPlrErrorCode, keyHash, osMeasurement, parseQuote, registrationReportData, toHex, utf8,
} from "@plr/shared";
import { bad, type Env } from "../config.js";
import { isUint, type AnchorArgs, type AnchorView, type RegisterArgs, type RegistryWriter } from "../registry-writer.js";

/** RestoreFootprint transactions per invocation before giving up (E_REGISTRY_UNAVAILABLE). */
const MAX_RESTORES = 2;

/** Source of read-only simulations (all-zero ed25519 key; never needs to exist). */
const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

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

/** Contract error name from `Error(Contract, #n)` in a host / simulation error string, else null. */
export function stellarContractErrorOf(text: unknown): (typeof STELLAR_ERRORS)[number] | null {
  if (typeof text !== "string") return null;
  const m = /Error\(Contract, #(\d{1,4})\)/.exec(text.slice(0, 64 * 1024));
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 1 && n <= STELLAR_ERRORS.length ? STELLAR_ERRORS[n - 1]! : null;
}

/** A contract error without a `@plr/shared` code (E_UNAUTHORIZED, E_ZERO_HASH). */
export class StellarContractError extends Error {
  constructor(readonly code: string, method: string) {
    super(`${code}: stellar ${method}`);
    this.name = "StellarContractError";
  }
}

function contractError(name: string, method: string): Error {
  return isPlrErrorCode(name) ? new PlrError(name, `stellar ${method}`) : new StellarContractError(name, method);
}

const unavailable = (d: string): never => {
  throw new PlrError("E_REGISTRY_UNAVAILABLE", `stellar ${d}`);
};
const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));
const malformed = (what: string): never => {
  throw new PlrError("E_BAD_RESPONSE", `stellar ${what}`);
};

// ------------------------------------------------------------------------------------------------ config (PLR_STELLAR_*)

export interface StellarConfig {
  /** Soroban RPC URL (http/https). */
  rpcUrl: string;
  networkPassphrase: string;
  /** Registry contract `C…` strkey. */
  registry: string;
  /** Operator secret seed `S…` (validated). */
  key: string;
}

export const isStellarPassphrase = (p: unknown): p is string =>
  typeof p === "string" && p.length >= 1 && p.length <= 256 && /^[\x20-\x7e]+$/.test(p);

/**
 * SPEC-CHAINS §10 instance env: all of PLR_STELLAR_RPC, PLR_STELLAR_PASSPHRASE, the registry (`registryVar`, default
 * PLR_STELLAR_REGISTRY; the VPN exit uses PLR_STELLAR_VPN_REGISTRY when set) and PLR_STELLAR_KEY, or none (→ null).
 * @throws PlrError E_BAD_INPUT if partially set or invalid (the message names the variable, never its value)
 */
export function loadStellar(env: Env, registryVar: string = "PLR_STELLAR_REGISTRY"): StellarConfig | null {
  const vars = ["PLR_STELLAR_RPC", "PLR_STELLAR_PASSPHRASE", registryVar, "PLR_STELLAR_KEY"] as const;
  const set = vars.filter((k) => (env[k] ?? "") !== "");
  if (set.length === 0) return null;
  if (set.length !== vars.length) bad(`Stellar (PLR_STELLAR_RPC, PLR_STELLAR_PASSPHRASE, ${registryVar}, PLR_STELLAR_KEY must be set together)`);
  const rpcUrl = env.PLR_STELLAR_RPC!;
  if (rpcUrl.length > 2048) bad("PLR_STELLAR_RPC");
  let u: URL;
  try {
    u = new URL(rpcUrl);
  } catch {
    return bad("PLR_STELLAR_RPC");
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username !== "" || u.password !== "") bad("PLR_STELLAR_RPC");
  const networkPassphrase = env.PLR_STELLAR_PASSPHRASE!;
  if (!isStellarPassphrase(networkPassphrase)) bad("PLR_STELLAR_PASSPHRASE");
  const registry = env[registryVar]!;
  if (!StrKey.isValidContract(registry)) bad(registryVar);
  const key = env.PLR_STELLAR_KEY!;
  if (!StrKey.isValidEd25519SecretSeed(key)) bad("PLR_STELLAR_KEY");
  return { rpcUrl, networkPassphrase, registry, key };
}

// ------------------------------------------------------------------------------------------------ ScVal

const scvBytesN = (hex: string): xdr.ScVal => xdr.ScVal.scvBytes(Uint8Array.from(Buffer.from(hex, "hex")));
const scvU64 = (n: number): xdr.ScVal => xdr.ScVal.scvU64(BigInt(n));

function u64Of(v: xdr.ScVal | undefined, what: string): number {
  if (v === undefined || v.type !== "scvU64") return malformed(what);
  return v.u64 >= 0n && v.u64 <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v.u64) : malformed(what);
}
function bytesOf(v: xdr.ScVal | undefined, len: number, what: string): string {
  if (v === undefined || v.type !== "scvBytes" || v.bytes.value.length !== len) return malformed(what);
  return toHex(new Uint8Array(v.bytes.value));
}
function structOf(v: xdr.ScVal, keys: readonly string[], what: string): Map<string, xdr.ScVal> {
  if (v.type !== "scvMap") return malformed(what);
  const out = new Map<string, xdr.ScVal>();
  for (const e of v.map ?? []) {
    if (e.key.type !== "scvSymbol") return malformed(what);
    const k = e.key.sym.toString();
    if (!keys.includes(k) || out.has(k)) return malformed(what);
    out.set(k, e.val);
  }
  return out.size === keys.length ? out : malformed(what);
}
const INSTANCE_KEYS = ["compose_hash", "os_measurement", "x25519", "ed25519", "operator", "registered_at_ms", "expires_at_ms", "next_seq"];
const ANCHOR_KEYS = ["key_hash", "root", "first_seq", "count", "at_ms", "sig"];

// ------------------------------------------------------------------------------------------------ writer

export interface StellarWriterOptions {
  rpcUrl: string;
  networkPassphrase: string;
  /** Registry `C…` strkey. */
  registry: string;
  /** Operator secret seed `S…`. */
  key: string;
  /** Per-RPC-call timeout (default 15 s). */
  timeoutMs?: number;
  /** Max wait for a submitted transaction (default 60 s). */
  confirmTimeoutMs?: number;
  /** Poll period (default 500 ms). */
  pollMs?: number;
  /** Submissions tried on sequence races / TRY_AGAIN_LATER (default 6). */
  maxSubmitAttempts?: number;
  /** Transaction validity window in seconds (default 120). */
  txTimeoutSec?: number;
  /** Inclusion fee in stroops on top of the simulated resource fee (default 1000). */
  inclusionFee?: number;
}

export class StellarRegistryWriter implements RegistryWriter {
  readonly contractId: string;
  readonly operatorId: string;
  readonly registry: string;
  readonly #server: rpc.Server;
  readonly #contract: Contract;
  readonly #kp: Keypair;
  readonly #passphrase: string;
  readonly #timeoutMs: number;
  readonly #confirmTimeoutMs: number;
  readonly #pollMs: number;
  readonly #maxAttempts: number;
  readonly #txTimeoutSec: number;
  readonly #fee: string;
  /** Serialises this process's submissions (one sequence number at a time). */
  #queue: Promise<unknown> = Promise.resolve();
  #closed = false;

  constructor(o: StellarWriterOptions) {
    let u: URL;
    try {
      u = new URL(o.rpcUrl);
    } catch {
      throw new PlrError("E_BAD_INPUT", "stellar rpc url");
    }
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username !== "" || u.password !== "") throw new PlrError("E_BAD_INPUT", "stellar rpc url");
    if (!isStellarPassphrase(o.networkPassphrase)) throw new PlrError("E_BAD_INPUT", "stellar passphrase");
    if (!StrKey.isValidContract(o.registry)) throw new PlrError("E_BAD_INPUT", "stellar registry");
    if (typeof o.key !== "string" || !StrKey.isValidEd25519SecretSeed(o.key)) throw new PlrError("E_BAD_INPUT", "stellar key");
    const n = (v: number | undefined, def: number, min: number, max: number, what: string): number => {
      const x = v ?? def;
      if (!isUint(x) || x < min || x > max) throw new PlrError("E_BAD_INPUT", `stellar writer ${what}`);
      return x;
    };
    this.#timeoutMs = n(o.timeoutMs, 15_000, 1, 600_000, "timeoutMs");
    this.#confirmTimeoutMs = n(o.confirmTimeoutMs, 60_000, 1, 900_000, "confirmTimeoutMs");
    this.#pollMs = n(o.pollMs, 500, 1, 60_000, "pollMs");
    this.#maxAttempts = n(o.maxSubmitAttempts, 6, 1, 100, "maxSubmitAttempts");
    this.#txTimeoutSec = n(o.txTimeoutSec, 120, 10, 3600, "txTimeoutSec");
    this.#fee = String(n(o.inclusionFee, 1000, 100, 100_000_000, "inclusionFee"));
    this.#kp = Keypair.fromSecret(o.key);
    this.#passphrase = o.networkPassphrase;
    this.registry = o.registry;
    this.contractId = `stellar:${o.registry}`;
    this.operatorId = this.#kp.publicKey();
    this.#server = new rpc.Server(u.href, { allowHttp: u.protocol === "http:", timeout: this.#timeoutMs });
    this.#contract = new Contract(o.registry);
  }

  close(): void {
    this.#closed = true;
  }

  // ----------------------------------------------------------------------------------------------- RPC plumbing

  async #rpc<T>(what: string, f: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new PlrError("E_REGISTRY_UNAVAILABLE", `stellar ${what}: timeout`)), this.#timeoutMs);
      timer.unref?.();
    });
    try {
      return await Promise.race([f(), timeout]);
    } catch (e) {
      if (e instanceof PlrError) throw e;
      throw new PlrError("E_REGISTRY_UNAVAILABLE", `stellar ${what}`);
    } finally {
      clearTimeout(timer);
    }
  }

  #build(source: Account, method: string, args: xdr.ScVal[]) {
    return new TransactionBuilder(source, { fee: this.#fee, networkPassphrase: this.#passphrase })
      .addOperation(this.#contract.call(method, ...args))
      .setTimeout(this.#txTimeoutSec)
      .build();
  }

  /**
   * Simulates `method`; a contract error throws its mapped error. Returns the simulation. A simulation that needs
   * archived entries restored first (protocol ≥ 23: executed as if they were live) is returned too; callers that
   * submit must restore them first ({@link StellarRegistryWriter.#restore}). Archived entries keep their value, so
   * a view may use the result (as the client reader does).
   */
  async #simulate(source: Account, method: string, args: xdr.ScVal[]) {
    const tx = this.#build(source, method, args);
    const sim = await this.#rpc(`simulate ${method}`, () => this.#server.simulateTransaction(tx));
    if (rpc.Api.isSimulationError(sim)) {
      const name = stellarContractErrorOf(sim.error);
      if (name !== null) throw contractError(name, method);
      return unavailable(`${method}: simulation failed`);
    }
    return { tx, sim };
  }

  /**
   * Submits a RestoreFootprint transaction for the archived entries of a simulation's restore preamble (signed by
   * the operator, resource fee and footprint from the preamble) and waits until it is final (bounded).
   */
  async #restore(preamble: { minResourceFee: string; transactionData: { build(): xdr.SorobanTransactionData } }, method: string): Promise<void> {
    const resourceFee = /^\d{1,15}$/.test(preamble.minResourceFee) ? Number(preamble.minResourceFee) : NaN;
    if (!Number.isSafeInteger(resourceFee)) return malformed(`${method}: restore preamble`);
    // A fresh account: building the simulated invocation advanced the old object's sequence number.
    const source = await this.#rpc("getAccount", () => this.#server.getAccount(this.operatorId));
    const tx = new TransactionBuilder(source, { fee: String(Number(this.#fee) + resourceFee), networkPassphrase: this.#passphrase })
      .setSorobanData(preamble.transactionData.build())
      .addOperation(Operation.restoreFootprint({}))
      .setTimeout(this.#txTimeoutSec)
      .build();
    tx.sign(this.#kp);
    const sent = await this.#rpc(`send restore for ${method}`, () => this.#server.sendTransaction(tx));
    if (sent.status !== "PENDING" && sent.status !== "DUPLICATE") return unavailable(`${method}: restore rejected`);
    const deadline = Date.now() + this.#confirmTimeoutMs;
    for (;;) {
      const r = await this.#rpc("getTransaction", () => this.#server.getTransaction(sent.hash)).catch(() => null);
      if (r !== null && r.status === rpc.Api.GetTransactionStatus.SUCCESS) return;
      if (r !== null && r.status === rpc.Api.GetTransactionStatus.FAILED) return; // re-simulation decides (a concurrent restore wins too)
      if (this.#closed || Date.now() >= deadline) return unavailable(`${method}: restore not confirmed in time`);
      await sleep(this.#pollMs);
    }
  }

  /** Read-only call. */
  async view(method: string, args: xdr.ScVal[] = []): Promise<xdr.ScVal> {
    const { sim } = await this.#simulate(new Account(NULL_ACCOUNT, "0"), method, args);
    const ret = sim.result?.retval;
    if (ret === undefined || !xdr.ScVal.is(ret)) return malformed(`${method}: no result`);
    return ret;
  }

  /** Signed invocation by the operator; resolves with the return value once the transaction succeeded. */
  invoke(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal | undefined> {
    const run = this.#queue.then(() => this.#invokeInner(method, args));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #invokeInner(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal | undefined> {
    let restores = 0;
    for (let attempt = 0; ; attempt++) {
      if (this.#closed) unavailable("writer closed");
      const account = await this.#rpc("getAccount", () => this.#server.getAccount(this.operatorId));
      const { tx, sim } = await this.#simulate(account, method, args);
      if (rpc.Api.isSimulationRestore(sim)) {
        // Archived entries (e.g. an allowlisted compose hash nobody touched for longer than its TTL): restore them,
        // then simulate again with a fresh sequence number. Bounded: a second preamble after two restores fails.
        if (restores >= MAX_RESTORES) return unavailable(`${method}: archived state still needs a restore`);
        restores++;
        await this.#restore(sim.restorePreamble, method);
        attempt--;
        continue;
      }
      const prepared = rpc.assembleTransaction(tx, sim).build();
      prepared.sign(this.#kp);
      const sent = await this.#rpc(`send ${method}`, () => this.#server.sendTransaction(prepared));
      if (sent.status === "PENDING" || sent.status === "DUPLICATE") {
        const r = await this.#await(sent.hash, method, args);
        if (r === "retry" && attempt + 1 < this.#maxAttempts) continue;
        if (r === "retry") return unavailable(`${method}: failed`);
        return r.value;
      }
      // TRY_AGAIN_LATER, or ERROR (txBadSeq: another process of this operator used the sequence number)
      const code = sent.status === "ERROR" ? sent.errorResult?.result?.type : undefined;
      const retriable = sent.status === "TRY_AGAIN_LATER" || code === "txBadSeq" || code === "txTooLate";
      if (!retriable || attempt + 1 >= this.#maxAttempts) return unavailable(`${method}: rejected${code ? ` (${code})` : ""}`);
      await sleep(this.#pollMs * (attempt + 1));
    }
  }

  /** Polls until the transaction is final. "retry": it failed without a contract error (e.g. a race); re-submit. */
  async #await(hash: string, method: string, args: xdr.ScVal[]): Promise<"retry" | { value: xdr.ScVal | undefined }> {
    const deadline = Date.now() + this.#confirmTimeoutMs;
    for (;;) {
      const r = await this.#rpc("getTransaction", () => this.#server.getTransaction(hash)).catch(() => null);
      if (r !== null && r.status === rpc.Api.GetTransactionStatus.SUCCESS) return { value: r.returnValue };
      if (r !== null && r.status === rpc.Api.GetTransactionStatus.FAILED) {
        // Simulation passed but execution failed (state changed in between): re-simulating reports the contract
        // error if there is one (thrown), otherwise the caller re-submits.
        await this.#simulate(new Account(NULL_ACCOUNT, "0"), method, args);
        return "retry";
      }
      if (this.#closed || Date.now() >= deadline) return unavailable(`${method}: not confirmed in time`);
      await sleep(this.#pollMs);
    }
  }

  // ----------------------------------------------------------------------------------------------- writes

  /**
   * `register_instance(operator, x25519, ed25519, compose_hash, os_measurement, quote)`. The quote must be bound to
   * this registry and operator (checked here first, as the contract does). @throws PlrError
   */
  async registerInstance(a: RegisterArgs): Promise<void> {
    if (!isHex(a.x25519, 32) || !isHex(a.ed25519, 32) || !isHex(a.quote) || a.quote.length === 0 || typeof a.app_compose !== "string") {
      throw new PlrError("E_BAD_INPUT", "register args");
    }
    const xp = fromHex(a.x25519, 32);
    const ep = fromHex(a.ed25519, 32);
    const quote = fromHex(a.quote);
    const report = parseQuote(quote).report;
    if (toHex(report.reportData) !== toHex(registrationReportData(xp, ep, this.contractId, this.operatorId))) {
      throw new PlrError("E_REPORT_DATA", "registration quote not bound to this registry/operator");
    }
    const compose = toHex(sha256(utf8(a.app_compose)));
    const os = toHex(osMeasurement(report));
    await this.invoke("register_instance", [
      new Address(this.operatorId).toScVal(),
      scvBytesN(a.x25519),
      scvBytesN(a.ed25519),
      scvBytesN(compose),
      scvBytesN(os),
      xdr.ScVal.scvBytes(quote),
    ]);
  }

  /** `anchor_receipts(...)`; returns the anchor id. @throws PlrError E_SEQ | E_INSTANCE_NOT_REGISTERED | … */
  async anchorReceipts(a: AnchorArgs): Promise<unknown> {
    if (!isHex(a.key_hash, 32) || !isHex(a.root, 32) || !isHex(a.sig, 64) || !isUint(a.first_seq) || !isUint(a.count) || a.count < 1 || a.count > 10_000) {
      throw new PlrError("E_BAD_INPUT", "anchor args");
    }
    const ret = await this.invoke("anchor_receipts", [
      new Address(this.operatorId).toScVal(),
      scvBytesN(a.key_hash),
      scvBytesN(a.root),
      scvU64(a.first_seq),
      scvU64(a.count),
      scvBytesN(a.sig),
    ]);
    return ret === undefined ? null : u64Of(ret, "anchor_receipts");
  }

  // ----------------------------------------------------------------------------------------------- reads

  async #instance(kh: string): Promise<Map<string, xdr.ScVal> | null> {
    if (!isHex(kh, 32)) return null;
    const v = await this.view("get_instance", [scvBytesN(kh)]);
    if (v.type === "scvVoid") return null;
    return structOf(v, INSTANCE_KEYS, "get_instance");
  }

  async getInstanceNextSeq(kh: string): Promise<number | null> {
    const s = await this.#instance(kh);
    return s === null ? null : u64Of(s.get("next_seq"), "get_instance");
  }

  async getInstanceOperator(kh: string): Promise<string | null> {
    const s = await this.#instance(kh);
    if (s === null) return null;
    const v = s.get("operator");
    if (v === undefined || v.type !== "scvAddress") return malformed("get_instance");
    try {
      return Address.fromScVal(v).toString();
    } catch {
      return malformed("get_instance");
    }
  }

  async anchorCount(): Promise<number> {
    return u64Of(await this.view("anchor_count"), "anchor_count");
  }

  async getAnchor(id: number): Promise<AnchorView | null> {
    if (!isUint(id)) return null;
    const v = await this.view("get_anchor", [scvU64(id)]);
    if (v.type === "scvVoid") return null;
    const s = structOf(v, ANCHOR_KEYS, "get_anchor");
    return {
      id,
      key_hash: bytesOf(s.get("key_hash"), 32, "get_anchor"),
      root: bytesOf(s.get("root"), 32, "get_anchor"),
      first_seq: u64Of(s.get("first_seq"), "get_anchor"),
      count: u64Of(s.get("count"), "get_anchor"),
    };
  }
}

/** Writer from validated {@link StellarConfig}. */
export function createStellarWriter(c: StellarConfig): StellarRegistryWriter {
  return new StellarRegistryWriter({ rpcUrl: c.rpcUrl, networkPassphrase: c.networkPassphrase, registry: c.registry, key: c.key });
}
