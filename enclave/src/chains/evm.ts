/**
 * EVM / Monad tier-B registry writer (SPEC-CHAINS §4, §9) for `contracts/evm/src/PlrRegistry.sol`, with viem.
 *
 * - `registerInstance`: submits `(x25519, ed25519, compose_hash, os_measurement, quote)` signed by the operator key
 *   (`PLR_EVM_KEY`); the contract checks the quote format and its report_data binding to
 *   `registrationNonce(contractId, operator)` (SPEC §5 rev 1.3) and stores the quote. The writer checks the same
 *   binding locally first (a quote clients would reject is never submitted). A refresh is the same call.
 * - `anchorReceipts`: submits `(key_hash, root, first_seq, count, sig)`; returns the anchor id from the
 *   `ReceiptsAnchored` event.
 * - reads (`getInstanceNextSeq`, `getInstanceOperator`, `anchorCount`, `getAnchor`) are `eth_call` views.
 *
 * Every write is first simulated (`eth_call`): a contract revert surfaces as a PlrError with the PLR code of the
 * custom error (SPEC-CHAINS §9) — `E_SEQ` and `E_INSTANCE_NOT_REGISTERED` drive the anchorer's resync/re-register.
 * Then the transaction is sent and its receipt awaited (bounded). Before the first write the writer checks that the
 * node is on the configured chain and that the contract reports this writer's `contractId()`.
 *
 * Nonces: sends are serialized within the process and take the account's `pending` nonce. Other processes may share
 * the operator key (the router and exit of one operator, or a combo's two services), so a nonce collision
 * ("nonce too low", "already known", "replacement transaction underpriced") is retried with a fresh nonce after a
 * short random delay (bounded attempts).
 *
 * Never logs or returns the key; RPC/node error text is never propagated (static PlrError details only).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  parseEventLogs,
  type Account,
  type Address,
  type Chain,
  type Hex,
  type HttpTransport,
  type PublicClient,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { PlrError, fromHex, isHex, keyHash, osMeasurement, parseQuote, registrationReportData, toHex, utf8, type PlrErrorCode } from "@plr/shared";
import { bad, intVar, type Env } from "../config.js";
import { isUint, type AnchorArgs, type AnchorView, type RegisterArgs, type RegistryWriter } from "../registry-writer.js";
import { EVM_REGISTRY_ERRORS, PLR_REGISTRY_ABI, type EvmRegistryErrorName } from "./evm-abi.js";

export { PLR_REGISTRY_ABI, EVM_REGISTRY_ERRORS, type EvmRegistryErrorName } from "./evm-abi.js";

const ANY_CASE_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const KEY_RE = /^(?:0x)?[0-9a-fA-F]{64}$/;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const MAX_REPLY_BYTES = 256 * 1024;

// ------------------------------------------------------------------------------------------------- config

/** EVM registration settings (SPEC-CHAINS §9 `PLR_EVM_*`). */
export interface EvmConfig {
  /** JSON-RPC URL (http/https; optional `user:pass@` for basic auth). */
  rpcUrl: string;
  /** Registry contract address (lowercase). */
  registry: string;
  /** Operator secp256k1 secret (64 hex, optional 0x), validated. */
  key: string;
  /** `PLR_EVM_CHAIN_ID` if set (else the writer asks the node, see {@link EvmRegistryWriter.create}). */
  chainId: number | null;
}

/**
 * EVM registration config: all of PLR_EVM_RPC, the registry address (`registryVar`, default PLR_EVM_REGISTRY; the VPN
 * exit uses PLR_EVM_VPN_REGISTRY) and PLR_EVM_KEY, or none (→ null). PLR_EVM_CHAIN_ID is optional.
 * @throws PlrError E_BAD_INPUT if partially set or invalid
 */
export function loadEvm(env: Env, registryVar: string = "PLR_EVM_REGISTRY"): EvmConfig | null {
  const vars = ["PLR_EVM_RPC", registryVar, "PLR_EVM_KEY"] as const;
  const set = vars.filter((k) => (env[k] ?? "") !== "");
  if (set.length === 0) return null;
  if (set.length !== vars.length) bad(`EVM (PLR_EVM_RPC, ${registryVar}, PLR_EVM_KEY must be set together)`);
  const rpcUrl = env.PLR_EVM_RPC!;
  if (rpcUrl.length > 2048) bad("PLR_EVM_RPC");
  let u: URL;
  try {
    u = new URL(rpcUrl);
  } catch {
    bad("PLR_EVM_RPC");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") bad("PLR_EVM_RPC");
  const registry = env[registryVar]!;
  if (!ANY_CASE_ADDRESS_RE.test(registry) || registry.toLowerCase() === ZERO_ADDRESS) bad(registryVar);
  const key = env.PLR_EVM_KEY!;
  if (!isEvmSecretKey(key)) bad("PLR_EVM_KEY");
  const chainRaw = env.PLR_EVM_CHAIN_ID;
  const chainId = chainRaw === undefined || chainRaw === "" ? null : intVar(env, "PLR_EVM_CHAIN_ID", 0, 1, 9_999_999_999);
  return { rpcUrl, registry: registry.toLowerCase(), key, chainId };
}

/** True for a valid secp256k1 secret key (64 hex, optional `0x`). Never throws. */
export function isEvmSecretKey(k: unknown): k is string {
  if (typeof k !== "string" || !KEY_RE.test(k)) return false;
  try {
    privateKeyToAccount(normKey(k));
    return true;
  } catch {
    return false;
  }
}

function normKey(k: string): Hex {
  return (k.startsWith("0x") ? k.toLowerCase() : `0x${k.toLowerCase()}`) as Hex;
}

// ------------------------------------------------------------------------------------------------- reverts

/** The PLR code of a registry revert (`E_UNAUTHORIZED` / `E_ZERO_HASH` are contract-only names ⇒ E_BAD_INPUT). */
export function plrCodeOfRevert(name: EvmRegistryErrorName): PlrErrorCode {
  return name === "E_UNAUTHORIZED" || name === "E_ZERO_HASH" ? "E_BAD_INPUT" : name;
}

/** The registry custom error a viem error carries (decoded against the registry ABI), else null. Never throws. */
export function evmRevertName(e: unknown): EvmRegistryErrorName | null {
  try {
    if (!(e instanceof BaseError)) return null;
    const r = e.walk((x) => x instanceof ContractFunctionRevertedError);
    if (!(r instanceof ContractFunctionRevertedError)) return null;
    const n = r.data?.errorName;
    return typeof n === "string" && (EVM_REGISTRY_ERRORS as readonly string[]).includes(n) ? (n as EvmRegistryErrorName) : null;
  } catch {
    return null;
  }
}

/** A registry revert as a PlrError; `revert` keeps the contract's error name. */
export class EvmRevertError extends PlrError {
  readonly revert: EvmRegistryErrorName;
  constructor(revert: EvmRegistryErrorName, fn: string) {
    super(plrCodeOfRevert(revert), `${fn} reverted ${revert}`);
    this.name = "EvmRevertError";
    this.revert = revert;
  }
}

/** True for node errors that mean "this nonce is taken" (another sender of the same key won the race). */
export function isNonceConflict(e: unknown): boolean {
  const parts: string[] = [];
  if (e instanceof BaseError) {
    e.walk((x) => {
      if (x instanceof Error) parts.push(x.message, (x as BaseError).details ?? "", (x as BaseError).shortMessage ?? "");
      return false;
    });
  } else if (e instanceof Error) parts.push(e.message);
  const m = parts.join("\n").toLowerCase();
  return /nonce too low|nonce too high|already known|replacement transaction underpriced|nonce has already been used|invalid nonce|known transaction/.test(m);
}

// ------------------------------------------------------------------------------------------------- writer

export interface EvmWriterOptions {
  rpcUrl: string;
  /** Registry address (any case). */
  registry: string;
  /** Operator secp256k1 secret (64 hex, optional 0x). */
  key: string;
  chainId: number;
  /** Per-RPC-call timeout (default 15 s). */
  timeoutMs?: number;
  /** Max wait for a transaction receipt (default 120 s). */
  confirmTimeoutMs?: number;
  /** Receipt polling period (default 250 ms). */
  pollMs?: number;
  /** Send attempts on nonce conflicts (default 8). */
  maxSendAttempts?: number;
  /** Random source for retry jitter, in [0, 1) (default Math.random). */
  random?: () => number;
}

const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));
const unavailable = (d: string): never => {
  throw new PlrError("E_REGISTRY_UNAVAILABLE", d);
};

function transportOf(rpcUrl: string, timeoutMs: number): HttpTransport {
  let u: URL;
  try {
    u = new URL(rpcUrl);
  } catch {
    throw new PlrError("E_BAD_INPUT", "evm rpc url");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new PlrError("E_BAD_INPUT", "evm rpc url");
  // fetch refuses URLs with credentials: move them to a basic-auth header.
  const headers: Record<string, string> = {};
  if (u.username !== "" || u.password !== "") {
    headers.authorization = `Basic ${Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")}`;
    u.username = "";
    u.password = "";
  }
  return http(u.toString(), { timeout: timeoutMs, retryCount: 1, retryDelay: 150, maxResponseBodySize: MAX_REPLY_BYTES, batch: false, fetchOptions: { headers } });
}

export class EvmRegistryWriter implements RegistryWriter {
  readonly contractId: string;
  readonly operatorId: string;
  readonly chainId: number;
  /** Registry address (lowercase). */
  readonly registry: string;
  readonly #account: Account;
  readonly #public: PublicClient<HttpTransport, Chain>;
  readonly #wallet: WalletClient<HttpTransport, Chain, Account>;
  readonly #confirmTimeoutMs: number;
  readonly #pollMs: number;
  readonly #maxAttempts: number;
  readonly #random: () => number;
  #identity: Promise<void> | null = null;
  #queue: Promise<unknown> = Promise.resolve();
  #closed = false;

  constructor(o: EvmWriterOptions) {
    if (typeof o !== "object" || o === null) throw new PlrError("E_BAD_INPUT", "evm writer options");
    if (typeof o.registry !== "string" || !ANY_CASE_ADDRESS_RE.test(o.registry) || o.registry.toLowerCase() === ZERO_ADDRESS) {
      throw new PlrError("E_BAD_INPUT", "evm registry address");
    }
    if (!isEvmSecretKey(o.key)) throw new PlrError("E_BAD_INPUT", "evm key");
    if (typeof o.chainId !== "number" || !Number.isSafeInteger(o.chainId) || o.chainId < 1) throw new PlrError("E_BAD_INPUT", "evm chain id");
    const n = (v: number | undefined, def: number, min: number, max: number, what: string): number => {
      const x = v ?? def;
      if (!isUint(x) || x < min || x > max) throw new PlrError("E_BAD_INPUT", `evm writer ${what}`);
      return x;
    };
    const timeoutMs = n(o.timeoutMs, 15_000, 1, 600_000, "timeoutMs");
    this.#confirmTimeoutMs = n(o.confirmTimeoutMs, 120_000, 1, 900_000, "confirmTimeoutMs");
    this.#pollMs = n(o.pollMs, 250, 1, 60_000, "pollMs");
    this.#maxAttempts = n(o.maxSendAttempts, 8, 1, 100, "maxSendAttempts");
    this.#random = o.random ?? Math.random;
    this.chainId = o.chainId;
    this.registry = o.registry.toLowerCase();
    this.contractId = `evm:${o.chainId}:${this.registry}`;
    this.#account = privateKeyToAccount(normKey(o.key));
    this.operatorId = this.#account.address.toLowerCase();
    const chain = defineChain({
      id: o.chainId,
      name: `evm-${o.chainId}`,
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [] } },
    });
    const transport = transportOf(o.rpcUrl, timeoutMs);
    this.#public = createPublicClient({ chain, transport, pollingInterval: this.#pollMs });
    this.#wallet = createWalletClient({ chain, transport, account: this.#account, pollingInterval: this.#pollMs });
  }

  /** Builds a writer, asking the node for its chain id when `chainId` is not given. @throws PlrError */
  static async create(o: Omit<EvmWriterOptions, "chainId"> & { chainId?: number | null }): Promise<EvmRegistryWriter> {
    let chainId = o.chainId ?? null;
    if (chainId === null) {
      const probe = createPublicClient({ transport: transportOf(o.rpcUrl, o.timeoutMs ?? 15_000) });
      try {
        chainId = await probe.getChainId();
      } catch {
        return unavailable("eth_chainId");
      }
    }
    return new EvmRegistryWriter({ ...o, chainId });
  }

  close(): void {
    this.#closed = true;
  }

  // ----------------------------------------------------------------------------------------------- reads

  async #read(fn: string, args: readonly unknown[], allow: readonly EvmRegistryErrorName[] = []): Promise<unknown> {
    try {
      return await this.#public.readContract({ address: this.registry as Address, abi: PLR_REGISTRY_ABI, functionName: fn as never, args: args as never });
    } catch (e) {
      const r = evmRevertName(e);
      if (r !== null && allow.includes(r)) return new EvmRevertError(r, fn);
      throw new PlrError("E_REGISTRY_UNAVAILABLE", `evm ${fn}`);
    }
  }

  /** Node on the configured chain and the contract's own `contractId()` equal to ours (checked once; retried on failure). */
  #checkIdentity(): Promise<void> {
    this.#identity ??= (async () => {
      let id: number;
      try {
        id = await this.#public.getChainId();
      } catch {
        return unavailable("evm eth_chainId");
      }
      if (id !== this.chainId) throw new PlrError("E_BAD_INPUT", "evm node is on another chain");
      const cid = await this.#read("contractId", []);
      if (cid !== this.contractId) throw new PlrError("E_BAD_INPUT", "evm contract is not this registry");
    })().catch((e: unknown) => {
      this.#identity = null;
      throw e;
    });
    return this.#identity;
  }

  async #instance(kh: string): Promise<{ operator: string; nextSeq: number; expiresAtMs: number } | null> {
    if (!isHex(kh, 32)) throw new PlrError("E_BAD_INPUT", "key hash");
    const v = await this.#read("getInstance", [`0x${kh}`]);
    if (!Array.isArray(v) || v.length !== 9 || typeof v[0] !== "boolean") return unavailable("evm getInstance: malformed");
    if (!v[0]) return null;
    const op = v[5];
    const next = v[8];
    const exp = v[7];
    if (typeof op !== "string" || !ANY_CASE_ADDRESS_RE.test(op)) return unavailable("evm getInstance: malformed operator");
    return { operator: op.toLowerCase(), nextSeq: safeInt(next, "getInstance"), expiresAtMs: safeInt(exp, "getInstance") };
  }

  async getInstanceNextSeq(kh: string): Promise<number | null> {
    return (await this.#instance(kh))?.nextSeq ?? null;
  }

  async getInstanceOperator(kh: string): Promise<string | null> {
    return (await this.#instance(kh))?.operator ?? null;
  }

  async anchorCount(): Promise<number> {
    return safeInt(await this.#read("anchorCount", []), "anchorCount");
  }

  async getAnchor(id: number): Promise<AnchorView | null> {
    if (!isUint(id)) return null;
    const v = await this.#read("getAnchor", [BigInt(id)], ["E_BAD_INPUT"]);
    if (v instanceof EvmRevertError) return null;
    if (!Array.isArray(v) || v.length !== 6) return unavailable("evm getAnchor: malformed");
    const [kh, root, first, count] = v as unknown[];
    if (!isB32(kh) || !isB32(root)) return unavailable("evm getAnchor: malformed");
    return { id, key_hash: kh.slice(2).toLowerCase(), root: root.slice(2).toLowerCase(), first_seq: safeInt(first, "getAnchor"), count: safeInt(count, "getAnchor") };
  }

  // ----------------------------------------------------------------------------------------------- writes

  /** @throws PlrError (E_REPORT_DATA locally; contract reverts mapped; E_REGISTRY_UNAVAILABLE on transport issues) */
  async registerInstance(a: RegisterArgs): Promise<void> {
    if (typeof a !== "object" || a === null || !isHex(a.x25519, 32) || !isHex(a.ed25519, 32) || !isHex(a.quote) || typeof a.app_compose !== "string") {
      throw new PlrError("E_BAD_INPUT", "register args");
    }
    const xp = fromHex(a.x25519, 32);
    const ep = fromHex(a.ed25519, 32);
    const quote = fromHex(a.quote);
    const report = parseQuote(quote).report;
    if (toHex(report.reportData) !== toHex(registrationReportData(xp, ep, this.contractId, this.operatorId))) {
      throw new PlrError("E_REPORT_DATA", "registration quote not bound to this registry/operator");
    }
    void keyHash(xp, ep); // validates the key lengths (the contract derives the key hash itself)
    const compose = toHex(sha256(utf8(a.app_compose)));
    const os = toHex(osMeasurement(report));
    await this.#send("registerInstance", [`0x${a.x25519}`, `0x${a.ed25519}`, `0x${compose}`, `0x${os}`, `0x${a.quote}`]);
  }

  /** Returns the anchor id (from the `ReceiptsAnchored` event), or null if the event is missing. */
  async anchorReceipts(a: AnchorArgs): Promise<unknown> {
    if (
      typeof a !== "object" || a === null || !isHex(a.key_hash, 32) || !isHex(a.root, 32) || !isHex(a.sig, 64) ||
      !isUint(a.first_seq) || !isUint(a.count) || a.count < 1 || a.count > 10_000
    ) {
      throw new PlrError("E_BAD_INPUT", "anchor args");
    }
    const logs = await this.#send("anchorReceipts", [`0x${a.key_hash}`, `0x${a.root}`, BigInt(a.first_seq), BigInt(a.count), `0x${a.sig}`]);
    for (const l of parseEventLogs({ abi: PLR_REGISTRY_ABI, eventName: "ReceiptsAnchored", logs, strict: true })) {
      if (l.address.toLowerCase() !== this.registry) continue;
      if (l.args.keyHash.slice(2).toLowerCase() !== a.key_hash || l.args.firstSeq !== BigInt(a.first_seq)) continue;
      return l.args.id <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(l.args.id) : null;
    }
    return null;
  }

  /** Serialized: simulate → send (nonce-conflict retries) → receipt. Returns the receipt logs. */
  #send(fn: "registerInstance" | "anchorReceipts", args: readonly unknown[]) {
    const run = this.#queue.then(() => this.#sendInner(fn, args));
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async #simulate(fn: string, args: readonly unknown[]): Promise<void> {
    try {
      await this.#public.simulateContract({ account: this.#account, address: this.registry as Address, abi: PLR_REGISTRY_ABI, functionName: fn as never, args: args as never });
    } catch (e) {
      const r = evmRevertName(e);
      if (r !== null) throw new EvmRevertError(r, fn);
      unavailable(`evm ${fn}: simulation failed`);
    }
  }

  async #sendInner(fn: "registerInstance" | "anchorReceipts", args: readonly unknown[]) {
    if (this.#closed) unavailable("evm writer closed");
    await this.#checkIdentity();
    for (let attempt = 1; ; attempt++) {
      await this.#simulate(fn, args);
      let hash: Hex;
      try {
        const nonce = await this.#public.getTransactionCount({ address: this.#account.address, blockTag: "pending" });
        hash = await this.#wallet.writeContract({ address: this.registry as Address, abi: PLR_REGISTRY_ABI, functionName: fn as never, args: args as never, nonce } as never);
      } catch (e) {
        const r = evmRevertName(e);
        if (r !== null) throw new EvmRevertError(r, fn);
        if (isNonceConflict(e) && attempt < this.#maxAttempts && !this.#closed) {
          await sleep(50 + Math.floor(clamp01(this.#random()) * 250 * attempt));
          continue;
        }
        return unavailable(`evm ${fn}: send failed`);
      }
      let receipt;
      try {
        receipt = await this.#public.waitForTransactionReceipt({ hash, timeout: this.#confirmTimeoutMs, pollingInterval: this.#pollMs, retryCount: 3 });
      } catch {
        return unavailable(`evm ${fn}: not confirmed in time`);
      }
      if (receipt.status !== "success") {
        // State changed between simulation and inclusion (e.g. another anchor won): report the current reason.
        await this.#simulate(fn, args);
        return unavailable(`evm ${fn}: reverted`);
      }
      return receipt.logs;
    }
  }
}

function clamp01(r: number): number {
  return Number.isFinite(r) && r >= 0 && r < 1 ? r : 0;
}

function isB32(v: unknown): v is string {
  return typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
}

function safeInt(v: unknown, what: string): number {
  if (typeof v !== "bigint" || v < 0n || v > BigInt(Number.MAX_SAFE_INTEGER)) return unavailable(`evm ${what}: malformed value`);
  return Number(v);
}

/** {@link EvmRegistryWriter} from {@link loadEvm} settings (needs `chainId`; else use {@link EvmRegistryWriter.create}). */
export function evmWriterOf(c: EvmConfig): EvmRegistryWriter {
  if (c.chainId === null) throw new PlrError("E_BAD_INPUT", "PLR_EVM_CHAIN_ID required for a synchronous writer");
  return new EvmRegistryWriter({ rpcUrl: c.rpcUrl, registry: c.registry, key: c.key, chainId: c.chainId });
}
