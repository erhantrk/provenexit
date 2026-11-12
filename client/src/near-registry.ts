/**
 * {@link RegistryReader} backed by the NEAR registry contract (SPEC §7, §10) through JSON-RPC view calls.
 *
 * Every reply is validated strictly; any transport error, RPC error, timeout or malformed reply rejects, so
 * `verifyAttestation` maps it to E_REGISTRY_UNAVAILABLE (fail closed).
 *
 * TRUST: view results are not accompanied by state proofs, so whoever answers these calls decides checks 3, 8 and
 * 9 of `verifyAttestation`. The network is untrusted (SPEC §1), therefore every endpoint must be reached over an
 * authenticated channel: `https:` for any remote host; plain `http:` only to a loopback address (a local node /
 * sandbox, or a local light client).
 *
 * SEVERAL ENDPOINTS: `rpcUrl` may list several endpoints, separated by commas (ideally run by different
 * operators). Then every query (each contract view and the `view_account` of the code pin) is sent to all of them
 * in parallel and is used only if ALL of them answer and ALL answers are the same:
 *  - what is compared is the answer itself (the bytes the contract returned; for `view_account` the `code_hash`),
 *    not the block height / block hash next to it, because endpoints answer at slightly different blocks;
 *  - answers differ ⇒ the query is asked once more after {@link RPC_DISAGREE_RETRY_MS} (an owner call that landed
 *    between two endpoints' latest blocks looks like a disagreement for a moment); still different ⇒ rejects with
 *    {@link RegistryRpcDisagreeError} (`E_REGISTRY_RPC_DISAGREE`);
 *  - an endpoint that is down, slow or answers garbage ⇒ rejects like a single unreachable endpoint
 *    (`E_REGISTRY_UNAVAILABLE`). This is fail closed on purpose: a "2 of 3 is enough" rule would let an attacker
 *    who can silence the honest endpoints choose which ones get a say. Two answers that differ win over a third
 *    endpoint being down (the disagreement is what gets reported).
 * So a single lying or compromised endpoint can make the client refuse, but cannot make it accept. What is still
 * trusted: that the listed endpoints do not all lie in the same way (they collude, or share one upstream node).
 * With one endpoint nothing is compared and that endpoint is trusted as before.
 *
 * CODE PIN: with `codeHash` set, the registry account's on-chain `code_hash` (`view_account`) must equal that pin
 * before any view result is used; a different hash rejects with {@link RegistryCodeHashError}
 * (`E_REGISTRY_CODE_HASH`). A passed check is reused for {@link CODE_HASH_TTL_MS}; a failed or unanswered one is
 * never reused.
 */
import { JsonRpcProvider } from "near-api-js";
import {
  PlrError,
  isAnchorRecord,
  isHash32,
  isInstanceRecord,
  isOrgId,
  isRegistryRoot,
  parseJsonIntegers,
  type AnchorRecord,
  type InstanceRecord,
  type RegistryReader,
  type RegistryRoot,
} from "@plr/shared";

export type NearFinality = "optimistic" | "near-final" | "final";

export interface NearRegistryOptions {
  /** One RPC endpoint URL, or several separated by commas: then all must answer the same (see the file header). */
  rpcUrl: string;
  contractId: string;
  /** Per-call timeout (default 10 s). */
  timeoutMs?: number;
  /**
   * Block finality for views (default `"optimistic"`, the latest block, so an owner's revocation is seen
   * by the very next request — SPEC demo scenario 5).
   */
  finality?: NearFinality;
  /**
   * Pinned `code_hash` of the registry account (base58, as `view_account` prints it). Set ⇒ checked before any
   * view; unset ⇒ only the account id is pinned (local MOCK demo).
   */
  codeHash?: string;
}

/** The client-only error code of a registry account that does not run the pinned code. */
export const E_REGISTRY_CODE_HASH = "E_REGISTRY_CODE_HASH";

/**
 * The registry account's `code_hash` differs from the pin. A `PlrError` whose `code` is `E_REGISTRY_CODE_HASH`.
 * That code is deliberately NOT in `@plr/shared`'s `ERROR_CODES`: `@plr/shared` is bundled into the measured exit
 * image, and this is a client-side check, so the exit's source (and its reproducible image digest) stays as it is.
 */
export class RegistryCodeHashError extends PlrError {
  constructor() {
    super("E_REGISTRY_UNAVAILABLE");
    (this as { code: string }).code = E_REGISTRY_CODE_HASH;
    this.message = `${E_REGISTRY_CODE_HASH}: registry account code hash differs from the pin`;
  }
}

export function isRegistryCodeHashError(e: unknown): e is RegistryCodeHashError {
  return e instanceof PlrError && (e.code as string) === E_REGISTRY_CODE_HASH;
}

/**
 * The code-hash check of a registry reader that has one (a {@link NearRegistry}, also behind a wrapper that
 * forwards `checkCodeHash`); a no-op for any other reader. Runs before the registry is used for a verification.
 * @throws RegistryCodeHashError (different code); RegistryRpcDisagreeError (the endpoints report different code
 *         hashes); PlrError E_REGISTRY_UNAVAILABLE (account unreadable)
 */
export async function checkRegistryCode(registry: unknown): Promise<void> {
  const f = (registry as { checkCodeHash?: unknown } | null)?.checkCodeHash;
  if (typeof f !== "function") return;
  try {
    await (f as () => Promise<void>).call(registry);
  } catch (e) {
    if (isRegistryRefusal(e)) throw e;
    throw new PlrError("E_REGISTRY_UNAVAILABLE", "view_account");
  }
}

/** The client-only error code of RPC endpoints that give different answers to the same registry query. */
export const E_REGISTRY_RPC_DISAGREE = "E_REGISTRY_RPC_DISAGREE";

/**
 * The configured RPC endpoints answered the same registry query differently (twice in a row). A `PlrError` whose
 * `code` is `E_REGISTRY_RPC_DISAGREE`; like `E_REGISTRY_CODE_HASH` it is a client-only code and deliberately NOT
 * in `@plr/shared`'s `ERROR_CODES` (the exit's source and its reproducible image digest stay as they are).
 */
export class RegistryRpcDisagreeError extends PlrError {
  constructor(what = "") {
    super("E_REGISTRY_UNAVAILABLE");
    (this as { code: string }).code = E_REGISTRY_RPC_DISAGREE;
    this.message = `${E_REGISTRY_RPC_DISAGREE}: the RPC endpoints give different answers${what === "" ? "" : ` (${what})`}`;
  }
}

export function isRegistryRpcDisagreeError(e: unknown): e is RegistryRpcDisagreeError {
  return e instanceof PlrError && (e.code as string) === E_REGISTRY_RPC_DISAGREE;
}

/**
 * True for the two client-only registry refusals (other code than pinned; endpoints disagree). Callers that turn
 * registry failures into E_REGISTRY_UNAVAILABLE let these two through unchanged.
 */
export function isRegistryRefusal(e: unknown): e is RegistryCodeHashError | RegistryRpcDisagreeError {
  return isRegistryCodeHashError(e) || isRegistryRpcDisagreeError(e);
}

/** Endpoints that disagree are asked once more after this pause before the client refuses. */
export const RPC_DISAGREE_RETRY_MS = 1_000;
/** Upper bound on listed endpoints (every query goes to all of them). */
export const MAX_RPC_URLS = 5;

/**
 * Splits and validates an RPC setting: one URL or a comma-separated list (spaces around commas are ignored). Each
 * URL must pass {@link checkRpcUrl}; an empty entry, a repeated endpoint or more than {@link MAX_RPC_URLS} is
 * refused (a repeated endpoint would look like two voices but be one).
 * @throws PlrError E_BAD_INPUT
 */
export function parseRpcUrls(rpcUrl: unknown): URL[] {
  if (typeof rpcUrl !== "string") throw new PlrError("E_BAD_INPUT", "rpcUrl must be a string");
  const parts = rpcUrl.split(",");
  if (parts.length > MAX_RPC_URLS) throw new PlrError("E_BAD_INPUT", `at most ${MAX_RPC_URLS} RPC endpoints`);
  const urls = parts.map((u) => checkRpcUrl(parts.length === 1 ? u : u.trim()));
  if (new Set(urls.map((u) => u.href)).size !== urls.length) throw new PlrError("E_BAD_INPUT", "the same RPC endpoint is listed twice");
  return urls;
}

/** A passed code-hash check is reused for this long; a failed one is never reused. */
export const CODE_HASH_TTL_MS = 30_000;

/**
 * Code hashes of the registries this client ships with: the reproducible build of `contracts/near` deployed at
 * that account (README, "Run it yourself"). `PLR_VPN_REGISTRY_CODE_HASH` overrides / adds a pin.
 */
export const KNOWN_REGISTRY_CODE_HASHES: Readonly<Record<string, string>> = Object.freeze({
  "vpnreg.pe-owner-erhan.testnet": "C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM",
});

const CODE_HASH_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
/** `code_hash` of an account with no contract (32 zero bytes): never a valid pin. */
const NO_CODE_HASH = "1".repeat(32);

/** True for a base58 SHA-256 as NEAR prints `code_hash` (and not the "no contract" value). */
export function isCodeHash(v: unknown): v is string {
  return typeof v === "string" && CODE_HASH_RE.test(v) && v !== NO_CODE_HASH;
}

/**
 * The code-hash pin for a registry: `explicit` (`PLR_VPN_REGISTRY_CODE_HASH`) if set, else the shipped pin of a
 * known registry. With neither: an INTEL verification refuses to start (throws), a MOCK one (local demo / tests,
 * where the registry is a sandbox contract built on the spot) runs with the account id only and returns undefined.
 * @throws Error — malformed pin, or no pin for a registry used with the Intel root
 */
export function resolveRegistryCodeHash(contractId: string, explicit: string | undefined, intel: boolean): string | undefined {
  if (explicit !== undefined && explicit !== "") {
    if (!isCodeHash(explicit)) throw new Error("PLR_VPN_REGISTRY_CODE_HASH must be the registry account's code hash (base58, as view_account prints it)");
    return explicit;
  }
  const known = Object.hasOwn(KNOWN_REGISTRY_CODE_HASHES, contractId) ? KNOWN_REGISTRY_CODE_HASHES[contractId] : undefined;
  if (known !== undefined) return known;
  if (intel) throw new Error(`PLR_VPN_REGISTRY_CODE_HASH is required for registry ${contractId} (no shipped code-hash pin; INTEL mode refuses an unpinned registry)`);
  return undefined;
}

/** Max size of a view result we are willing to parse. */
const MAX_RESULT_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
/** NEAR account id rules (nearcore `AccountId` validation). */
const ACCOUNT_ID_RE = /^(?:(?:[a-z\d]+[-_])*[a-z\d]+\.)*(?:[a-z\d]+[-_])*[a-z\d]+$/;
const U64_DEC_RE = /^(?:0|[1-9]\d{0,15})$/;

export class NearRegistryError extends Error {
  constructor(detail: string) {
    super(`NearRegistry: ${detail}`);
    this.name = "NearRegistryError";
  }
}

/** True for hosts that never leave the machine: `localhost`, 127.0.0.0/8, `::1`. */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "[::1]") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h); // WHATWG URL canonicalises IPv4 literals
  return m !== null && m.slice(1).every((o) => Number(o) <= 255);
}

/**
 * Validates a NEAR RPC URL: `https:` (any host) or `http:` to a loopback host only; no credentials in the URL
 * userinfo. Throws PlrError E_BAD_INPUT otherwise. Returns the parsed URL.
 */
export function checkRpcUrl(rpcUrl: unknown): URL {
  if (typeof rpcUrl !== "string") throw new PlrError("E_BAD_INPUT", "rpcUrl must be a string");
  let url: URL;
  try {
    url = new URL(rpcUrl);
  } catch {
    throw new PlrError("E_BAD_INPUT", "rpcUrl must be a URL");
  }
  if (url.username !== "" || url.password !== "") throw new PlrError("E_BAD_INPUT", "rpcUrl must not carry credentials");
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) return url;
  throw new PlrError("E_BAD_INPUT", "rpcUrl must be https (plain http is accepted only for a loopback host)");
}

export function isNearAccountId(id: unknown): id is string {
  return typeof id === "string" && id.length >= 2 && id.length <= 64 && ACCOUNT_ID_RE.test(id);
}

/** Accepts a JSON number or a decimal string (near-sdk `U64`) and returns a safe integer, else `undefined`. */
function toUint(v: unknown): number | undefined {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? v : undefined;
  if (typeof v === "string" && U64_DEC_RE.test(v)) {
    const n = Number(v);
    return Number.isSafeInteger(n) ? n : undefined;
  }
  return undefined;
}

function normalizeUints(v: unknown, fields: readonly string[]): unknown {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return v;
  const o: Record<string, unknown> = { ...(v as Record<string, unknown>) };
  for (const f of fields) {
    const n = toUint(o[f]);
    if (n !== undefined) o[f] = n;
  }
  return o;
}

const INSTANCE_UINTS = ["registered_at_ms", "expires_at_ms", "next_seq"] as const;
const ANCHOR_UINTS = ["id", "first_seq", "count", "at_ms"] as const;

export class NearRegistry implements RegistryReader {
  readonly chain = "near";
  readonly contractId: string;
  /** The endpoint URL; with several, their URLs joined by commas (as configured, normalised). */
  readonly rpcUrl: string;
  /** Every endpoint asked, in the configured order. */
  readonly rpcUrls: readonly string[];
  readonly #providers: JsonRpcProvider[];
  readonly #retryMs: number;
  readonly #timeoutMs: number;
  readonly #finality: NearFinality;
  /** The pinned `code_hash`, or undefined when only the account id is pinned. */
  readonly pinnedCodeHash: string | undefined;
  #codeOkUntil = 0;
  #codePending: Promise<void> | undefined;

  constructor(o: NearRegistryOptions) {
    if (typeof o !== "object" || o === null) throw new PlrError("E_BAD_INPUT", "NearRegistry options required");
    const urls = parseRpcUrls(o.rpcUrl);
    if (!isNearAccountId(o.contractId)) throw new PlrError("E_BAD_INPUT", "contractId is not a valid NEAR account id");
    const timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) throw new PlrError("E_BAD_INPUT", "bad timeoutMs");
    const finality = o.finality ?? "optimistic";
    if (finality !== "optimistic" && finality !== "near-final" && finality !== "final") throw new PlrError("E_BAD_INPUT", "bad finality");
    this.rpcUrls = Object.freeze(urls.map((u) => u.href));
    this.rpcUrl = this.rpcUrls.join(",");
    this.contractId = o.contractId;
    this.#timeoutMs = timeoutMs;
    this.#finality = finality;
    if (o.codeHash !== undefined && !isCodeHash(o.codeHash)) throw new PlrError("E_BAD_INPUT", "codeHash is not a base58 code hash");
    this.pinnedCodeHash = o.codeHash;
    // Few, quick retries: the per-call timeout below bounds the total wait anyway.
    this.#providers = this.rpcUrls.map((url) => new JsonRpcProvider({ url }, { retries: 2, wait: 100, backoff: 1.5 }));
    this.#retryMs = Math.min(RPC_DISAGREE_RETRY_MS, timeoutMs);
  }

  /**
   * Sends one query to every endpoint in parallel (each bounded by the per-call timeout) and returns the answer
   * they all gave. `ask` returns the part of the reply that must be the same everywhere, as text.
   * One endpoint: its answer, as before. Several: see the file header (all must answer, all answers equal, one
   * re-ask on a disagreement).
   * @throws RegistryRpcDisagreeError; NearRegistryError (an endpoint failed, timed out or answered garbage)
   */
  async #askAll(what: string, ask: (p: JsonRpcProvider) => Promise<string>): Promise<string> {
    for (let attempt = 0; ; attempt++) {
      const settled = await Promise.allSettled(this.#providers.map((p) => this.#askOne(what, p, ask)));
      const answers = settled.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []));
      if (answers.some((a) => a !== answers[0])) {
        if (attempt > 0) throw new RegistryRpcDisagreeError(what);
        await new Promise<void>((ok) => setTimeout(ok, this.#retryMs));
        continue;
      }
      // fail closed: an endpoint that did not answer is not outvoted by the ones that did
      const failed = settled.find((r) => r.status === "rejected");
      if (failed !== undefined) throw failed.reason as NearRegistryError;
      return answers[0]!;
    }
  }

  async #askOne(what: string, p: JsonRpcProvider, ask: (p: JsonRpcProvider) => Promise<string>): Promise<string> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new NearRegistryError(`${what}: timeout`)), this.#timeoutMs);
      timer.unref?.();
    });
    try {
      return await Promise.race([ask(p), timeout]);
    } catch (e) {
      if (e instanceof NearRegistryError) throw e;
      throw new NearRegistryError(`${what}: RPC failed`);
    } finally {
      clearTimeout(timer);
    }
  }

  /** With a pin: true while the last code-hash check passed and is still fresh. Without a pin: undefined. */
  get codeHashVerified(): boolean | undefined {
    return this.pinnedCodeHash === undefined ? undefined : performance.now() < this.#codeOkUntil;
  }

  /**
   * Checks the registry account's `code_hash` against the pin (no-op without one, or within the reuse window);
   * concurrent callers share one `view_account`.
   * @throws RegistryCodeHashError (different code); RegistryRpcDisagreeError (endpoints report different hashes);
   *         NearRegistryError (RPC failed / malformed / timeout)
   */
  async checkCodeHash(): Promise<void> {
    if (this.pinnedCodeHash === undefined || performance.now() < this.#codeOkUntil) return;
    this.#codePending ??= this.#fetchAndCompareCode().finally(() => {
      this.#codePending = undefined;
    });
    return this.#codePending;
  }

  async #fetchAndCompareCode(): Promise<void> {
    this.#codeOkUntil = 0;
    // Only `code_hash` is compared between endpoints: balance and block fields legitimately differ by block.
    const hash = await this.#askAll("view_account", async (p) => {
      const acct: unknown = await p.query({ request_type: "view_account", finality: this.#finality, account_id: this.contractId });
      const h: unknown = typeof acct === "object" && acct !== null ? (acct as Record<string, unknown>).code_hash : undefined;
      if (typeof h !== "string" || !CODE_HASH_RE.test(h)) throw new NearRegistryError("view_account: malformed reply");
      return h;
    });
    if (hash !== this.pinnedCodeHash) throw new RegistryCodeHashError();
    this.#codeOkUntil = performance.now() + CODE_HASH_TTL_MS;
  }

  /**
   * Raw view call: returns the JSON-decoded result. Rejects on any error or timeout; with a code-hash pin, first
   * rejects with {@link RegistryCodeHashError} when the account runs other code. With several endpoints: rejects
   * with {@link RegistryRpcDisagreeError} unless all give the same result.
   */
  async view(method: string, args: Record<string, unknown>): Promise<unknown> {
    await this.checkCodeHash();
    // The contract's returned bytes (as text) are what every endpoint must agree on; they are parsed once.
    const text = await this.#askAll(method, async (p) =>
      decodeResultText(method, await p.callFunctionRaw({ contractId: this.contractId, method, args, blockQuery: { finality: this.#finality } })),
    );
    return parseJsonIntegers(text);
  }

  async getRoot(): Promise<RegistryRoot> {
    const v = await this.view("get_root", {});
    if (!isRegistryRoot(v)) throw new NearRegistryError("get_root: malformed reply");
    return { kind: v.kind, p256: v.p256 };
  }

  async isComposeAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false; // the contract never allows malformed or zero hashes
    return this.#bool("is_compose_allowed", { hash: h });
  }

  async isOsAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    return this.#bool("is_os_allowed", { hash: h });
  }

  async getInstance(keyHash: string): Promise<InstanceRecord | null> {
    if (!isHash32(keyHash)) return null;
    const v = normalizeUints(await this.view("get_instance", { key_hash: keyHash }), INSTANCE_UINTS);
    if (v === null) return null;
    if (!isInstanceRecord(v)) throw new NearRegistryError("get_instance: malformed reply");
    return {
      compose_hash: v.compose_hash,
      os_measurement: v.os_measurement,
      x25519: v.x25519,
      ed25519: v.ed25519,
      operator: v.operator,
      org_id: v.org_id,
      registered_at_ms: v.registered_at_ms,
      expires_at_ms: v.expires_at_ms,
      next_seq: v.next_seq,
    };
  }

  /** `get_operator(account_id)` (SPEC §7 rev 1.2): the account's owner-approved `org_id`, or null. */
  async getOperator(accountId: string): Promise<string | null> {
    if (!isNearAccountId(accountId)) return null; // the contract never maps malformed account ids
    const v = await this.view("get_operator", { account_id: accountId });
    if (v !== null && !isOrgId(v)) throw new NearRegistryError("get_operator: malformed reply");
    return v;
  }

  async getAnchor(id: number): Promise<AnchorRecord | null> {
    if (!Number.isSafeInteger(id) || id < 0) return null;
    const v = normalizeUints(await this.view("get_anchor", { id }), ANCHOR_UINTS);
    if (v === null) return null;
    if (!isAnchorRecord(v)) throw new NearRegistryError("get_anchor: malformed reply");
    return { id: v.id, key_hash: v.key_hash, root: v.root, first_seq: v.first_seq, count: v.count, at_ms: v.at_ms };
  }

  async anchorCount(): Promise<number> {
    const n = toUint(await this.view("anchor_count", {}));
    if (n === undefined) throw new NearRegistryError("anchor_count: malformed reply");
    return n;
  }

  async #bool(method: string, args: Record<string, unknown>): Promise<boolean> {
    const v = await this.view(method, args);
    if (typeof v !== "boolean") throw new NearRegistryError(`${method}: malformed reply`);
    return v;
  }
}

/** Decodes `result: number[]` (UTF-8 JSON bytes) of a `call_function` query, strictly, to its JSON text. */
function decodeResultText(method: string, raw: unknown): string {
  if (typeof raw !== "object" || raw === null) throw new NearRegistryError(`${method}: malformed RPC reply`);
  const result: unknown = (raw as Record<string, unknown>).result;
  if (!Array.isArray(result) || result.length === 0 || result.length > MAX_RESULT_BYTES) {
    throw new NearRegistryError(`${method}: malformed RPC result`);
  }
  const bytes = new Uint8Array(result.length);
  for (let i = 0; i < result.length; i++) {
    const b: unknown = result[i];
    if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) throw new NearRegistryError(`${method}: malformed RPC result`);
    bytes[i] = b;
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parseJsonIntegers(text); // must parse, so that a non-JSON answer counts as an endpoint failure
    return text;
  } catch {
    throw new NearRegistryError(`${method}: result is not JSON`);
  }
}
