/**
 * {@link RegistryReader} for the EVM / Monad tier-B registry (SPEC-CHAINS §1, §2, §9): `PlrRegistry` views through
 * JSON-RPC `eth_call` (viem).
 *
 * Tier B: the contract enforces owner policy, operator approval (`operator = tx sender`), the registration quote's
 * format and report_data binding, and contiguous anchors from the instance's operator, but it does NOT verify the
 * quote signature or the anchor's Ed25519 signature. So `verifiesOnChain = false`: clients check the stored
 * registration quote (`getRegistrationQuote`, SPEC-CHAINS §2) and each anchor's `sig`.
 *
 * Identity: `contractId = "evm:<chainId>:<0x lowercase address>"` (SPEC-CHAINS §3). Before the first answer (and
 * again after a failure) the reader checks that the node's `eth_chainId` is that chain id and that the contract at
 * that address reports exactly this `contractId()`: a reader pointed at the wrong chain or contract never answers.
 *
 * Every reply is validated strictly; a transport error, RPC error, timeout, unexpected revert or malformed value
 * rejects (⇒ E_REGISTRY_UNAVAILABLE in `verifyAttestation`, fail closed). Responses are size-bounded.
 *
 * TRUST: like NEAR views, `eth_call` results carry no state proofs, so the RPC endpoint is part of the client's
 * trusted base and must be reached over an authenticated channel: `https:` for a remote host, plain `http:` only to
 * a loopback address.
 *
 * TIME: expiry is judged against the local clock (`expires_at_ms <= now` ⇒ null); EVM block timestamps track wall
 * time (anvil, Monad, Ethereum).
 */
import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  http,
  type Address,
  type PublicClient,
} from "viem";
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
import { isPlainObject } from "../util.js";
import { EVM_REGISTRY_ERRORS, PLR_REGISTRY_ABI, type EvmRegistryErrorName } from "./evm-abi.js";

export { PLR_REGISTRY_ABI, EVM_REGISTRY_ERRORS, type EvmRegistryErrorName } from "./evm-abi.js";

/** `0x` + 40 lowercase hex (SPEC-CHAINS §3 operator id). */
export const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const ANY_CASE_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const CONTRACT_ID_RE = /^evm:([1-9][0-9]{0,15}):(0x[0-9a-f]{40})$/;
/** Largest chain id accepted (keeps `contractId` ≤ 64 bytes and the id a safe integer). */
export const MAX_EVM_CHAIN_ID = Number.MAX_SAFE_INTEGER;
/** Largest registration quote returned (INTEL quotes are bounded by SPEC §2 at 32 KiB; the contract stores 828). */
const MAX_QUOTE_BYTES = 32 * 1024;
/** Largest JSON-RPC reply parsed. */
const MAX_REPLY_BYTES = 256 * 1024;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export interface EvmRegistryOptions {
  /** JSON-RPC URL (https, or http to a loopback host only). */
  rpcUrl: string;
  /** `evm:<chainId>:<0x lowercase address>` — or give `chainId` + `address`. */
  contractId?: string;
  chainId?: number;
  /** Registry contract address (any case; stored lowercase). */
  address?: string;
  /** Per-call timeout (default 10 s). */
  timeoutMs?: number;
  /** Injectable clock (ms) for expiry (default `Date.now`). */
  now?: () => number;
}

export class EvmRegistryError extends Error {
  constructor(detail: string) {
    super(`EvmRegistry: ${detail}`);
    this.name = "EvmRegistryError";
  }
}

/** A registry revert mapped to its PLR code; `revert` is the contract's error name (SPEC-CHAINS §9). */
export class EvmRevertError extends PlrError {
  readonly revert: EvmRegistryErrorName;
  constructor(revert: EvmRegistryErrorName, detail?: string) {
    super(plrCodeOfRevert(revert), detail === undefined ? revert : `${revert} ${detail}`);
    this.name = "EvmRevertError";
    this.revert = revert;
  }
}

/**
 * The PLR code of a registry revert. The two contract-only names (`E_UNAUTHORIZED`, `E_ZERO_HASH`) are not in the
 * shared PLR code set and map to `E_BAD_INPUT` (the original name is kept on {@link EvmRevertError.revert}).
 */
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

/** True for a positive safe-integer chain id. */
export function isEvmChainId(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 1 && n <= MAX_EVM_CHAIN_ID;
}

/** SPEC-CHAINS §3 contract id of a deployment. @throws PlrError E_BAD_INPUT */
export function evmContractId(chainId: number, address: string): string {
  if (!isEvmChainId(chainId)) throw new PlrError("E_BAD_INPUT", "bad chain id");
  if (typeof address !== "string" || !ANY_CASE_ADDRESS_RE.test(address)) throw new PlrError("E_BAD_INPUT", "bad registry address");
  return `evm:${chainId}:${address.toLowerCase()}`;
}

/** Parses `evm:<chainId>:<0x lowercase address>`; null if malformed. Never throws. */
export function parseEvmContractId(id: unknown): { chainId: number; address: string } | null {
  if (typeof id !== "string" || id.length > 64) return null;
  const m = CONTRACT_ID_RE.exec(id);
  if (m === null) return null;
  const chainId = Number(m[1]);
  return isEvmChainId(chainId) ? { chainId, address: m[2]! } : null;
}

const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** uint64/uint256 from viem (bigint) → safe integer, else throws malformed. */
function safeInt(v: unknown, what: string): number {
  if (typeof v !== "bigint" || v < 0n || v > BigInt(Number.MAX_SAFE_INTEGER)) throw new EvmRegistryError(`${what}: malformed value`);
  return Number(v);
}

function hex32(v: unknown, what: string): string {
  if (typeof v !== "string" || !/^0x[0-9a-f]{64}$/i.test(v)) throw new EvmRegistryError(`${what}: malformed bytes32`);
  return v.slice(2).toLowerCase();
}

function bytesOf(v: unknown, what: string, max: number): Uint8Array {
  if (typeof v !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(v) || (v.length - 2) / 2 > max) throw new EvmRegistryError(`${what}: malformed bytes`);
  return Uint8Array.from(Buffer.from(v.slice(2), "hex"));
}

export class EvmRegistry implements RegistryReader {
  readonly chain = "evm";
  /** Tier B: the quote signature is not verified on-chain (SPEC-CHAINS §1, §2). */
  readonly verifiesOnChain = false;
  readonly contractId: string;
  readonly chainId: number;
  /** Registry address, lowercase. */
  readonly address: string;
  readonly rpcUrl: string;
  readonly #client: PublicClient;
  readonly #now: () => number;
  /** Resolved once the node's chain id and the contract's own `contractId()` matched (reset on failure). */
  #identity: Promise<void> | null = null;

  constructor(o: EvmRegistryOptions) {
    if (!isPlainObject(o)) throw new PlrError("E_BAD_INPUT", "EvmRegistry options required");
    const url = checkRpcUrl(o.rpcUrl);
    let id: { chainId: number; address: string } | null;
    if (o.contractId !== undefined) {
      id = parseEvmContractId(o.contractId);
      if (id === null) throw new PlrError("E_BAD_INPUT", "contractId must be evm:<chainId>:<0x lowercase address>");
      if ((o.chainId !== undefined && o.chainId !== id.chainId) || (o.address !== undefined && String(o.address).toLowerCase() !== id.address)) {
        throw new PlrError("E_BAD_INPUT", "contractId disagrees with chainId/address");
      }
    } else {
      id = parseEvmContractId(evmContractId(o.chainId as number, o.address as string));
      if (id === null) throw new PlrError("E_BAD_INPUT", "bad chainId/address");
    }
    if (id.address === ZERO_ADDRESS) throw new PlrError("E_BAD_INPUT", "registry address is zero");
    const timeoutMs = o.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) throw new PlrError("E_BAD_INPUT", "bad timeoutMs");
    if (o.now !== undefined && typeof o.now !== "function") throw new PlrError("E_BAD_INPUT", "bad now");
    this.chainId = id.chainId;
    this.address = id.address;
    this.contractId = `evm:${id.chainId}:${id.address}`;
    this.rpcUrl = url.href;
    this.#now = o.now ?? Date.now;
    this.#client = createPublicClient({
      transport: http(url.href, { timeout: timeoutMs, retryCount: 1, retryDelay: 100, maxResponseBodySize: MAX_REPLY_BYTES, batch: false }),
    });
  }

  /** Checks (once, retried after a failure) that the node and the contract are the ones `contractId` names. */
  #checkIdentity(): Promise<void> {
    this.#identity ??= (async () => {
      let chainId: number;
      try {
        chainId = await this.#client.getChainId();
      } catch {
        throw new EvmRegistryError("eth_chainId: RPC failed");
      }
      if (chainId !== this.chainId) throw new EvmRegistryError("node is on another chain");
      const cid = await this.#read("contractId", []);
      if (cid !== this.contractId) throw new EvmRegistryError("contract at this address is not this registry");
    })().catch((e: unknown) => {
      this.#identity = null;
      throw e;
    });
    return this.#identity;
  }

  /** One view call; `allow` lists reverts the caller handles (returned as {@link EvmRevertError}). */
  async #read(fn: string, args: readonly unknown[], allow: readonly EvmRegistryErrorName[] = []): Promise<unknown> {
    try {
      return await this.#client.readContract({ address: this.address as Address, abi: PLR_REGISTRY_ABI, functionName: fn as never, args: args as never });
    } catch (e) {
      const r = evmRevertName(e);
      if (r !== null && allow.includes(r)) return new EvmRevertError(r);
      throw new EvmRegistryError(r !== null ? `${fn}: reverted ${r}` : `${fn}: RPC failed`);
    }
  }

  async #view(fn: string, args: readonly unknown[], allow: readonly EvmRegistryErrorName[] = []): Promise<unknown> {
    await this.#checkIdentity();
    return this.#read(fn, args, allow);
  }

  async getRoot(): Promise<RegistryRoot> {
    const v = await this.#view("getRoot", []);
    if (!Array.isArray(v) || v.length !== 2) throw new EvmRegistryError("getRoot: malformed reply");
    const kind = v[0] === 1 ? "MOCK" : v[0] === 2 ? "INTEL" : null;
    if (kind === null) throw new EvmRegistryError("getRoot: unknown root kind");
    const p = bytesOf(v[1], "getRoot", 64);
    if (p.length !== 64) throw new EvmRegistryError("getRoot: malformed key");
    return { kind, p256: toHex(p) };
  }

  async isComposeAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false; // the contract never allows the zero hash; malformed input is never allowed
    return this.#bool("isComposeAllowed", [`0x${h}`]);
  }

  async isOsAllowed(h: string): Promise<boolean> {
    if (!isHash32(h)) return false;
    return this.#bool("isOsAllowed", [`0x${h}`]);
  }

  async #bool(fn: string, args: readonly unknown[]): Promise<boolean> {
    const v = await this.#view(fn, args);
    if (typeof v !== "boolean") throw new EvmRegistryError(`${fn}: malformed reply`);
    return v;
  }

  /** `getOperator(op)`: the operator's owner-approved `org_id`, or null. */
  async getOperator(account: string): Promise<string | null> {
    if (typeof account !== "string" || !ANY_CASE_ADDRESS_RE.test(account)) return null;
    const v = await this.#view("getOperator", [account.toLowerCase()]);
    if (typeof v !== "string") throw new EvmRegistryError("getOperator: malformed reply");
    if (v === "") return null;
    if (!isOrgId(v)) throw new EvmRegistryError("getOperator: malformed org id");
    return v;
  }

  /** The live instance (null if unknown, expired or its operator is unapproved); `org_id` is the operator's live organization. */
  async getInstance(keyHash: string): Promise<InstanceRecord | null> {
    if (!isHash32(keyHash)) return null;
    const v = await this.#view("getInstance", [`0x${keyHash}`]);
    if (!Array.isArray(v) || v.length !== 9) throw new EvmRegistryError("getInstance: malformed reply");
    const [exists, compose, os, x, ed, operator, regAt, expAt, nextSeq] = v as unknown[];
    if (typeof exists !== "boolean") throw new EvmRegistryError("getInstance: malformed reply");
    if (!exists) return null;
    if (typeof operator !== "string" || !ANY_CASE_ADDRESS_RE.test(operator) || operator.toLowerCase() === ZERO_ADDRESS) {
      throw new EvmRegistryError("getInstance: malformed operator");
    }
    const rec = {
      compose_hash: hex32(compose, "getInstance"),
      os_measurement: hex32(os, "getInstance"),
      x25519: hex32(x, "getInstance"),
      ed25519: hex32(ed, "getInstance"),
      operator: operator.toLowerCase(),
      registered_at_ms: safeInt(regAt, "getInstance"),
      expires_at_ms: safeInt(expAt, "getInstance"),
      next_seq: safeInt(nextSeq, "getInstance"),
    };
    if (!isHash32(rec.compose_hash) || !isHash32(rec.os_measurement)) throw new EvmRegistryError("getInstance: zero measurement");
    if (rec.expires_at_ms <= this.#now()) return null;
    // SPEC-CHAINS §1: tier B accepts instance records only from operators the owner currently approves.
    const org_id = await this.getOperator(rec.operator);
    if (org_id === null) return null;
    return { ...rec, org_id };
  }

  async getAnchor(id: number): Promise<AnchorRecord | null> {
    if (!isUint(id)) return null;
    const v = await this.#view("getAnchor", [BigInt(id)], ["E_BAD_INPUT"]);
    if (v instanceof EvmRevertError) return null; // unknown id
    if (!Array.isArray(v) || v.length !== 6) throw new EvmRegistryError("getAnchor: malformed reply");
    const [kh, root, first, count, at, sig] = v as unknown[];
    const key_hash = hex32(kh, "getAnchor");
    if (!isHash32(key_hash)) throw new EvmRegistryError("getAnchor: zero key hash");
    const s = bytesOf(sig, "getAnchor", 64);
    if (s.length !== 64) throw new EvmRegistryError("getAnchor: malformed sig");
    return {
      id,
      key_hash,
      root: hex32(root, "getAnchor"),
      first_seq: safeInt(first, "getAnchor"),
      count: safeInt(count, "getAnchor"),
      at_ms: safeInt(at, "getAnchor"),
      sig: toHex(s),
    };
  }

  /** Tier B: the registration quote stored on-chain (`offered` ignored, SPEC-CHAINS §2); null if none. */
  async getRegistrationQuote(keyHash: string, _offered?: Uint8Array): Promise<Uint8Array | null> {
    if (!isHash32(keyHash)) return null;
    const v = await this.#view("getRegistrationQuote", [`0x${keyHash}`]);
    const q = bytesOf(v, "getRegistrationQuote", MAX_QUOTE_BYTES);
    return q.length === 0 ? null : q;
  }

  async anchorCount(): Promise<number> {
    return safeInt(await this.#view("anchorCount", []), "anchorCount");
  }

  /** The registry owner (lowercase address). */
  async getOwner(): Promise<string> {
    const v = await this.#view("owner", []);
    if (typeof v !== "string" || !ANY_CASE_ADDRESS_RE.test(v)) throw new EvmRegistryError("owner: malformed reply");
    return v.toLowerCase();
  }
}
