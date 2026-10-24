/** Chain-agnostic registry reader contract (SPEC §7, §10) and an in-memory implementation for tests. */
import { PlrError } from "./errors.js";
import { fromHex, isHex, isPlainObject, isUint } from "./bytes.js";
import type { RootKind } from "./tdx/quote.js";

export interface RegistryRoot {
  kind: RootKind;
  /** 64-byte P-256 `x‖y`, 128 lowercase hex. */
  p256: string;
}

export interface InstanceRecord {
  compose_hash: string;
  os_measurement: string;
  x25519: string;
  ed25519: string;
  operator: string;
  /** SPEC §7 rev 1.2: live organization of `operator` (owner-approved), null if the operator is not approved. */
  org_id: string | null;
  registered_at_ms: number;
  expires_at_ms: number;
  next_seq: number;
}

export interface AnchorRecord {
  id: number;
  key_hash: string;
  root: string;
  first_seq: number;
  count: number;
  at_ms: number;
  /**
   * SPEC-CHAINS §2: tier B/C registries store the instance's Ed25519 anchor signature (64 bytes, 128 lowercase hex)
   * over SPEC §7 `anchorMessage`; clients verify it. Absent on tier A (the contract verified it).
   */
  sig?: string;
}

export interface RegistryReader {
  readonly chain: string;
  readonly contractId: string;
  getRoot(): Promise<RegistryRoot>;
  isComposeAllowed(h: string): Promise<boolean>;
  isOsAllowed(h: string): Promise<boolean>;
  /** null if unknown or expired */
  getInstance(keyHash: string): Promise<InstanceRecord | null>;
  getAnchor(id: number): Promise<AnchorRecord | null>;
  /**
   * SPEC-CHAINS §2 (rev 1.4): true only for tier-A registries that verify the registration quote on-chain. When false,
   * clients require registration evidence ({@link RegistryReader.getRegistrationQuote}) after SPEC §9 step 9.
   */
  readonly verifiesOnChain: boolean;
  /**
   * SPEC-CHAINS §2: the registration quote of `keyHash`. Tier B: the quote stored on-chain (`offered` ignored);
   * tier C: `offered` iff its SHA-256 equals the on-chain commitment, else null; tier A may return null.
   */
  getRegistrationQuote(keyHash: string, offered?: Uint8Array): Promise<Uint8Array | null>;
}

const ZERO32 = "00".repeat(32);

/** SPEC §7 rev 1.2 operator organization id. */
export const ORG_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** True for a valid `org_id` (SPEC §7 rev 1.2: `^[a-z0-9][a-z0-9._-]{0,63}$`). Never throws. */
export function isOrgId(v: unknown): v is string {
  return typeof v === "string" && v.length <= 64 && ORG_ID_RE.test(v);
}

/** 32-byte lowercase hex, not all-zero (the registry never accepts the zero hash). */
export function isHash32(h: unknown): h is string {
  return isHex(h, 32) && h !== ZERO32;
}

export function isRegistryRoot(v: unknown): v is RegistryRoot {
  return isPlainObject(v) && (v.kind === "MOCK" || v.kind === "INTEL") && isHex(v.p256, 64);
}

export function isInstanceRecord(v: unknown): v is InstanceRecord {
  return (
    isPlainObject(v) &&
    isHash32(v.compose_hash) &&
    isHash32(v.os_measurement) &&
    isHex(v.x25519, 32) &&
    isHex(v.ed25519, 32) &&
    typeof v.operator === "string" &&
    // required key (fail closed): an absent org_id is not the same as "unapproved"
    Object.prototype.hasOwnProperty.call(v, "org_id") &&
    (v.org_id === null || isOrgId(v.org_id)) &&
    isUint(v.registered_at_ms) &&
    isUint(v.expires_at_ms) &&
    isUint(v.next_seq)
  );
}

export function isAnchorRecord(v: unknown): v is AnchorRecord {
  return (
    isPlainObject(v) &&
    isUint(v.id) &&
    isHash32(v.key_hash) &&
    isHex(v.root, 32) &&
    isUint(v.first_seq) &&
    isUint(v.count) &&
    isUint(v.at_ms) &&
    (v.sig === undefined || isHex(v.sig, 64))
  );
}

export interface MemoryRegistryOptions {
  root: RegistryRoot;
  compose: string[];
  os: string[];
  instances: Record<string, InstanceRecord>;
  anchors?: AnchorRecord[];
  chain?: string;
  contractId?: string;
  /** Clock used for instance expiry (default `Date.now`). */
  now?: () => number;
  /**
   * Operator account → org_id (SPEC §7 rev 1.2 `approve_operator`). When an instance's operator has an entry
   * here (approved, or revoked via {@link MemoryRegistry.revokeOperator}), `getInstance` returns that live
   * value as `org_id`; otherwise the record's own `org_id` is returned unchanged.
   */
  operators?: Record<string, string>;
  /** SPEC-CHAINS §2: whether the registry verified registration quotes on-chain (tier A). Default true. */
  verifiesOnChain?: boolean;
  /** SPEC-CHAINS §2: keyHash → registration quote (hex), returned by `getRegistrationQuote`. */
  registrationQuotes?: Record<string, string>;
}

function bad(what: string): never {
  throw new PlrError("E_BAD_INPUT", `MemoryRegistry: ${what}`);
}

/**
 * In-memory {@link RegistryReader} with the contract's semantics (tests only): strict hex inputs, zero hash
 * never allowed, expired instances read as null. Every value returned is a fresh copy.
 */
export class MemoryRegistry implements RegistryReader {
  readonly chain: string;
  readonly contractId: string;
  readonly verifiesOnChain: boolean;
  #root: RegistryRoot;
  readonly #regQuotes = new Map<string, Uint8Array>();
  readonly #compose = new Set<string>();
  readonly #os = new Set<string>();
  readonly #instances = new Map<string, InstanceRecord>();
  readonly #anchors: AnchorRecord[] = [];
  /** account → org_id; `null` = explicitly revoked */
  readonly #operators = new Map<string, string | null>();
  readonly #now: () => number;

  constructor(o: MemoryRegistryOptions) {
    if (!isPlainObject(o)) bad("options required");
    if (!isRegistryRoot(o.root)) bad("bad root");
    if (!Array.isArray(o.compose) || !Array.isArray(o.os) || !isPlainObject(o.instances)) bad("bad allowlists");
    this.chain = o.chain ?? "memory";
    this.contractId = o.contractId ?? "registry.memory";
    this.#now = o.now ?? Date.now;
    if (o.verifiesOnChain !== undefined && typeof o.verifiesOnChain !== "boolean") bad("bad verifiesOnChain");
    this.verifiesOnChain = o.verifiesOnChain ?? true;
    if (o.registrationQuotes !== undefined) {
      if (!isPlainObject(o.registrationQuotes)) bad("bad registrationQuotes");
      for (const [k, q] of Object.entries(o.registrationQuotes)) this.setRegistrationQuote(k, q);
    }
    this.#root = { kind: o.root.kind, p256: o.root.p256 };
    for (const h of o.compose) this.allowCompose(h);
    for (const h of o.os) this.allowOs(h);
    for (const [k, rec] of Object.entries(o.instances)) this.putInstance(k, rec);
    for (const a of o.anchors ?? []) this.addAnchor(a);
    if (o.operators !== undefined) {
      if (!isPlainObject(o.operators)) bad("bad operators");
      for (const [acct, org] of Object.entries(o.operators)) this.approveOperator(acct, org);
    }
  }

  // --- mutators (test helpers mirroring the owner/operator methods) ---

  setRoot(root: RegistryRoot): void {
    if (!isRegistryRoot(root)) bad("bad root");
    this.#root = { kind: root.kind, p256: root.p256 };
  }
  allowCompose(h: string): void {
    if (!isHash32(h)) bad("bad compose hash");
    this.#compose.add(h);
  }
  revokeCompose(h: string): void {
    this.#compose.delete(h);
  }
  allowOs(h: string): void {
    if (!isHash32(h)) bad("bad os hash");
    this.#os.add(h);
  }
  revokeOs(h: string): void {
    this.#os.delete(h);
  }
  putInstance(keyHash: string, rec: InstanceRecord): void {
    if (!isHash32(keyHash)) bad("bad key hash");
    if (!isInstanceRecord(rec)) bad("bad instance record");
    this.#instances.set(keyHash, { ...rec });
  }
  removeInstance(keyHash: string): void {
    this.#instances.delete(keyHash);
  }
  /** `approve_operator(account_id, org_id)`: (re)maps an operator account to an organization. */
  approveOperator(account: string, orgId: string): void {
    if (typeof account !== "string" || account.length === 0) bad("bad operator account");
    if (!isOrgId(orgId)) bad("bad org_id");
    this.#operators.set(account, orgId);
  }
  /** `revoke_operator(account_id)`: the operator's instances read `org_id: null` from now on. */
  revokeOperator(account: string): void {
    if (typeof account !== "string" || account.length === 0) bad("bad operator account");
    this.#operators.set(account, null);
  }
  /** `get_operator(account_id)`: live org of an account (null if unknown or revoked). */
  async getOperator(account: string): Promise<string | null> {
    return typeof account === "string" ? (this.#operators.get(account) ?? null) : null;
  }
  /** Sets (or replaces) the registration quote returned for `keyHash`. */
  setRegistrationQuote(keyHash: string, quoteHex: string): void {
    if (!isHash32(keyHash)) bad("bad key hash");
    if (!isHex(quoteHex) || quoteHex.length === 0) bad("bad registration quote");
    this.#regQuotes.set(keyHash, fromHex(quoteHex));
  }
  /** Appends an anchor; its `id` must equal the current anchor count. */
  addAnchor(a: AnchorRecord): void {
    if (!isAnchorRecord(a) || a.id !== this.#anchors.length) bad("bad anchor");
    this.#anchors.push({ ...a });
  }

  // --- RegistryReader ---

  async getRoot(): Promise<RegistryRoot> {
    return { kind: this.#root.kind, p256: this.#root.p256 };
  }
  async isComposeAllowed(h: string): Promise<boolean> {
    return isHash32(h) && this.#compose.has(h);
  }
  async isOsAllowed(h: string): Promise<boolean> {
    return isHash32(h) && this.#os.has(h);
  }
  async getInstance(keyHash: string): Promise<InstanceRecord | null> {
    if (!isHash32(keyHash)) return null;
    const rec = this.#instances.get(keyHash);
    if (rec === undefined || rec.expires_at_ms <= this.#now()) return null;
    const org_id = this.#operators.has(rec.operator) ? (this.#operators.get(rec.operator) ?? null) : rec.org_id;
    return { ...rec, org_id };
  }
  async getAnchor(id: number): Promise<AnchorRecord | null> {
    if (!isUint(id)) return null;
    const a = this.#anchors[id];
    return a === undefined ? null : { ...a };
  }
  /** Returns the configured registration quote for `keyHash` (ignores `offered`), or null. */
  async getRegistrationQuote(keyHash: string, _offered?: Uint8Array): Promise<Uint8Array | null> {
    if (!isHash32(keyHash)) return null;
    const q = this.#regQuotes.get(keyHash);
    return q === undefined ? null : q.slice();
  }
  async anchorCount(): Promise<number> {
    return this.#anchors.length;
  }
}
