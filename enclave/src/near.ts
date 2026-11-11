/**
 * NEAR implementation of the registry operations the router performs (SPEC §7): `register_instance`,
 * `anchor_receipts` and the views needed to resynchronise anchoring state. Every view result is
 * shape-checked; nothing returned by the RPC is trusted blindly.
 */
import { Account, JsonRpcProvider, KeyPairSigner, type KeyPairString } from "near-api-js";
import { PlrError } from "@plr/shared";
import { isAnchorView, isUint, type AnchorArgs, type AnchorView, type RegisterArgs, type RegistryWriter } from "./registry-writer.js";

export type { AnchorArgs, AnchorView, RegisterArgs, RegistryWriter } from "./registry-writer.js";
export { isAnchorView } from "./registry-writer.js";

export const NEAR_ACCOUNT_RE = /^(?=.{2,64}$)(?:(?:[a-z\d]+[-_])*[a-z\d]+\.)*(?:[a-z\d]+[-_])*[a-z\d]+$/;
export const NEAR_KEY_RE = /^ed25519:[1-9A-HJ-NP-Za-km-z]{32,128}$/;
const TGAS = 1_000_000_000_000n;

export class NearRegistryWriter implements RegistryWriter {
  readonly contractId: string;
  readonly operatorId: string;
  readonly #provider: JsonRpcProvider;
  readonly #account: Account;
  readonly #deposit: bigint;
  readonly #anchorDeposit: bigint;

  constructor(o: { rpcUrl: string; contractId: string; operatorId: string; operatorKey: string; registerDeposit: bigint; anchorDeposit?: bigint }) {
    if (!NEAR_ACCOUNT_RE.test(o.contractId) || !NEAR_ACCOUNT_RE.test(o.operatorId)) throw new PlrError("E_BAD_INPUT", "account id");
    if (!NEAR_KEY_RE.test(o.operatorKey)) throw new PlrError("E_BAD_INPUT", "operator key");
    this.contractId = o.contractId;
    this.operatorId = o.operatorId;
    this.#provider = new JsonRpcProvider({ url: o.rpcUrl });
    this.#account = new Account(o.operatorId, this.#provider, KeyPairSigner.fromSecretKey(o.operatorKey as KeyPairString));
    this.#deposit = o.registerDeposit;
    this.#anchorDeposit = o.anchorDeposit ?? 0n;
    if (this.#deposit < 0n || this.#anchorDeposit < 0n) throw new PlrError("E_BAD_INPUT", "deposit");
  }

  async #view(method: string, args: Record<string, unknown>): Promise<unknown> {
    return this.#provider.callFunction({ contractId: this.contractId, method, args });
  }

  async #call(methodName: string, args: object, deposit: bigint): Promise<unknown> {
    return this.#account.callFunction({ contractId: this.contractId, methodName, args: args as Record<string, unknown>, gas: 300n * TGAS, deposit });
  }

  async registerInstance(args: RegisterArgs): Promise<void> {
    // INTEL mode registers through the on-chain DCAP-verifying method (INTERFACES §2.3); same gas + deposit.
    await this.#call(args.collateral ? "register_instance_tdx" : "register_instance", args, this.#deposit);
  }

  /** Attaches the anchor storage deposit (excess refunded by the contract; shortfall drawn from the prepaid credit). */
  anchorReceipts(args: AnchorArgs): Promise<unknown> {
    return this.#call("anchor_receipts", args, this.#anchorDeposit);
  }

  /** The deposit attached to each `anchor_receipts` call (yoctoNEAR). */
  get anchorDeposit(): bigint {
    return this.#anchorDeposit;
  }

  async getInstanceNextSeq(keyHash: string): Promise<number | null> {
    const r = await this.#view("get_instance", { key_hash: keyHash });
    if (r === null || r === undefined) return null;
    if (typeof r !== "object" || !isUint((r as Record<string, unknown>).next_seq)) throw new PlrError("E_BAD_RESPONSE", "get_instance");
    return (r as { next_seq: number }).next_seq;
  }

  async getInstanceOperator(keyHash: string): Promise<string | null> {
    const r = await this.#view("get_instance", { key_hash: keyHash });
    if (r === null || r === undefined) return null;
    const op = typeof r === "object" ? (r as Record<string, unknown>).operator : undefined;
    if (typeof op !== "string" || !NEAR_ACCOUNT_RE.test(op)) throw new PlrError("E_BAD_RESPONSE", "get_instance");
    return op;
  }

  async anchorCount(): Promise<number> {
    const n = await this.#view("anchor_count", {});
    if (!isUint(n)) throw new PlrError("E_BAD_RESPONSE", "anchor_count");
    return n;
  }

  async getAnchor(id: number): Promise<AnchorView | null> {
    const a = await this.#view("get_anchor", { id });
    if (a === null || a === undefined) return null;
    if (!isAnchorView(a)) throw new PlrError("E_BAD_RESPONSE", "get_anchor");
    return a;
  }
}
