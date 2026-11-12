/**
 * The registry writer (SPEC §7): the operations the VPN exit performs on its registry — registration, anchoring and
 * the reads needed to resynchronise anchoring state. Implementation: NEAR (`near.ts`); faked in unit tests.
 */
import { isHex, type TdxEvent } from "@plr/shared";

export interface RegisterArgs {
  quote: string;
  event_log: TdxEvent[];
  app_compose: string;
  x25519: string;
  ed25519: string;
  /**
   * INTEL mode: the canonical collateral JSON text (SPEC-TDX §1.2). Its presence selects `register_instance_tdx`
   * on NEAR; MOCK registrations never carry it.
   */
  collateral?: string;
}

export interface AnchorArgs {
  key_hash: string;
  root: string;
  first_seq: number;
  count: number;
  sig: string;
}

export interface AnchorView {
  id: number;
  key_hash: string;
  root: string;
  first_seq: number;
  count: number;
}

/** What the instance needs from its registry chain. Faked in unit tests. */
export interface RegistryWriter {
  /** The registry contract account id, bound into the registration quote and every anchor signature. */
  readonly contractId: string;
  /** The account that signs this instance's transactions (its on-chain `operator`, SPEC §7 rev 1.2). */
  readonly operatorId: string;
  registerInstance(args: RegisterArgs): Promise<void>;
  /** Returns the chain's return value (the anchor id if the chain returns one). */
  anchorReceipts(args: AnchorArgs): Promise<unknown>;
  getInstanceNextSeq(keyHash: string): Promise<number | null>;
  /** The `operator` account recorded for the instance, or null if it is not (or no longer) registered. */
  getInstanceOperator(keyHash: string): Promise<string | null>;
  anchorCount(): Promise<number>;
  getAnchor(id: number): Promise<AnchorView | null>;
  /** Releases background resources (timers, sockets). Optional. */
  close?(): void;
}

export const isUint = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

export function isAnchorView(a: unknown): a is AnchorView {
  if (typeof a !== "object" || a === null) return false;
  const r = a as Record<string, unknown>;
  return isUint(r.id) && isHex(r.key_hash, 32) && isHex(r.root, 32) && isUint(r.first_seq) && isUint(r.count);
}
