/** Human-readable per-check report of `verifyAttestation` for the CLI (`plr verify`). */
import {
  CHECKS,
  REGISTRATION_EVIDENCE_CHECK,
  PlrError,
  type AnchorRecord,
  type InstanceRecord,
  type PlrErrorCode,
  type RegistryReader,
  type RegistryRoot,
} from "@plr/shared";

type CheckKey = keyof typeof CHECKS;
type RegistryMethod = "getRoot" | "isComposeAllowed" | "isOsAllowed" | "getInstance" | "getAnchor" | "getRegistrationQuote";
/** A check line: one of SPEC §9 `CHECKS`, or SPEC-CHAINS §2 registration evidence (step 9b). */
type StepKey = CheckKey | "REGISTRATION_EVIDENCE";

/** Registry wrapper that remembers the last method called, to attribute E_REGISTRY_UNAVAILABLE to a step. */
export class TracingRegistry implements RegistryReader {
  lastCall: RegistryMethod | undefined;
  constructor(readonly inner: RegistryReader) {}
  get chain(): string {
    return this.inner.chain;
  }
  get contractId(): string {
    return this.inner.contractId;
  }
  /** Forwarded strictly: anything but an explicit `true` counts as false (fail closed). */
  get verifiesOnChain(): boolean {
    try {
      return this.inner.verifiesOnChain === true;
    } catch {
      return false;
    }
  }
  getRegistrationQuote(keyHash: string, offered?: Uint8Array): Promise<Uint8Array | null> {
    this.lastCall = "getRegistrationQuote";
    return this.inner.getRegistrationQuote(keyHash, offered);
  }
  getRoot(): Promise<RegistryRoot> {
    this.lastCall = "getRoot";
    return this.inner.getRoot();
  }
  isComposeAllowed(h: string): Promise<boolean> {
    this.lastCall = "isComposeAllowed";
    return this.inner.isComposeAllowed(h);
  }
  isOsAllowed(h: string): Promise<boolean> {
    this.lastCall = "isOsAllowed";
    return this.inner.isOsAllowed(h);
  }
  getInstance(keyHash: string): Promise<InstanceRecord | null> {
    this.lastCall = "getInstance";
    return this.inner.getInstance(keyHash);
  }
  getAnchor(id: number): Promise<AnchorRecord | null> {
    this.lastCall = "getAnchor";
    return this.inner.getAnchor(id);
  }
}

const ORDER = Object.keys(CHECKS) as CheckKey[];
const ORDER_WITH_EVIDENCE: StepKey[] = [...ORDER, "REGISTRATION_EVIDENCE"];

/**
 * CLI wording where it says more than the `CHECKS` name. SPEC §5 rev 1.3: a session quote carries
 * `SHA256("PLR-v1/session-nonce" ‖ nonce)`, never the raw nonce, so it can never double as a registration quote.
 */
const LABELS: Partial<Record<CheckKey, string>> = {
  NONCE: `report_data binds client nonce as a session quote (SHA256("PLR-v1/session-nonce" ‖ nonce))`,
};
const label = (k: StepKey): string => (k === "REGISTRATION_EVIDENCE" ? REGISTRATION_EVIDENCE_LABEL : (LABELS[k] ?? CHECKS[k]));

/** SPEC-CHAINS §2 wording for `plr verify`. */
export const REGISTRATION_EVIDENCE_LABEL = `${REGISTRATION_EVIDENCE_CHECK} (registration evidence: the chain does not verify quotes)`;

const CODE_TO_CHECK: Partial<Record<PlrErrorCode, StepKey>> = {
  E_BAD_RESPONSE: "RESPONSE",
  E_QUOTE_FORMAT: "QUOTE_FORMAT",
  E_TEE_TYPE: "TEE_TYPE",
  E_ROOT_UNTRUSTED: "ROOT",
  E_QUOTE_SIG: "QUOTE_SIG",
  E_DEBUG_TD: "DEBUG",
  E_REPORT_DATA_KEYS: "REPORT_DATA_KEYS",
  E_NONCE: "NONCE",
  E_EVENT_LOG: "EVENT_LOG",
  E_RTMR3: "RTMR3",
  E_COMPOSE_MISMATCH: "COMPOSE",
  E_COMPOSE_NOT_ALLOWED: "COMPOSE_ALLOWED",
  E_OS_NOT_ALLOWED: "OS_ALLOWED",
  E_INSTANCE_NOT_REGISTERED: "INSTANCE",
  E_REGISTRATION_EVIDENCE: "REGISTRATION_EVIDENCE",
};

const REGISTRY_STEP: Record<RegistryMethod, StepKey> = {
  getRoot: "ROOT",
  isComposeAllowed: "COMPOSE_ALLOWED",
  isOsAllowed: "OS_ALLOWED",
  getInstance: "INSTANCE",
  getAnchor: "INSTANCE",
  getRegistrationQuote: "REGISTRATION_EVIDENCE",
};

export type CheckStatus = "pass" | "fail" | "skipped";
export interface CheckLine {
  name: string;
  status: CheckStatus;
  code?: PlrErrorCode;
}

/**
 * Per-check status. On success every check passed. On failure, `verifyAttestation` runs checks in the fixed
 * SPEC §9 order and stops at the first failure, so every earlier check passed and later ones did not run.
 * `o.evidence` (registries with `verifiesOnChain` false, SPEC-CHAINS §2) adds the registration-evidence step
 * after the instance check.
 */
export function checkLines(err: unknown, lastRegistryCall?: RegistryMethod, o: { evidence?: boolean } = {}): CheckLine[] {
  const order: StepKey[] = o.evidence === true ? ORDER_WITH_EVIDENCE : ORDER;
  if (err === undefined) return order.map((k) => ({ name: label(k), status: "pass" }));
  const code: PlrErrorCode = err instanceof PlrError ? err.code : "E_BAD_RESPONSE";
  let failing: StepKey | undefined = CODE_TO_CHECK[code];
  if (code === "E_REGISTRY_UNAVAILABLE") failing = lastRegistryCall ? REGISTRY_STEP[lastRegistryCall] : "ROOT";
  const found = failing === undefined ? -1 : order.indexOf(failing);
  const idx = found < 0 ? 0 : found;
  return order.map((k, i) => {
    if (i < idx) return { name: label(k), status: "pass" };
    if (i === idx) return { name: label(k), status: "fail", code };
    return { name: label(k), status: "skipped" };
  });
}

export function formatCheckLine(l: CheckLine): string {
  if (l.status === "pass") return `  ✔ ${l.name}`;
  if (l.status === "fail") return `  ✘ ${l.name}  [${l.code ?? "?"}]`;
  return `  · ${l.name}  (not checked)`;
}
