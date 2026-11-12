/** Human-readable per-check report of `verifyAttestation` for the CLI (`plr vpn verify`). */
import {
  CHECKS,
  PlrError,
  type AnchorRecord,
  type InstanceRecord,
  type PlrErrorCode,
  type RegistryReader,
  type RegistryRoot,
} from "@plr/shared";
import { E_REGISTRY_CODE_HASH, isRegistryCodeHashError } from "./near-registry.js";

type CheckKey = keyof typeof CHECKS;
type RegistryMethod = "getRoot" | "isComposeAllowed" | "isOsAllowed" | "getInstance" | "getAnchor";
/**
 * A check line: one of SPEC §9 `CHECKS`, or the client's own registry code-hash check (`REGISTRY_CODE`), which
 * runs first of all, before the exit is asked for its attestation and before any registry view.
 */
type StepKey = CheckKey | "REGISTRY_CODE";

/** Name of the registry code-hash check line (shown only when the registry has a code-hash pin). */
export const REGISTRY_CODE_LINE = "registry contract code hash matches the pinned build (view_account.code_hash)";

/** State of the registry code-hash pin for a report: no pin (undefined), or whether the last check passed. */
export type CodeHashState = "verified" | "unverified" | undefined;

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
  /** The inner reader's code-hash pin state (a `NearRegistry` with `codeHash`), else undefined. */
  get codeHashState(): CodeHashState {
    const v = (this.inner as { codeHashVerified?: unknown }).codeHashVerified;
    return v === true ? "verified" : v === false ? "unverified" : undefined;
  }
  /** Forwards the inner reader's code-hash check (no-op for a reader without one). */
  checkCodeHash(): Promise<void> {
    const f = (this.inner as { checkCodeHash?: unknown }).checkCodeHash;
    return typeof f === "function" ? (f as () => Promise<void>).call(this.inner) : Promise.resolve();
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

/**
 * Checks that only an INTEL verification reports (SPEC-TDX §3.1): MOCK never pushes them, so the MOCK report
 * keeps exactly the SPEC §9 list. INTEL pushes TCB right after QUOTE_SIG and COMPOSE_POLICY right after COMPOSE.
 */
const INTEL_ONLY: ReadonlySet<CheckKey> = new Set<CheckKey>(["TCB", "COMPOSE_POLICY"]);

const ALL_CHECKS = Object.keys(CHECKS) as CheckKey[];
const MOCK_ORDER = ALL_CHECKS.filter((k) => !INTEL_ONLY.has(k));
const INTEL_ORDER: CheckKey[] = MOCK_ORDER.flatMap((k) =>
  k === "QUOTE_SIG" ? [k, "TCB" as const] : k === "COMPOSE" ? [k, "COMPOSE_POLICY" as const] : [k],
);

export interface CheckLineOptions {
  intel?: boolean;
  /** Set (pinned registry) ⇒ the code-hash line is listed, as the first check. */
  codeHash?: CodeHashState;
}

/**
 * SPEC §9 order for MOCK, plus the two INTEL-only steps at their SPEC-TDX §3.1 positions; for a pinned registry
 * the code-hash check comes first (it runs before anything else).
 */
function orderFor(o: CheckLineOptions): StepKey[] {
  const base: StepKey[] = [...(o.intel === true ? INTEL_ORDER : MOCK_ORDER)];
  return o.codeHash === undefined ? base : ["REGISTRY_CODE", ...base];
}

/**
 * CLI wording where it says more than the `CHECKS` name. SPEC §5 rev 1.3: a session quote carries
 * `SHA256("PLR-v1/session-nonce" ‖ nonce)`, never the raw nonce, so it can never double as a registration quote.
 */
const LABELS: Partial<Record<CheckKey, string>> = {
  NONCE: `report_data binds client nonce as a session quote (SHA256("PLR-v1/session-nonce" ‖ nonce))`,
};
const label = (k: StepKey): string => (k === "REGISTRY_CODE" ? REGISTRY_CODE_LINE : (LABELS[k] ?? CHECKS[k]));

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
  E_TCB_STATUS: "TCB",
  E_COLLATERAL: "QUOTE_SIG",
  E_COMPOSE_POLICY: "COMPOSE_POLICY",
};

const REGISTRY_STEP: Record<RegistryMethod, StepKey> = {
  getRoot: "ROOT",
  isComposeAllowed: "COMPOSE_ALLOWED",
  isOsAllowed: "OS_ALLOWED",
  getInstance: "INSTANCE",
  getAnchor: "INSTANCE",
};

export type CheckStatus = "pass" | "fail" | "skipped";
export interface CheckLine {
  name: string;
  status: CheckStatus;
  code?: PlrErrorCode | typeof E_REGISTRY_CODE_HASH;
}

/**
 * Per-check status. On success every check passed. On failure, `verifyAttestation` runs checks in the fixed
 * SPEC §9 order and stops at the first failure, so every earlier check passed and later ones did not run.
 * `o.intel` (SPEC-TDX §3.1) adds the TCB and dstack-compose steps; `o.codeHash` adds the registry code-hash step.
 */
export function checkLines(
  err: unknown,
  lastRegistryCall?: RegistryMethod,
  o: CheckLineOptions = {},
): CheckLine[] {
  const order = orderFor(o);
  if (err === undefined) return order.map((k) => ({ name: label(k), status: "pass" }));
  const code: PlrErrorCode | typeof E_REGISTRY_CODE_HASH = isRegistryCodeHashError(err) ? E_REGISTRY_CODE_HASH : err instanceof PlrError ? err.code : "E_BAD_RESPONSE";
  let failing: StepKey | undefined = code === E_REGISTRY_CODE_HASH ? "REGISTRY_CODE" : CODE_TO_CHECK[code];
  if (code === "E_REGISTRY_UNAVAILABLE") {
    failing = lastRegistryCall ? REGISTRY_STEP[lastRegistryCall] : "ROOT";
    // the account could not be read, so its code hash was never confirmed: that is the step that failed
    if (o.codeHash === "unverified") failing = "REGISTRY_CODE";
  }
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
