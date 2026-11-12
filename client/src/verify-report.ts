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

type CheckKey = keyof typeof CHECKS;
type RegistryMethod = "getRoot" | "isComposeAllowed" | "isOsAllowed" | "getInstance" | "getAnchor";
/** A check line: one of SPEC §9 `CHECKS`. */
type StepKey = CheckKey;

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
 * keeps exactly the SPEC §9 list. INTEL pushes COLLATERAL right before QUOTE_SIG, TCB right after it and
 * COMPOSE_POLICY right after COMPOSE.
 */
const INTEL_ONLY: ReadonlySet<CheckKey> = new Set<CheckKey>(["TCB", "COMPOSE_POLICY", "COLLATERAL"]);

const ALL_CHECKS = Object.keys(CHECKS) as CheckKey[];
const MOCK_ORDER = ALL_CHECKS.filter((k) => !INTEL_ONLY.has(k));
const INTEL_ORDER: CheckKey[] = MOCK_ORDER.flatMap((k) =>
  k === "QUOTE_SIG" ? ["COLLATERAL" as const, k, "TCB" as const] : k === "COMPOSE" ? [k, "COMPOSE_POLICY" as const] : [k],
);

/** SPEC §9 order for MOCK, plus the two INTEL-only steps at their SPEC-TDX §3.1 positions. */
function orderFor(o: { intel?: boolean }): StepKey[] {
  return [...(o.intel === true ? INTEL_ORDER : MOCK_ORDER)];
}

/**
 * CLI wording where it says more than the `CHECKS` name. SPEC §5 rev 1.3: a session quote carries
 * `SHA256("PLR-v1/session-nonce" ‖ nonce)`, never the raw nonce, so it can never double as a registration quote.
 */
const LABELS: Partial<Record<CheckKey, string>> = {
  NONCE: `report_data binds client nonce as a session quote (SHA256("PLR-v1/session-nonce" ‖ nonce))`,
};
const label = (k: StepKey): string => LABELS[k] ?? CHECKS[k];

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
  E_COLLATERAL_FETCH: "COLLATERAL",
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
  code?: PlrErrorCode;
  /** Why a skipped line was not checked, when it is not simply "after the failing check". */
  note?: string;
}

/**
 * Where an INTEL verification took its collateral from: the client's own PCCS fetch (the default; the COLLATERAL
 * line is a real check), the exit's copy (`PLR_PCCS_URL=exit`) or a fixture's recorded copy. In the last two the
 * COLLATERAL line is printed as not checked, with the reason.
 */
export type CollateralMode = "pccs" | "exit" | "recorded";

const COLLATERAL_NOTES: Record<Exclude<CollateralMode, "pccs">, string> = {
  exit: "not checked: PLR_PCCS_URL=exit, the exit's own copy is used",
  recorded: "not checked: offline replay uses the recorded collateral",
};

/**
 * Per-check status. On success every check passed. On failure, `verifyAttestation` runs checks in the fixed
 * SPEC §9 order and stops at the first failure, so every earlier check passed and later ones did not run.
 * `o.intel` (SPEC-TDX §3.1) adds the collateral, TCB and dstack-compose steps; `o.collateral` (default "pccs")
 * says whether the collateral step was a check at all.
 */
export function checkLines(
  err: unknown,
  lastRegistryCall?: RegistryMethod,
  o: { intel?: boolean; collateral?: CollateralMode } = {},
): CheckLine[] {
  const mode = o.collateral ?? "pccs";
  if (mode === "pccs") return rawCheckLines(err, lastRegistryCall, o);
  const note = COLLATERAL_NOTES[mode];
  return rawCheckLines(err, lastRegistryCall, o).map((l) => (l.name === CHECKS.COLLATERAL ? { name: l.name, status: "skipped", note } : l));
}

function rawCheckLines(err: unknown, lastRegistryCall: RegistryMethod | undefined, o: { intel?: boolean }): CheckLine[] {
  const order = orderFor(o);
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
  return `  · ${l.name}  (${l.note ?? "not checked"})`;
}
