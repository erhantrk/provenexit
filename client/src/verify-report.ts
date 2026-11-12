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
import { E_REGISTRY_CODE_HASH, E_REGISTRY_RPC_DISAGREE, isRegistryCodeHashError, isRegistryRpcDisagreeError } from "./near-registry.js";
import { COLLATERAL_LINE, E_COLLATERAL_FETCH, isCollateralFetchError } from "./pccs.js";

type CheckKey = keyof typeof CHECKS;
type RegistryMethod = "getRoot" | "isComposeAllowed" | "isOsAllowed" | "getInstance" | "getAnchor";
/**
 * A check line: one of SPEC §9 `CHECKS`, or one of the client's own two checks: the registry code-hash check
 * (`REGISTRY_CODE`), which runs first of all, before the exit is asked for its attestation and before any registry
 * view, and the fresh-collateral check (`COLLATERAL`, INTEL only), which runs right before the signature check.
 */
type StepKey = CheckKey | "REGISTRY_CODE" | "COLLATERAL";
/** Error codes a check line can carry: the shared ones plus the client's own three. */
type LineCode = PlrErrorCode | typeof E_REGISTRY_CODE_HASH | typeof E_REGISTRY_RPC_DISAGREE | typeof E_COLLATERAL_FETCH;

/** Name of the registry code-hash check line (shown only when the registry has a code-hash pin). */
export const REGISTRY_CODE_LINE = "registry contract code hash matches the pinned build (view_account.code_hash)";

/** State of the registry code-hash pin for a report: no pin (undefined), or whether the last check passed. */
export type CodeHashState = "verified" | "unverified" | undefined;

/**
 * Registry wrapper that remembers the last method called, to attribute E_REGISTRY_UNAVAILABLE and
 * E_REGISTRY_RPC_DISAGREE to a step.
 */
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
 * keeps exactly the SPEC §9 list. INTEL pushes TCB right after QUOTE_SIG and COMPOSE_POLICY right after COMPOSE;
 * the client's own COLLATERAL step (its PCCS fetch) sits right before QUOTE_SIG.
 */
const INTEL_ONLY: ReadonlySet<CheckKey> = new Set<CheckKey>(["TCB", "COMPOSE_POLICY"]);

const ALL_CHECKS = Object.keys(CHECKS) as CheckKey[];
const MOCK_ORDER = ALL_CHECKS.filter((k) => !INTEL_ONLY.has(k));
const INTEL_ORDER: StepKey[] = MOCK_ORDER.flatMap((k) =>
  k === "QUOTE_SIG" ? ["COLLATERAL" as const, k, "TCB" as const] : k === "COMPOSE" ? [k, "COMPOSE_POLICY" as const] : [k],
);

export interface CheckLineOptions {
  intel?: boolean;
  /** INTEL only: whether the collateral step was a check at all (default "pccs": it was). */
  collateral?: CollateralMode;
  /** Set (pinned registry) ⇒ the code-hash line is listed, as the first check. */
  codeHash?: CodeHashState;
}

/**
 * SPEC §9 order for MOCK, plus the INTEL-only steps at their SPEC-TDX §3.1 positions; for a pinned registry
 * the code-hash check comes first (it runs before anything else).
 */
function orderFor(o: CheckLineOptions): StepKey[] {
  const base: StepKey[] = [...(o.intel === true ? INTEL_ORDER : MOCK_ORDER)];
  return o.codeHash === undefined ? base : ["REGISTRY_CODE", ...base];
}

/**
 * Client wording where it says more than the `CHECKS` name, or says it better. SPEC §5 rev 1.3: a session quote carries
 * `SHA256("PLR-v1/session-nonce" ‖ nonce)`, never the raw nonce, so it can never double as a registration quote.
 */
const LABELS: Partial<Record<CheckKey, string>> = {
  // the `CHECKS` name still says "router keys" (the wording of the earlier LLM router); the keys are the exit's
  REPORT_DATA_KEYS: "report_data binds the exit's keys",
  NONCE: `report_data binds client nonce as a session quote (SHA256("PLR-v1/session-nonce" ‖ nonce))`,
};
const label = (k: StepKey): string =>
  k === "REGISTRY_CODE" ? REGISTRY_CODE_LINE : k === "COLLATERAL" ? COLLATERAL_LINE : (LABELS[k] ?? CHECKS[k]);

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
  code?: LineCode;
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
 * says whether the collateral step was a check at all; `o.codeHash` adds the registry code-hash step.
 */
export function checkLines(
  err: unknown,
  lastRegistryCall?: RegistryMethod,
  o: CheckLineOptions = {},
): CheckLine[] {
  const mode = o.collateral ?? "pccs";
  if (mode === "pccs") return rawCheckLines(err, lastRegistryCall, o);
  const note = COLLATERAL_NOTES[mode];
  return rawCheckLines(err, lastRegistryCall, o).map((l) => (l.name === COLLATERAL_LINE ? { name: l.name, status: "skipped", note } : l));
}

function rawCheckLines(err: unknown, lastRegistryCall: RegistryMethod | undefined, o: CheckLineOptions): CheckLine[] {
  const order = orderFor(o);
  if (err === undefined) return order.map((k) => ({ name: label(k), status: "pass" }));
  const code: LineCode = isRegistryCodeHashError(err)
    ? E_REGISTRY_CODE_HASH
    : isRegistryRpcDisagreeError(err)
      ? E_REGISTRY_RPC_DISAGREE
      : isCollateralFetchError(err)
        ? E_COLLATERAL_FETCH
        : err instanceof PlrError
          ? err.code
          : "E_BAD_RESPONSE";
  let failing: StepKey | undefined =
    code === E_REGISTRY_CODE_HASH ? "REGISTRY_CODE"
    : code === E_COLLATERAL_FETCH ? "COLLATERAL"
    : code === E_REGISTRY_RPC_DISAGREE ? undefined // set just below, like an unreadable registry
    : CODE_TO_CHECK[code];
  // An unreadable registry and RPC endpoints that disagree both fail the check whose registry query it was.
  if (code === "E_REGISTRY_UNAVAILABLE" || code === E_REGISTRY_RPC_DISAGREE) {
    failing = lastRegistryCall ? REGISTRY_STEP[lastRegistryCall] : "ROOT";
    // the account could not be read (or the endpoints report different code hashes), so its code hash was never
    // confirmed: that is the step that failed
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
  return `  · ${l.name}  (${l.note ?? "not checked"})`;
}
