/** Human-readable per-check report of `verifyAttestation` for the CLI (`plr verify`). */
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

const ORDER = Object.keys(CHECKS) as CheckKey[];

const CODE_TO_CHECK: Partial<Record<PlrErrorCode, CheckKey>> = {
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
};

const REGISTRY_STEP: Record<RegistryMethod, CheckKey> = {
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
}

/**
 * Per-check status. On success every check passed. On failure, `verifyAttestation` runs checks in the fixed
 * SPEC §9 order and stops at the first failure, so every earlier check passed and later ones did not run.
 */
export function checkLines(err: unknown, lastRegistryCall?: RegistryMethod): CheckLine[] {
  if (err === undefined) return ORDER.map((k) => ({ name: CHECKS[k], status: "pass" }));
  const code: PlrErrorCode = err instanceof PlrError ? err.code : "E_BAD_RESPONSE";
  let failing: CheckKey | undefined = CODE_TO_CHECK[code];
  if (code === "E_REGISTRY_UNAVAILABLE") failing = lastRegistryCall ? REGISTRY_STEP[lastRegistryCall] : "ROOT";
  const idx = failing === undefined ? 0 : ORDER.indexOf(failing);
  return ORDER.map((k, i) => {
    if (i < idx) return { name: CHECKS[k], status: "pass" };
    if (i === idx) return { name: CHECKS[k], status: "fail", code };
    return { name: CHECKS[k], status: "skipped" };
  });
}

export function formatCheckLine(l: CheckLine): string {
  if (l.status === "pass") return `  ✔ ${l.name}`;
  if (l.status === "fail") return `  ✘ ${l.name}  [${l.code ?? "?"}]`;
  return `  · ${l.name}  (not checked)`;
}
