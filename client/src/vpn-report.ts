/**
 * The two lines of `plr vpn verify` that are not SPEC §9 checks, and the data form of that report: the same ordered
 * check list `plr vpn verify` prints, as `{name, ok, detail}` (used by the status bundle and the MCP server).
 */
import { toHex, type VerifiedRouter } from "@plr/shared";
import { recheckRegistry, type AttestationSession } from "./attestation.js";
import { TracingRegistry, checkLines, type CheckLine, type CodeHashState } from "./verify-report.js";
import type { VpnClient } from "./vpn/client.js";
import { isPlrError } from "@plr/shared";

export const RECHECK_LINE = "registry re-check before each connection (compose, OS, instance)";
export const REMOTE_DNS_LINE = "destinations resolved by the exit (remote DNS); the client never resolves them";

export interface VerifyCheck {
  name: string;
  ok: boolean;
  /** "" when ok; the error code of the failing check; "not checked" for checks after the failing one. */
  detail: string;
}

export interface VerifyReport {
  verdict: "VERIFIED" | "REFUSED";
  /** The error code when REFUSED, else null. */
  code: string | null;
  root: "INTEL" | "MOCK";
  checks: VerifyCheck[];
  /** Set iff VERIFIED. */
  session?: AttestationSession;
  /** The refusing error was the registry being unreadable (E_REGISTRY_UNAVAILABLE). */
  registryUnavailable: boolean;
}

const errCode = (e: unknown): string => (isPlrError(e) ? e.code : e instanceof Error ? e.message : "error");

const fromLine = (l: CheckLine): VerifyCheck => ({
  name: l.name,
  ok: l.status === "pass",
  detail: l.status === "pass" ? "" : l.status === "fail" ? (l.code ?? "error") : "not checked",
});

/**
 * Runs exactly what `plr vpn verify` runs (attest, registry re-check) and returns the ordered check list
 * (INTEL: 16 lines, 17 with the registry code-hash line of a pinned registry, + re-check + remote DNS). Never throws.
 */
export async function verifyVpnReport(client: VpnClient, registry: TracingRegistry): Promise<VerifyReport> {
  const root = client.rootKind;
  const intel = root === "INTEL";
  const opts = (): { intel: boolean; codeHash: CodeHashState } => ({ intel, codeHash: registry.codeHashState });
  const refused = (e: unknown, lines: CheckLine[], recheck: "skip" | "fail"): VerifyReport => {
    const code = errCode(e);
    const checks = lines.map(fromLine);
    checks.push({ name: RECHECK_LINE, ok: false, detail: recheck === "fail" ? code : "not checked" });
    checks.push({ name: REMOTE_DNS_LINE, ok: false, detail: "not checked" });
    return { verdict: "REFUSED", code, root, checks, registryUnavailable: code === "E_REGISTRY_UNAVAILABLE" };
  };
  let session: AttestationSession;
  try {
    session = await client.attestSession();
  } catch (e) {
    return refused(e, checkLines(e, registry.lastCall, opts()), "skip");
  }
  const passed = checkLines(undefined, undefined, opts());
  try {
    await recheckRegistry(registry, session.verified);
  } catch (e) {
    return refused(e, passed, "fail");
  }
  const checks = passed.map(fromLine);
  checks.push({ name: RECHECK_LINE, ok: true, detail: "" }, { name: REMOTE_DNS_LINE, ok: true, detail: "" });
  return { verdict: "VERIFIED", code: null, root, checks, session, registryUnavailable: false };
}

/** Compose facts of a verified exit (dstack app-compose, SPEC-TDX §1.4). */
export interface ComposeFacts {
  hash: string;
  image: string | null;
  logging: string | null;
  allowed_ports: number[] | null;
  max_tunnels: number | null;
}

/** Reads the measured compose (its hash was verified against the quote) for what the site shows. Never throws. */
export function composeFacts(verified: Pick<VerifiedRouter, "composeHash" | "images">, appCompose: string): ComposeFacts {
  let yaml = "";
  try {
    const j = JSON.parse(appCompose) as { docker_compose_file?: unknown };
    if (typeof j.docker_compose_file === "string") yaml = j.docker_compose_file;
  } catch {
    /* unparseable: facts stay null */
  }
  const logging = /^\s*logging:\s*\n\s*driver:\s*"?([\w-]+)"?/m.exec(yaml)?.[1] ?? null;
  const ports = /^\s*PLR_VPN_ALLOWED_PORTS:\s*"?([\d,\s]+?)"?\s*$/m.exec(yaml)?.[1];
  const max = /^\s*PLR_VPN_MAX_TUNNELS:\s*"?(\d+)"?\s*$/m.exec(yaml)?.[1];
  const allowed = ports === undefined ? null : ports.split(",").map((p) => Number(p.trim())).filter((n) => Number.isInteger(n));
  return {
    hash: toHex(verified.composeHash),
    image: verified.images?.[0] ?? /^\s*image:\s*(\S+)\s*$/m.exec(yaml)?.[1] ?? null,
    logging,
    allowed_ports: allowed,
    max_tunnels: max === undefined ? null : Number(max),
  };
}
