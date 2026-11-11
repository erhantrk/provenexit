/**
 * Fixture replay (INTERFACES §3.3): `plr vpn verify --fixture <dir>` re-verifies a recorded attestation bundle
 * against the recorded registry snapshot. The DCAP check runs at the capture time, so a fixture verifies
 * forever and needs no network. What it proves is that the recorded exit was genuine at capture time.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  DcapQvlVerifier,
  INTEL_ROOT_P256,
  MemoryRegistry,
  PlrError,
  fromHex,
  isHex,
  verifyAttestation,
  type AttestationBundle,
  type InstanceRecord,
  type MemoryRegistryOptions,
  type QuoteVerifier,
  type VerifiedRouter,
} from "@plr/shared";
import { isPlainObject } from "./util.js";

/** `meta.json` of a fixture directory (INTERFACES §3.3). */
export interface FixtureMeta {
  captured_at_ms: number;
  exit_url: string;
  network: string;
  registry: string;
  registration_tx: string;
  revocation_tx: string | null;
  note?: string;
}

/** The four files of a fixture directory, parsed. */
export interface Fixture {
  meta: FixtureMeta;
  /** The nonce the capture used (the bundle's report_data binds it). */
  nonce: Uint8Array;
  bundle: AttestationBundle;
  /** Registry snapshot, ready for {@link MemoryRegistry}. */
  registry: MemoryRegistryOptions;
}

const bad = (what: string): never => {
  throw new PlrError("E_BAD_INPUT", `fixture: ${what}`);
};

function readJson(dir: string, name: string): unknown {
  let text: string;
  try {
    text = readFileSync(join(dir, name), "utf8");
  } catch {
    return bad(`cannot read ${name}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return bad(`${name} is not JSON`);
  }
}

function str(v: unknown, what: string): string {
  return typeof v === "string" && v.length > 0 ? v : bad(what);
}

function parseMeta(v: unknown): FixtureMeta {
  if (!isPlainObject(v)) return bad("meta.json is not an object");
  const at = v.captured_at_ms;
  if (typeof at !== "number" || !Number.isSafeInteger(at) || at < 0) bad("meta.json captured_at_ms");
  const revocation = v.revocation_tx;
  if (revocation !== undefined && revocation !== null && typeof revocation !== "string") bad("meta.json revocation_tx");
  return {
    captured_at_ms: at as number,
    exit_url: str(v.exit_url, "meta.json exit_url"),
    network: str(v.network, "meta.json network"),
    registry: str(v.registry, "meta.json registry"),
    registration_tx: str(v.registration_tx, "meta.json registration_tx"),
    revocation_tx: typeof revocation === "string" ? revocation : null,
    ...(typeof v.note === "string" ? { note: v.note } : {}),
  };
}

/** Registry snapshot → {@link MemoryRegistryOptions}: tier A, clocked at the capture (INTERFACES §3.3). */
function registryOptions(v: unknown, meta: FixtureMeta): MemoryRegistryOptions {
  if (!isPlainObject(v)) return bad("registry.json is not an object");
  const root = v.root;
  if (!isPlainObject(root) || root.kind !== "INTEL" || typeof root.p256 !== "string") bad("registry root");
  if (!Array.isArray(v.compose) || !Array.isArray(v.os) || !isPlainObject(v.instances)) bad("registry snapshot");
  return {
    root: { kind: "INTEL", p256: (root as { p256: string }).p256 },
    compose: v.compose as string[],
    os: v.os as string[],
    instances: v.instances as Record<string, InstanceRecord>,
    chain: "near",
    contractId: meta.registry,
    verifiesOnChain: true,
    now: () => meta.captured_at_ms,
  };
}

/**
 * Reads the four files of `dir`: `meta.json`, `nonce.hex`, `bundle.json`, `registry.json`.
 * @throws PlrError E_BAD_INPUT on a missing or malformed file
 */
export function readFixture(dir: string): Fixture {
  const meta = parseMeta(readJson(dir, "meta.json"));
  let nonceHex: string;
  try {
    nonceHex = readFileSync(join(dir, "nonce.hex"), "utf8").trim();
  } catch {
    return bad("cannot read nonce.hex");
  }
  if (!isHex(nonceHex, 32)) return bad("nonce.hex is not 64 lowercase hex chars");
  const bundle = readJson(dir, "bundle.json");
  if (!isPlainObject(bundle)) return bad("bundle.json is not an object");
  return {
    meta,
    nonce: fromHex(nonceHex, 32),
    bundle: bundle as unknown as AttestationBundle,
    registry: registryOptions(readJson(dir, "registry.json"), meta),
  };
}

/**
 * The verifier {@link verifyFixture} uses by default: the real DCAP verifier pinned to the Intel root and clocked
 * at the capture time (INTERFACES §3.3), so a recorded bundle verifies forever. Exported so a test can pin the
 * clock hook itself: `verify` without `ctx.nowSecs` must use `captured_at_ms`.
 */
export function fixtureVerifier(meta: FixtureMeta): DcapQvlVerifier {
  return new DcapQvlVerifier(INTEL_ROOT_P256, { clock: () => meta.captured_at_ms });
}

/**
 * INTERFACES §3.3: `verifyAttestation` over the recorded bundle, with the DCAP check at `captured_at_ms` and the
 * registry snapshot read through {@link MemoryRegistry} (`verifiesOnChain: true`, clock = `captured_at_ms`).
 * `verifier` exists for tests only: a synthetic fixture has no real Intel signature, so it needs a stub verifier.
 * @throws PlrError — the failing check's code (E_BAD_RESPONSE, E_QUOTE_*, E_COMPOSE_*, …)
 */
export async function verifyFixture(dir: string, verifier?: QuoteVerifier): Promise<VerifiedRouter> {
  const f = readFixture(dir);
  return verifyAttestation({
    bundle: f.bundle,
    nonce: f.nonce,
    verifier: verifier ?? fixtureVerifier(f.meta),
    registry: new MemoryRegistry(f.registry),
    trustedRoot: INTEL_ROOT_P256,
    now: f.meta.captured_at_ms,
  });
}

/** Final line of a fixture replay (INTERFACES §3.3). */
export function fixtureReplayLine(meta: FixtureMeta): string {
  const captured = new Date(meta.captured_at_ms).toISOString();
  return `✔ VERIFIED (FIXTURE REPLAY of ${meta.exit_url}, captured ${captured}; registry snapshot of ${meta.registry}; registration tx ${meta.registration_tx})`;
}
