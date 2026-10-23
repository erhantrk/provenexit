/**
 * `app-compose.json` (SPEC §4): canonical serialisation (used by the build) and strict parsing (used by the
 * mock TDX host and the router). Verifiers hash the bytes received; this module never re-serialises
 * something it was given.
 */
import { PlrError, isHex } from "@plr/shared";

/** Upper bound for a compose document (SPEC §7: app_compose ≤ 8 KiB). */
export const MAX_COMPOSE_BYTES = 8 * 1024;

export type LlmKind = "llama.cpp" | "mock";

/**
 * SPEC §4 schema plus two runtime pins (spec revision requested, see README "Runtime measurement"):
 * - `llm.runtime_sha256`: runtime closure digest of the program that serves the LLM (llama-server for
 *   `llama.cpp`; node for `mock`, which runs the mock-LLM script) — see `mock-tdx/runtime.ts`;
 * - `router.node_sha256`: runtime closure digest of the node that runs the router bundle.
 * The mock TDX host refuses to launch unless the runtimes it is about to execute match these digests.
 */
export interface AppCompose {
  llm: { kind: LlmKind; model_sha256: string; runtime: string; runtime_sha256: string };
  manifest_version: 1;
  name: "plr-router";
  policy: { disk: "none"; egress: []; logs: "none" };
  router: { bundle_sha256: string; entry: string; node_sha256: string };
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function sortKeys(v: Json): Json {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v !== null && typeof v === "object") {
    const out: { [k: string]: Json } = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k] as Json);
    return out;
  }
  return v;
}

/** Canonical form (SPEC §4): keys sorted recursively, `JSON.stringify(obj, null, 2) + "\n"`. */
export function canonicalJson(obj: Json): string {
  return JSON.stringify(sortKeys(obj), null, 2) + "\n";
}

/** Entry file names are plain basenames: no directories, no traversal. */
const ENTRY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.mjs$/;
const RUNTIME_RE = /^[\x20-\x7e]{1,64}$/;

function exactKeys(o: unknown, keys: readonly string[]): o is Record<string, unknown> {
  if (typeof o !== "object" || o === null || Array.isArray(o)) return false;
  const proto: unknown = Object.getPrototypeOf(o);
  if (proto !== Object.prototype && proto !== null) return false;
  const have = Object.keys(o).sort();
  const want = [...keys].sort();
  return have.length === want.length && have.every((k, i) => k === want[i]);
}

function bad(detail: string): never {
  throw new PlrError("E_BAD_INPUT", `app-compose: ${detail}`);
}

/** Builds a compose object from its variable parts (validated). */
export function makeCompose(p: {
  kind: LlmKind;
  modelSha256: string;
  runtime: string;
  runtimeSha256: string;
  bundleSha256: string;
  entry: string;
  nodeSha256: string;
}): AppCompose {
  const c: AppCompose = {
    llm: { kind: p.kind, model_sha256: p.modelSha256, runtime: p.runtime, runtime_sha256: p.runtimeSha256 },
    manifest_version: 1,
    name: "plr-router",
    policy: { disk: "none", egress: [], logs: "none" },
    router: { bundle_sha256: p.bundleSha256, entry: p.entry, node_sha256: p.nodeSha256 },
  };
  validateCompose(c);
  return c;
}

/** Canonical bytes of a compose object. */
export function composeBytes(c: AppCompose): Uint8Array {
  validateCompose(c);
  return new TextEncoder().encode(canonicalJson(c as unknown as Json));
}

function validateCompose(c: unknown): asserts c is AppCompose {
  if (!exactKeys(c, ["llm", "manifest_version", "name", "policy", "router"])) bad("top-level keys");
  if (c.manifest_version !== 1) bad("manifest_version");
  if (c.name !== "plr-router") bad("name");
  const llm = c.llm;
  if (!exactKeys(llm, ["kind", "model_sha256", "runtime", "runtime_sha256"])) bad("llm keys");
  if (llm.kind !== "llama.cpp" && llm.kind !== "mock") bad("llm.kind");
  if (!isHex(llm.model_sha256, 32)) bad("llm.model_sha256");
  if (typeof llm.runtime !== "string" || !RUNTIME_RE.test(llm.runtime)) bad("llm.runtime");
  if (!isHex(llm.runtime_sha256, 32)) bad("llm.runtime_sha256");
  const pol = c.policy;
  if (!exactKeys(pol, ["disk", "egress", "logs"])) bad("policy keys");
  if (pol.disk !== "none" || pol.logs !== "none") bad("policy");
  if (!Array.isArray(pol.egress) || pol.egress.length !== 0) bad("policy.egress");
  const r = c.router;
  if (!exactKeys(r, ["bundle_sha256", "entry", "node_sha256"])) bad("router keys");
  if (!isHex(r.bundle_sha256, 32)) bad("router.bundle_sha256");
  if (!isHex(r.node_sha256, 32)) bad("router.node_sha256");
  // A mock LLM is a node script: its runtime is the very node the host runs, so both pins must agree.
  if (llm.kind === "mock" && llm.runtime_sha256 !== r.node_sha256) bad("llm.runtime_sha256 (mock runs on node)");
  if (typeof r.entry !== "string" || !ENTRY_RE.test(r.entry)) bad("router.entry");
}

/**
 * Strictly parses compose bytes: size-bounded, fatal UTF-8, exact schema, and the bytes MUST already be in
 * canonical form (a non-canonical document is refused rather than silently normalised).
 * @throws PlrError E_BAD_INPUT
 */
export function parseCompose(bytes: Uint8Array): AppCompose {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_COMPOSE_BYTES) bad("size");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    bad("not UTF-8");
  }
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    bad("not JSON");
  }
  validateCompose(obj);
  if (canonicalJson(obj as unknown as Json) !== text) bad("not canonical");
  return obj;
}
