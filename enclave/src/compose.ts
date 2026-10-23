/**
 * `app-compose.json` (SPEC §4, SPEC-VPN §2): canonical serialisation (used by the build) and strict parsing
 * (used by the mock TDX host, the router and the VPN exit). Two services share the canonical form and are told
 * apart by `name`: `plr-router` (LLM router) and `plr-vpn` (VPN exit). Verifiers hash the bytes received; this
 * module never re-serialises something it was given.
 */
import { readFileSync } from "node:fs";
import { PlrError, egressAllowed, isHex, isIpLiteral, parseIpv4 } from "@plr/shared";

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

/** Canonical bytes of a compose object (either service; validated against its exact schema). */
export function composeBytes(c: AppCompose | VpnCompose): Uint8Array {
  if (c.name === "plr-vpn") validateVpnCompose(c);
  else validateCompose(c);
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

/** Size-bounded, fatal UTF-8 JSON decode of compose bytes. */
function decodeCompose(bytes: Uint8Array): { text: string; obj: unknown } {
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
  return { text, obj };
}

function requireCanonical(obj: unknown, text: string): void {
  if (canonicalJson(obj as Json) !== text) bad("not canonical");
}

/**
 * Strictly parses router compose bytes: size-bounded, fatal UTF-8, exact schema, and the bytes MUST already be
 * in canonical form (a non-canonical document is refused rather than silently normalised).
 * @throws PlrError E_BAD_INPUT
 */
export function parseCompose(bytes: Uint8Array): AppCompose {
  const { text, obj } = decodeCompose(bytes);
  validateCompose(obj);
  requireCanonical(obj, text);
  return obj;
}

// ------------------------------------------------------------------------------------------- VPN (SPEC-VPN §2)

/** The only entry file name of a VPN exit bundle (SPEC-VPN §2). */
export const VPN_ENTRY = "vpn.bundle.mjs";

/** SPEC-VPN §2 schema (exact keys, no extras). `deny_private` is always true. */
export interface VpnCompose {
  manifest_version: 1;
  name: "plr-vpn";
  policy: {
    disk: "none";
    dns: { doh: string[] };
    egress: { allow_loopback: boolean; deny_private: true };
    logs: "none";
  };
  vpn: { bundle_sha256: string; entry: typeof VPN_ENTRY; node_sha256: string };
}

export type ComposeService = "router" | "vpn";

/** SPEC-VPN §2: production RFC 8484 resolvers (IP literals: no bootstrap DNS), tried in this order. */
export const VPN_DOH_PRODUCTION: readonly string[] = Object.freeze(["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"]);
/** SPEC-VPN §2: the local test resolver of test-policy builds (allowed only with `allow_loopback`). */
export const VPN_DOH_TEST: readonly string[] = Object.freeze(["http://127.0.0.1:18253/dns-query"]);
/** At most this many resolvers (SPEC-VPN §2). */
export const MAX_DOH_RESOLVERS = 4;
/** Upper bound on one resolver URL (far above any real one; bounds what the exit ever parses). */
export const MAX_DOH_URL_LEN = 256;

/** The address of a URL host (`1.2.3.4` or `[v6]`, as `URL.hostname` spells it), or null if it is not an IP literal. */
export function urlHostIp(hostname: string): string | null {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    const v6 = hostname.slice(1, -1);
    return isIpLiteral(v6) && parseIpv4(v6) === null ? v6 : null;
  }
  return parseIpv4(hostname) !== null ? hostname : null;
}

/**
 * One `policy.dns.doh` entry (SPEC-VPN §2): an absolute URL in its own normalised form (so the measured string is
 * exactly what is fetched), host an IP literal (no bootstrap DNS), no credentials / query / fragment, and either
 * `https:` to an address the egress policy allows, or — only on `allow_loopback` builds — `http://127.0.0.1:<port>/…`.
 * @returns the reason it is invalid, or null
 */
export function dohUrlProblem(url: unknown, allowLoopback: boolean): string | null {
  if (typeof url !== "string" || url.length === 0 || url.length > MAX_DOH_URL_LEN) return "not a bounded string";
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return "not a URL";
  }
  if (u.href !== url) return "not in normalised form";
  if (u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "") return "credentials, query or fragment";
  const ip = urlHostIp(u.hostname);
  if (ip === null) return "host is not an IP literal";
  if (u.protocol === "https:") {
    // The resolver itself is subject to the measured egress policy (never a private / metadata address).
    return egressAllowed(ip, { allow_loopback: allowLoopback, deny_private: true }) ? null : "address not allowed";
  }
  if (u.protocol === "http:") {
    if (!allowLoopback) return "plain http outside a loopback test build";
    if (ip !== "127.0.0.1" || u.port === "") return "plain http only to 127.0.0.1:<port>";
    return null;
  }
  return "scheme";
}

function validateDoh(dns: unknown, allowLoopback: boolean): void {
  if (!exactKeys(dns, ["doh"])) bad("policy.dns keys");
  const list = dns.doh;
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_DOH_RESOLVERS) bad("policy.dns.doh size");
  for (const u of list) if (dohUrlProblem(u, allowLoopback) !== null) bad("policy.dns.doh entry");
  if (new Set(list).size !== list.length) bad("policy.dns.doh duplicates");
}

function validateVpnCompose(c: unknown): asserts c is VpnCompose {
  if (!exactKeys(c, ["manifest_version", "name", "policy", "vpn"])) bad("top-level keys");
  if (c.manifest_version !== 1) bad("manifest_version");
  if (c.name !== "plr-vpn") bad("name");
  const pol = c.policy;
  if (!exactKeys(pol, ["disk", "dns", "egress", "logs"])) bad("policy keys");
  if (pol.disk !== "none" || pol.logs !== "none") bad("policy");
  const eg = pol.egress;
  if (!exactKeys(eg, ["allow_loopback", "deny_private"])) bad("policy.egress keys");
  if (typeof eg.allow_loopback !== "boolean") bad("policy.egress.allow_loopback");
  if (eg.deny_private !== true) bad("policy.egress.deny_private");
  validateDoh(pol.dns, eg.allow_loopback);
  const v = c.vpn;
  if (!exactKeys(v, ["bundle_sha256", "entry", "node_sha256"])) bad("vpn keys");
  if (!isHex(v.bundle_sha256, 32)) bad("vpn.bundle_sha256");
  if (!isHex(v.node_sha256, 32)) bad("vpn.node_sha256");
  if (v.entry !== VPN_ENTRY) bad("vpn.entry");
}

/**
 * Builds a VPN compose object from its variable parts (validated). `doh` defaults to {@link VPN_DOH_TEST} on
 * `allowLoopback` builds and to {@link VPN_DOH_PRODUCTION} otherwise (SPEC-VPN §2).
 */
export function makeVpnCompose(p: { bundleSha256: string; nodeSha256: string; allowLoopback: boolean; doh?: readonly string[] }): VpnCompose {
  const doh = [...(p.doh ?? (p.allowLoopback ? VPN_DOH_TEST : VPN_DOH_PRODUCTION))];
  const c: VpnCompose = {
    manifest_version: 1,
    name: "plr-vpn",
    policy: { disk: "none", dns: { doh }, egress: { allow_loopback: p.allowLoopback, deny_private: true }, logs: "none" },
    vpn: { bundle_sha256: p.bundleSha256, entry: VPN_ENTRY, node_sha256: p.nodeSha256 },
  };
  validateVpnCompose(c);
  return c;
}

/**
 * Strictly parses VPN compose bytes (same rules as {@link parseCompose}: bounded, fatal UTF-8, exact schema,
 * canonical). @throws PlrError E_BAD_INPUT
 */
export function parseVpnCompose(bytes: Uint8Array): VpnCompose {
  const { text, obj } = decodeCompose(bytes);
  validateVpnCompose(obj);
  requireCanonical(obj, text);
  return obj;
}

/**
 * Which service a compose document describes, from its `name` (the discriminator). Only a dispatch hint: the
 * document must still be parsed strictly with {@link parseCompose} / {@link parseVpnCompose}.
 * @throws PlrError E_BAD_INPUT
 */
export function composeService(bytes: Uint8Array): ComposeService {
  const { obj } = decodeCompose(bytes);
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) bad("not an object");
  const name = (obj as Record<string, unknown>).name;
  if (name === "plr-router") return "router";
  if (name === "plr-vpn") return "vpn";
  bad("name");
}

/** Reads a compose file once (bounded). */
export function readCompose(path: string): Uint8Array {
  const buf = readFileSync(path);
  if (buf.length > MAX_COMPOSE_BYTES) throw new Error("E_COMPOSE_SIZE");
  return new Uint8Array(buf);
}
