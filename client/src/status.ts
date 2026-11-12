/**
 * The status bundle (`getStatus()`): everything the demo site shows about the live exit, as one JSON object
 * (UI-BRIEF §4). Verification is the exact code `plr vpn verify` runs (`verifyVpnReport`), the replay is the
 * offline `--fixture` verification of the embedded capture, and everything about the chain is read from NEAR
 * (RPC views + the public NearBlocks API v3 for transaction lists, archival RPC `tx` for gas / call arguments).
 *
 * Fail closed and never throw: every network call has a timeout; when the registry or its RPC cannot be read,
 * `error` is set and no check is marked ok. Nothing is cached; callers cache.
 */
import { connect as tlsConnect } from "node:tls";
import { isIP } from "node:net";
import {
  fromHex,
  isHex,
  isValidP256Pub,
  keyHash,
  toHex,
  type QuoteVerifier,
} from "@plr/shared";
import { NearRegistry, checkRpcUrl, isNearAccountId } from "./near-registry.js";
import { TracingRegistry, checkLines } from "./verify-report.js";
import { VpnClient } from "./vpn/client.js";
import { composeFacts, fromLine, verifyVpnReport, type ComposeFacts, type VerifyCheck } from "./vpn-report.js";
import { COLLATERAL_FROM_EXIT, isPccsUrl } from "./pccs.js";
import { parseFixture, verifyFixtureData, type RawFixture } from "./fixture.js";

/** Replaced by esbuild (`scripts/build-status.mjs`) with the values of deploy/testnet/env.live and the live-exit fixture. */
declare const __STATUS_DEFAULTS__: StatusDefaults | undefined;
declare const __STATUS_REPLAY__: RawFixture | undefined;

export interface StatusDefaults {
  exitUrl?: string;
  registry?: string;
  trustedRoot?: string;
  rpcUrl?: string;
  /** deploy/testnet/env.live `OPERATOR_ID`. */
  operator?: string;
  /** deploy/testnet/env.live `PLATFORM`, if present. */
  platform?: string;
  /** deploy/testnet/env.live `REPRODUCIBLE_BUILD` (`true` / `false`), if present. */
  reproducibleBuild?: boolean;
}

const BAKED: StatusDefaults = typeof __STATUS_DEFAULTS__ === "undefined" ? {} : __STATUS_DEFAULTS__;
const BAKED_REPLAY: RawFixture | undefined = typeof __STATUS_REPLAY__ === "undefined" ? undefined : __STATUS_REPLAY__;

const DEFAULT_PLATFORM = "Intel TDX · Phala Cloud · dstack-0.6.1";
const DEFAULT_NEARBLOCKS = "https://api-testnet.nearblocks.io/v3";
const DEFAULT_ARCHIVAL = "https://archival-rpc.testnet.fastnear.com";
const REPO = "https://github.com/erhantrk/provenexit";
const EXPLORER_TX = "https://testnet.nearblocks.io/txns/{tx}";
/** Owner calls and registrations listed in `registry.events`. */
const EVENT_METHODS: ReadonlySet<string> = new Set([
  "approve_operator", "revoke_operator", "allow_compose", "revoke_compose", "allow_os", "revoke_os", "register_instance_tdx",
]);
const MAX_EVENT_PAGES = 12;
const MAX_EVENTS = 100;
const MAX_ANCHORS = 5;

export interface StatusOptions {
  exitUrl?: string;
  /** VPN registry account id. */
  registry?: string;
  /** Pinned root, 128 hex. */
  trustedRoot?: string;
  rpcUrl?: string;
  /** Operator account whose registration transaction is looked up (default: the instance's operator). */
  operator?: string;
  /**
   * The PCCS the live check fetches fresh Intel collateral from (INTEL mode). Default: `PLR_PCCS_URL`, else
   * `DEFAULT_PCCS_URL` (Intel's PCS); `"exit"` uses the exit's copy.
   */
  pccsUrl?: string;
  /** Env to read PLR_VPN_URL, PLR_VPN_REGISTRY, PLR_TRUSTED_ROOT, PLR_NEAR_RPC, PLR_PCCS_URL from (default `process.env`). */
  env?: Record<string, string | undefined>;
  /** NearBlocks API v3 base (default testnet). Plain http is allowed here (tests). */
  nearBlocksApi?: string;
  /** Archival RPC for `tx` (gas, call arguments). */
  archivalRpc?: string;
  /** Replaces the embedded live-exit fixture. */
  replay?: RawFixture;
  /** Replaces the DCAP verifier of the live check and of the replay (tests: a synthetic bundle has no Intel signature). */
  verifier?: QuoteVerifier;
  /** Egress probe target (default api.ipify.org:443 over TLS). */
  egress?: { host: string; port: number; tls: boolean; path?: string } | null;
  /** Per-step time limits in ms. */
  timeouts?: Partial<{ healthz: number; verify: number; egress: number; chain: number; events: number }>;
}

export interface StatusCheck extends VerifyCheck {}

export interface Status {
  checked_at: string;
  error: string | null;
  exit: {
    url: string | null;
    online: boolean;
    egress_ip: string | null;
    platform: string;
    compose: ComposeFacts | null;
  };
  verify: { verdict: "VERIFIED" | "REFUSED"; code: string | null; root: "INTEL" | "MOCK" | null; checks: StatusCheck[] };
  instance: {
    operator: string;
    organization: string | null;
    registered_at: string;
    expires_at: string;
    key_hash: string;
    registration_tx: string | null;
    registration_gas_tgas: number | null;
  } | null;
  registry: {
    account: string | null;
    owner: string | null;
    root: string | null;
    code_hash: string | null;
    full_access_keys: number | null;
    reproducible_build: boolean | null;
    events: RegistryEvent[];
  };
  receipts: { anchors: AnchorEntry[] };
  replay: {
    captured_at: string | null;
    verdict: "VERIFIED" | "REFUSED";
    code: string | null;
    checks: StatusCheck[];
    /** The compose facts of the recorded exit (a recording, not the live exit). */
    compose: ComposeFacts | null;
  } | null;
  links: { repo: string; explorer_tx: string };
}

export interface RegistryEvent {
  kind: string;
  /** Compose / OS hash the call allowed or revoked, else null. */
  hash: string | null;
  /** Operator account (approve_operator / revoke_operator / register_instance_tdx), else null. */
  account: string | null;
  org: string | null;
  tx: string;
  at: string;
}

export interface AnchorEntry {
  id: number;
  root: string;
  count: number;
  first_seq: number;
  tx: string | null;
  at: string;
}

/** Rejects after `ms` (the underlying work is abandoned, not cancelled: every call here also has its own timeout). */
function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`${what}: timeout`)), ms);
    timer.unref?.();
  });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

const msg = (e: unknown): string => (e instanceof Error ? e.message : "error");
const iso = (ms: number): string => new Date(ms).toISOString();

async function getJson(fetchFn: typeof fetch, url: string, ms: number, init?: RequestInit): Promise<unknown> {
  const res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(ms), headers: { accept: "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > 4 * 1024 * 1024) throw new Error("reply too large");
  return JSON.parse(text) as unknown;
}

async function rpcCall(fetchFn: typeof fetch, url: string, method: string, params: unknown, ms: number): Promise<Record<string, unknown>> {
  const j = (await getJson(fetchFn, url, ms, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "status", method, params }),
  })) as { result?: unknown; error?: unknown };
  if (typeof j.result !== "object" || j.result === null) throw new Error(`${method}: RPC error`);
  return j.result as Record<string, unknown>;
}

interface Txn {
  hash: string;
  method: string;
  signer: string;
  receiver: string;
  tsMs: number;
}

/** NearBlocks v3 `accounts/<id>/txns`, newest first, paged with `before_ts`; successful transactions only. */
async function listTxns(fetchFn: typeof fetch, api: string, account: string, ms: number, maxPages: number): Promise<Txn[]> {
  const out: Txn[] = [];
  const seen = new Set<string>();
  let before: string | undefined;
  const deadline = Date.now() + ms;
  for (let page = 0; page < maxPages; page++) {
    const left = deadline - Date.now();
    if (left <= 500) break;
    const url = `${api}/accounts/${encodeURIComponent(account)}/txns?per_page=25${before !== undefined ? `&before_ts=${before}` : ""}`;
    const j = (await getJson(fetchFn, url, left)) as { data?: unknown };
    if (!Array.isArray(j.data)) throw new Error("NearBlocks: malformed reply");
    let last: string | undefined;
    for (const t of j.data as Record<string, unknown>[]) {
      const ts = typeof t.block_timestamp === "string" ? t.block_timestamp : undefined;
      if (ts !== undefined) last = ts;
      const hash = t.transaction_hash;
      if (typeof hash !== "string" || ts === undefined || seen.has(hash)) continue;
      seen.add(hash);
      if ((t.outcomes as { status?: unknown } | undefined)?.status !== true) continue;
      const action = (t.actions as { action?: unknown; method?: unknown }[] | undefined)?.[0];
      out.push({
        hash,
        method: action?.action === "FUNCTION_CALL" && typeof action.method === "string" ? action.method : "",
        signer: String(t.signer_account_id ?? ""),
        receiver: String(t.receiver_account_id ?? ""),
        tsMs: Number(BigInt(ts) / 1_000_000n),
      });
    }
    if (j.data.length < 25 || last === undefined || last === before) break;
    before = last;
  }
  return out;
}

interface TxDetail {
  args: Record<string, unknown> | null;
  gasTgas: number | null;
}

/** Archival `tx`: first FunctionCall's JSON args, and total gas burnt (tx + all receipts) in Tgas. */
async function txDetail(fetchFn: typeof fetch, rpc: string, t: Txn, ms: number): Promise<TxDetail> {
  const r = await rpcCall(fetchFn, rpc, "tx", { tx_hash: t.hash, sender_account_id: t.signer, wait_until: "FINAL" }, ms);
  let args: Record<string, unknown> | null = null;
  const actions = (r.transaction as { actions?: unknown } | undefined)?.actions;
  const fc = Array.isArray(actions) ? (actions[0] as { FunctionCall?: { args?: unknown } } | undefined)?.FunctionCall : undefined;
  if (typeof fc?.args === "string") {
    try {
      const v = JSON.parse(Buffer.from(fc.args, "base64").toString("utf8")) as unknown;
      if (typeof v === "object" && v !== null && !Array.isArray(v)) args = v as Record<string, unknown>;
    } catch {
      /* args stay null */
    }
  }
  let burnt = (r.transaction_outcome as { outcome?: { gas_burnt?: unknown } } | undefined)?.outcome?.gas_burnt;
  let total = typeof burnt === "number" ? burnt : NaN;
  const receipts = r.receipts_outcome;
  if (Array.isArray(receipts)) {
    for (const ro of receipts as { outcome?: { gas_burnt?: unknown } }[]) {
      burnt = ro.outcome?.gas_burnt;
      total += typeof burnt === "number" ? burnt : NaN;
    }
  }
  return { args, gasTgas: Number.isFinite(total) ? Math.round(total / 1e10) / 100 : null };
}

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

function emptyStatus(now: number): Status {
  return {
    checked_at: iso(now),
    error: null,
    exit: { url: null, online: false, egress_ip: null, platform: BAKED.platform ?? DEFAULT_PLATFORM, compose: null },
    verify: { verdict: "REFUSED", code: null, root: null, checks: [] },
    instance: null,
    registry: { account: null, owner: null, root: null, code_hash: null, full_access_keys: null, reproducible_build: BAKED.reproducibleBuild ?? null, events: [] },
    receipts: { anchors: [] },
    replay: null,
    links: { repo: REPO, explorer_tx: EXPLORER_TX },
  };
}

/**
 * The replay verifies the recorded collateral and contacts no PCCS, so the client-fetched-collateral line is not
 * one of its checks: the replay list stays the 16 checks that ran.
 */
const REPLAY_LINES = { intel: true, collateral: "recorded" } as const;
const replayChecks = (e: unknown): StatusCheck[] => checkLines(e, undefined, REPLAY_LINES).filter((l) => l.note === undefined).map(fromLine);

async function replayOf(raw: RawFixture | undefined, verifier: QuoteVerifier | undefined): Promise<Status["replay"]> {
  if (raw === undefined) return null;
  try {
    const f = parseFixture(raw);
    const compose = (verified?: Awaited<ReturnType<typeof verifyFixtureData>>): ComposeFacts | null =>
      verified === undefined ? null : composeFacts(verified, f.bundle.app_compose);
    try {
      const verified = await verifyFixtureData(f, verifier);
      return {
        captured_at: iso(f.meta.captured_at_ms),
        verdict: "VERIFIED",
        code: null,
        checks: replayChecks(undefined),
        compose: compose(verified),
      };
    } catch (e) {
      const code = (e as { code?: string }).code ?? "error";
      return {
        captured_at: iso(f.meta.captured_at_ms),
        verdict: "REFUSED",
        code,
        checks: replayChecks(e),
        compose: null,
      };
    }
  } catch {
    return null;
  }
}

/** Decodes an HTTP/1.1 chunked body (ASCII; the probe reads a tiny IP text). Malformed input yields what was decoded so far. */
function dechunk(raw: string): string {
  let out = "";
  let pos = 0;
  for (;;) {
    const eol = raw.indexOf("\r\n", pos);
    if (eol < 0) break;
    const size = parseInt(raw.slice(pos, eol).split(";")[0]!, 16);
    if (!Number.isInteger(size) || size <= 0) break;
    out += raw.slice(eol + 2, eol + 2 + size);
    pos = eol + 2 + size + 2;
  }
  return out;
}

/** One TLS (or plain) GET through the attested tunnel; resolves the trimmed body if it is an IP literal. Never direct. */
async function egressIp(client: VpnClient, t: { host: string; port: number; tls: boolean; path?: string }, ms: number): Promise<string | null> {
  const tunnel = await client.connect(t.host, t.port);
  let sock: import("node:stream").Duplex = tunnel;
  try {
    if (t.tls) {
      sock = tlsConnect({ socket: tunnel, servername: t.host, minVersion: "TLSv1.2" });
    }
    const body = await new Promise<string>((ok, no) => {
      const chunks: Buffer[] = [];
      let n = 0;
      const timer = setTimeout(() => no(new Error("egress: timeout")), ms);
      timer.unref?.();
      sock.on("data", (c: Buffer) => {
        n += c.length;
        if (n > 16 * 1024) return no(new Error("egress: too large"));
        chunks.push(c);
      });
      sock.on("end", () => ok(Buffer.concat(chunks).toString("latin1")));
      sock.on("close", () => ok(Buffer.concat(chunks).toString("latin1")));
      sock.on("error", (e) => no(e));
      sock.write(`GET ${t.path ?? "/"} HTTP/1.1\r\nHost: ${t.host}\r\nUser-Agent: provenexit-status\r\nAccept: text/plain\r\nConnection: close\r\n\r\n`);
    });
    const i = body.indexOf("\r\n\r\n");
    if (i < 0 || !/^HTTP\/1\.[01] 200 /.test(body)) return null;
    let payload = body.slice(i + 4);
    if (/^transfer-encoding:\s*chunked/im.test(body.slice(0, i))) payload = dechunk(payload);
    const text = payload.trim();
    return isIP(text) !== 0 ? text : null;
  } finally {
    sock.destroy();
    tunnel.destroy();
  }
}

interface Cfg {
  exitUrl: string;
  registry: string;
  trustedRoot: Uint8Array;
  rpcUrl: string;
  /** undefined = the default PCCS (Intel PCS); "exit" = the exit's copy. */
  pccsUrl?: string;
}

function resolveConfig(o: StatusOptions): Cfg {
  const env = o.env ?? process.env;
  const pick = (opt: string | undefined, name: string, baked: string | undefined): string | undefined => opt || env[name] || baked || undefined;
  const exitUrl = pick(o.exitUrl, "PLR_VPN_URL", BAKED.exitUrl);
  const registry = pick(o.registry, "PLR_VPN_REGISTRY", BAKED.registry);
  const rootHex = pick(o.trustedRoot, "PLR_TRUSTED_ROOT", BAKED.trustedRoot);
  const rpcUrl = pick(o.rpcUrl, "PLR_NEAR_RPC", BAKED.rpcUrl);
  if (exitUrl === undefined) throw new Error("exit URL not configured (PLR_VPN_URL)");
  if (registry === undefined || !isNearAccountId(registry)) throw new Error("registry not configured (PLR_VPN_REGISTRY)");
  if (rootHex === undefined || !isHex(rootHex, 64)) throw new Error("PLR_TRUSTED_ROOT must be 128 lowercase hex chars");
  const trustedRoot = fromHex(rootHex, 64);
  if (!isValidP256Pub(trustedRoot)) throw new Error("PLR_TRUSTED_ROOT is not a valid P-256 public key");
  if (rpcUrl === undefined) throw new Error("NEAR RPC not configured (PLR_NEAR_RPC)");
  checkRpcUrl(rpcUrl);
  // Fresh Intel collateral is fetched by this process (default: Intel's PCS). Only the env value is validated here.
  const envPccs = env.PLR_PCCS_URL || undefined;
  if (o.pccsUrl === undefined && envPccs !== undefined && envPccs !== COLLATERAL_FROM_EXIT && !isPccsUrl(envPccs)) {
    throw new Error(`PLR_PCCS_URL must be an https URL or "${COLLATERAL_FROM_EXIT}"`);
  }
  const pccsUrl = o.pccsUrl ?? envPccs;
  return { exitUrl, registry, trustedRoot, rpcUrl, ...(pccsUrl !== undefined ? { pccsUrl } : {}) };
}

/**
 * Builds the status JSON. Never throws; every network call is bounded. Defaults are the live testnet deployment
 * (deploy/testnet/env.live, baked in at build time); `opts` / `PLR_VPN_URL`, `PLR_VPN_REGISTRY`, `PLR_TRUSTED_ROOT`,
 * `PLR_NEAR_RPC` override them.
 */
export async function getStatus(opts: StatusOptions = {}): Promise<Status> {
  const status = emptyStatus(Date.now());
  const fetchFn = globalThis.fetch;
  const T = { healthz: 5_000, verify: 25_000, egress: 15_000, chain: 8_000, events: 20_000, ...(opts.timeouts ?? {}) };
  const replayP = replayOf(opts.replay ?? BAKED_REPLAY, opts.verifier);
  let cfg: Cfg;
  try {
    cfg = resolveConfig(opts);
  } catch (e) {
    status.error = `configuration: ${msg(e)}`;
    status.replay = await replayP;
    return status;
  }
  status.exit.url = cfg.exitUrl;
  status.registry.account = cfg.registry;
  const near = new NearRegistry({ rpcUrl: cfg.rpcUrl, contractId: cfg.registry, timeoutMs: T.chain });
  const tracing = new TracingRegistry(near);
  const nearBlocks = (opts.nearBlocksApi ?? DEFAULT_NEARBLOCKS).replace(/\/+$/, "");
  const archival = opts.archivalRpc ?? DEFAULT_ARCHIVAL;

  // 1. independent reads, in parallel: exit health, live verification, registry facts, transaction list.
  const healthP = withTimeout(
    fetchFn(new URL("/healthz", cfg.exitUrl).href, { signal: AbortSignal.timeout(T.healthz) }).then((r) => r.ok),
    T.healthz + 500,
    "healthz",
  ).catch(() => false);
  const client = (() => {
    try {
      return new VpnClient({
        exitUrl: cfg.exitUrl,
        registry: tracing,
        trustedRoot: cfg.trustedRoot,
        ...(opts.verifier !== undefined ? { verifier: opts.verifier } : {}),
        timeouts: { attestMs: Math.min(15_000, T.verify), connectMs: T.egress },
        ...(cfg.pccsUrl !== undefined ? { pccsUrl: cfg.pccsUrl } : {}),
      });
    } catch {
      return undefined;
    }
  })();
  const verifyP = client === undefined
    ? Promise.resolve(undefined)
    : withTimeout(verifyVpnReport(client, tracing), T.verify, "verify").catch(() => undefined);
  const regFacts = (async () => {
    const [owner, root, acct, keys] = await Promise.all([
      near.view("get_owner", {}),
      near.getRoot(),
      withTimeout(rpcCall(fetchFn, cfg.rpcUrl, "query", { request_type: "view_account", finality: "final", account_id: cfg.registry }, T.chain), T.chain + 500, "view_account"),
      withTimeout(rpcCall(fetchFn, cfg.rpcUrl, "query", { request_type: "view_access_key_list", finality: "final", account_id: cfg.registry }, T.chain), T.chain + 500, "view_access_key_list"),
    ]);
    const list = Array.isArray(keys.keys) ? (keys.keys as { access_key?: { permission?: unknown } }[]) : null;
    return {
      owner: str(owner),
      root: root.kind,
      code_hash: str(acct.code_hash),
      full_access_keys: list === null ? null : list.filter((k) => k.access_key?.permission === "FullAccess").length,
    };
  })();
  const txnsP = withTimeout(listTxns(fetchFn, nearBlocks, cfg.registry, T.events, MAX_EVENT_PAGES), T.events + 500, "NearBlocks").catch(() => null);

  const [online, verify, facts, txns] = await Promise.all([healthP, verifyP, regFacts.catch((e: unknown) => e as Error), txnsP]);
  status.exit.online = online;
  status.replay = await replayP;

  // 2. registry facts
  let registryError: string | null = null;
  if (facts instanceof Error) registryError = `registry unreadable: ${msg(facts)}`;
  else {
    status.registry.owner = facts.owner;
    status.registry.root = facts.root;
    status.registry.code_hash = facts.code_hash;
    status.registry.full_access_keys = facts.full_access_keys;
  }

  // 3. verification
  if (verify === undefined) {
    status.verify = { verdict: "REFUSED", code: "E_BAD_RESPONSE", root: null, checks: [] };
    if (registryError === null) registryError = "verification did not complete";
  } else {
    status.verify = { verdict: verify.verdict, code: verify.code, root: verify.root, checks: verify.checks };
    if (verify.registryUnavailable && registryError === null) registryError = "registry unreadable: E_REGISTRY_UNAVAILABLE";
  }
  if (registryError !== null) {
    status.error = registryError;
    status.verify = { ...status.verify, verdict: "REFUSED", code: status.verify.code ?? "E_REGISTRY_UNAVAILABLE", checks: status.verify.checks.map((c) => ({ ...c, ok: false })) };
    return status;
  }

  // 4. compose + egress, only from a verified exit
  const session = verify?.session;
  if (session !== undefined && verify?.verdict === "VERIFIED") {
    status.exit.compose = composeFacts(session.verified, session.appCompose);
    const target = opts.egress === undefined ? { host: "api.ipify.org", port: 443, tls: true } : opts.egress;
    if (target !== null && client !== undefined) {
      status.exit.egress_ip = await withTimeout(egressIp(client, target, T.egress), T.egress + 2_000, "egress").catch(() => null);
    }
  }

  // 5. instance, registration tx + gas (key hash of the live exit, else of the recorded one)
  let keyHashHex: string | null = session !== undefined ? toHex(session.verified.keyHash) : null;
  if (keyHashHex === null) {
    try {
      const f = opts.replay ?? BAKED_REPLAY;
      if (f !== undefined) {
        const b = f.bundle as { x25519?: string; ed25519?: string };
        if (isHex(b.x25519, 32) && isHex(b.ed25519, 32)) {
          keyHashHex = toHex(keyHash(fromHex(b.x25519, 32), fromHex(b.ed25519, 32)));
        }
      }
    } catch {
      keyHashHex = null;
    }
  }
  if (keyHashHex !== null) {
    try {
      const inst = await near.getInstance(keyHashHex);
      if (inst !== null) {
        status.instance = {
          operator: inst.operator,
          organization: inst.org_id ?? null,
          registered_at: iso(inst.registered_at_ms),
          expires_at: iso(inst.expires_at_ms),
          key_hash: keyHashHex,
          registration_tx: null,
          registration_gas_tgas: null,
        };
        const regs = (txns ?? []).filter((t) => t.method === "register_instance_tdx" && t.signer === inst.operator);
        regs.sort((a, b) => Math.abs(a.tsMs - inst.registered_at_ms) - Math.abs(b.tsMs - inst.registered_at_ms));
        const reg = regs[0];
        if (reg !== undefined) {
          status.instance.registration_tx = reg.hash;
          try {
            status.instance.registration_gas_tgas = (await withTimeout(txDetail(fetchFn, archival, reg, T.chain), T.chain + 500, "tx")).gasTgas;
          } catch {
            /* gas stays null */
          }
        }
      }
    } catch {
      /* instance stays null */
    }
  }

  // 6. registry events (newest first) with call arguments from the archival RPC
  if (txns !== null) {
    const wanted = txns.filter((t) => EVENT_METHODS.has(t.method)).slice(0, MAX_EVENTS);
    const details = await Promise.all(
      wanted.map((t) => (t.method === "register_instance_tdx" ? Promise.resolve(null) : withTimeout(txDetail(fetchFn, archival, t, T.chain), T.chain + 500, "tx").catch(() => null))),
    );
    status.registry.events = wanted.map((t, i) => {
      const a = details[i]?.args ?? null;
      return {
        kind: t.method,
        hash: str(a?.hash),
        account: t.method === "register_instance_tdx" ? t.signer : str(a?.account_id),
        org: str(a?.org_id),
        tx: t.hash,
        at: iso(t.tsMs),
      };
    });
  }

  // 7. receipts: the newest anchors of the registry contract
  try {
    const count = await near.anchorCount();
    const ids: number[] = [];
    for (let id = count - 1; id >= 0 && ids.length < MAX_ANCHORS; id--) ids.push(id);
    // The anchor's `at_ms` is the block time of the call's execution, a block or two after the transaction's block.
    const anchorTxns = (txns ?? []).filter((t) => t.method === "anchor_receipts");
    const txFor = (atMs: number): string | null => {
      let best: Txn | undefined;
      for (const t of anchorTxns) if (Math.abs(t.tsMs - atMs) <= 5_000 && (best === undefined || Math.abs(t.tsMs - atMs) < Math.abs(best.tsMs - atMs))) best = t;
      return best?.hash ?? null;
    };
    const got = await Promise.all(ids.map((id) => near.getAnchor(id).catch(() => null)));
    status.receipts.anchors = got.flatMap((a) =>
      a === null ? [] : [{ id: a.id, root: a.root, count: a.count, first_seq: a.first_seq, tx: txFor(a.at_ms), at: iso(a.at_ms) }],
    );
  } catch {
    status.receipts.anchors = [];
  }
  return status;
}

/** The registry part of {@link getStatus} (for the MCP `registry_status` tool). */
export async function getRegistryStatus(opts: StatusOptions = {}): Promise<{ error: string | null; registry: Status["registry"]; instance: Status["instance"] }> {
  const s = await getStatus({ ...opts, egress: null });
  return { error: s.error, registry: s.registry, instance: s.instance };
}

/** A configured client for the live exit: what `plr vpn` builds from the same env variables and defaults. */
export interface OpenedExit {
  exitUrl: string;
  registryId: string;
  rpcUrl: string;
  client: VpnClient;
  registry: TracingRegistry;
}

/**
 * Builds the {@link VpnClient} for the configured exit (defaults baked at build time, overridable by `opts` and
 * `PLR_VPN_URL` / `PLR_VPN_REGISTRY` / `PLR_TRUSTED_ROOT` / `PLR_NEAR_RPC`).
 * @throws Error with a readable message when the configuration is invalid
 */
export function openExit(opts: StatusOptions = {}): OpenedExit {
  const cfg = resolveConfig(opts);
  const T = { verify: 25_000, egress: 15_000, chain: 8_000, ...(opts.timeouts ?? {}) };
  const registry = new TracingRegistry(new NearRegistry({ rpcUrl: cfg.rpcUrl, contractId: cfg.registry, timeoutMs: T.chain }));
  const client = new VpnClient({
    exitUrl: cfg.exitUrl,
    registry,
    trustedRoot: cfg.trustedRoot,
    ...(opts.verifier !== undefined ? { verifier: opts.verifier } : {}),
    timeouts: { attestMs: Math.min(15_000, T.verify), connectMs: T.egress },
    ...(cfg.pccsUrl !== undefined ? { pccsUrl: cfg.pccsUrl } : {}),
  });
  return { exitUrl: cfg.exitUrl, registryId: cfg.registry, rpcUrl: cfg.rpcUrl, client, registry };
}
