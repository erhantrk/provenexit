// State logic and formatters. Pure: no DOM, no fetch, no clock of its own.

export const STALE_MS = 5 * 60 * 1000;
export const NOT_CHECKED = "not checked";

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

export function checksOf(part) {
  return isObj(part) && Array.isArray(part.checks) ? part.checks.filter(isObj) : [];
}

/** pass | fail | skip. A row that was never reached is neither a pass nor a failure. */
export function rowStatus(check) {
  if (check?.ok === true) return "pass";
  if (check?.detail === NOT_CHECKED) return "skip";
  return "fail";
}

/**
 * input: undefined = no response yet; null or a non-object = the request failed; otherwise status.json.
 * Order matters: error, then stale, then offline, and only then the verdict.
 */
export function deriveState(input, now) {
  if (input === undefined) return "loading";
  if (!isObj(input)) return "error";
  if (input.error !== null && input.error !== undefined) return "error";
  const at = Date.parse(input.checked_at);
  if (!Number.isFinite(at)) return "error";
  if (now - at > STALE_MS) return "stale";
  if (!isObj(input.exit) || input.exit.online !== true) return "offline";
  const verdict = input.verify?.verdict;
  const checks = checksOf(input.verify);
  if (verdict === "VERIFIED" && checks.length > 0 && checks.every((c) => c.ok === true)) return "verified";
  if (verdict === "REFUSED") return "refused";
  return "error";
}

/**
 * What colour the response permits. `face` is the plate (and the nav chip, the logo tick, the title).
 * `marks` says whether any green or red mark may be drawn at all: only for a current answer from a
 * running exit. Offline, error, stale and loading are ink and grey throughout.
 */
export function colourOf(input, now) {
  const state = deriveState(input, now);
  return {
    state,
    face: state === "verified" ? "go" : state === "refused" ? "stop" : "unlit",
    marks: state === "verified" || state === "refused",
  };
}

/** The first row that failed (not one that was never reached). */
export function failingCheck(input) {
  const checks = checksOf(input?.verify);
  const index = checks.findIndex((c) => rowStatus(c) === "fail");
  return index < 0 ? null : { index, number: index + 1, check: checks[index] };
}

export const STAGES = [
  {
    id: "hardware",
    title: "Real Intel hardware",
    line: "Signed by Intel, debug off, patched",
    names: [
      "response well-formed, fresh 32-byte nonce",
      "quote structure (TDX v4)",
      "TEE type is TDX",
      "pinned root == registry root == verifier root",
      "fresh Intel collateral fetched by the client from the PCCS (not the exit's copy)",
      "quote signature chain to root",
      "Intel TCB status accepted",
      "TD debug attribute clear",
    ],
  },
  {
    id: "keys",
    title: "Keys and freshness",
    line: "The exit's keys and your nonce are inside the quote",
    names: [
      "report_data binds the exit's keys",
      'report_data binds client nonce as a session quote (SHA256("PLR-v1/session-nonce" ‖ nonce))',
    ],
  },
  {
    id: "image",
    title: "The approved image",
    line: "The exact image, pinned by digest, logging off",
    names: [
      "event log digests and boot sequence",
      "event log replays to RTMR3",
      "app-compose matches measured compose-hash",
      "dstack compose: images pinned by digest, exit logging disabled",
    ],
  },
  {
    id: "near",
    title: "Allowed on NEAR",
    line: "The registry runs its pinned code and lists this build, OS and exit",
    names: [
      "registry contract code hash matches the pinned build (view_account.code_hash)",
      "compose hash allowed by registry",
      "OS measurement allowed by registry",
      "instance registered with matching keys",
    ],
  },
  {
    id: "connection",
    title: "On every connection",
    line: "Read again before each tunnel; the exit resolves names",
    names: [
      "registry re-check before each connection (compose, OS, instance)",
      "destinations resolved by the exit (remote DNS); the client never resolves them",
    ],
  },
];
const OTHER = { id: "other", title: "Other", line: "Checks this page has no stage for" };

/** pass | fail | skip | part (some passed, the rest not reached). */
export function stageStatus(rows) {
  const s = rows.map((r) => r.status);
  if (s.includes("fail")) return "fail";
  if (s.length > 0 && s.every((x) => x === "pass")) return "pass";
  if (s.every((x) => x === "skip")) return "skip";
  return "part";
}

/** Groups checks into the stages by exact name, keeping the JSON's order and numbering. Empty stages are left out. */
export function groupChecks(checks) {
  const list = Array.isArray(checks) ? checks.filter(isObj) : [];
  const stageOf = new Map();
  STAGES.forEach((s) => s.names.forEach((n) => stageOf.set(n, s.id)));
  const buckets = new Map([...STAGES, OTHER].map((s) => [s.id, []]));
  list.forEach((c, i) => {
    buckets.get(stageOf.get(c.name) ?? "other").push({
      number: i + 1,
      name: String(c.name ?? ""),
      detail: typeof c.detail === "string" ? c.detail : "",
      status: rowStatus(c),
    });
  });
  return [...STAGES, OTHER]
    .map((s) => ({ id: s.id, title: s.title, line: s.line, rows: buckets.get(s.id) }))
    .filter((s) => s.rows.length > 0)
    .map((s) => ({ ...s, status: stageStatus(s.rows), passed: s.rows.filter((r) => r.status === "pass").length }));
}

/** The newest allow_compose / revoke_compose event for this hash, or null when the history does not say. */
export function allowlistStatus(events, hash) {
  if (!Array.isArray(events) || typeof hash !== "string" || hash === "") return null;
  const hits = events.filter(
    (e) => isObj(e) && e.hash === hash && (e.kind === "allow_compose" || e.kind === "revoke_compose"),
  );
  if (hits.length === 0) return null;
  const t = (e) => (Number.isFinite(Date.parse(e.at)) ? Date.parse(e.at) : -Infinity);
  const newest = hits.reduce((a, b) => (t(b) > t(a) ? b : a));
  return { allowed: newest.kind === "allow_compose", event: newest };
}

/** What the history supports saying about the build's hash; nothing when the history does not show it. */
export function approvalSentence(status) {
  if (!status) return "";
  return status.allowed ? "The owner approved this exact hash on NEAR." : "The owner revoked this exact hash on NEAR.";
}

export const EVENT_WORDS = {
  approve_operator: "Operator approved",
  allow_os: "OS image allowed",
  allow_compose: "Build allowed",
  revoke_compose: "Build revoked",
  revoke_os: "OS image revoked",
  register_instance_tdx: "Exit registered after the on-chain check",
};
export const eventWords = (kind) => (Object.hasOwn(EVENT_WORDS, kind) ? EVENT_WORDS[kind] : String(kind ?? ""));
export const isRevoke = (kind) => typeof kind === "string" && kind.startsWith("revoke_");

/** { expired, at } for the registration, or null when there is no usable expiry. */
export function expiryOf(instance, now) {
  const at = Date.parse(instance?.expires_at);
  if (!Number.isFinite(at)) return null;
  return { at, expired: now >= at };
}

// ---- formatters -------------------------------------------------------------------------------

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n) => String(n).padStart(2, "0");
const dateOf = (v) => {
  const d = new Date(v);
  return Number.isFinite(d.getTime()) ? d : null;
};

/** 12 Nov 2026 */
export function fmtDate(v) {
  const d = dateOf(v);
  return d ? `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}` : "";
}
/** 12:55:50 UTC */
export function fmtTime(v) {
  const d = dateOf(v);
  return d ? `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} UTC` : "";
}
/** 12:55 UTC */
export function fmtHM(v) {
  const d = dateOf(v);
  return d ? `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())} UTC` : "";
}
/** 12 Nov 2026, 12:55:50 UTC */
export function fmtDateTime(v) {
  return dateOf(v) ? `${fmtDate(v)}, ${fmtTime(v)}` : "";
}
/** 12 Nov 2026, 12:55 UTC */
export function fmtDateHM(v) {
  return dateOf(v) ? `${fmtDate(v)}, ${fmtHM(v)}` : "";
}

/** A span of time in words: "14 seconds", "1 minute", "3 hours", "2 days". */
export function fmtSpan(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const unit = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
  if (s < 60) return unit(s, "second");
  if (s < 3600) return unit(Math.floor(s / 60), "minute");
  if (s < 86400) return unit(Math.floor(s / 3600), "hour");
  return unit(Math.floor(s / 86400), "day");
}

/** First 8 and last 4 characters; short values are returned whole. */
export function short(value) {
  const s = String(value ?? "");
  return s.length <= 16 ? s : `${s.slice(0, 8)}…${s.slice(-4)}`;
}

export function platformItems(platform) {
  return typeof platform === "string" ? platform.split(" · ").map((s) => s.trim()).filter(Boolean) : [];
}

/** Only https links leave the page. Anything else is treated as absent. */
export function safeUrl(value) {
  if (typeof value !== "string") return null;
  try {
    const u = new URL(value);
    return u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

export function txUrl(links, tx) {
  const template = links?.explorer_tx;
  if (typeof template !== "string" || typeof tx !== "string" || tx === "" || !template.includes("{tx}")) return null;
  return safeUrl(template.replace("{tx}", encodeURIComponent(tx)));
}

/** https://testnet.nearblocks.io/address/<account>, built from the same explorer the tx links use. */
export function accountUrl(links, account) {
  const template = safeUrl(links?.explorer_tx?.replace?.("{tx}", "x"));
  if (template === null || typeof account !== "string" || account === "") return null;
  return `${new URL(template).origin}/address/${encodeURIComponent(account)}`;
}
