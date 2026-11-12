import {
  deriveState, checksOf, failingCheck, groupChecks, allowlistStatus, approvalSentence, eventWords, isRevoke, expiryOf,
  fmtDate, fmtTime, fmtHM, fmtDateTime, fmtDateHM, fmtSpan, short, platformItems, safeUrl, txUrl, accountUrl,
} from "./state.js";
import { CONFIG } from "./config.js";
import { startMotion, scanMotion } from "./motion.js";
import { startMore, enhanceMore } from "./more.js";

const POLL_MS = 15_000;
const FETCH_TIMEOUT_MS = 70_000;
const HISTORY_SHOWN = 3;
const CMD_LIVE = "npm ci && npx tsc -b && scripts/try-live.sh";
const CMD_REPLAY = "npm ci && npx tsc -b && node client/dist/cli.js vpn verify --fixture fixtures/live-exit";
const KEY_CHECKS = ["report_data binds the exit's keys", "instance registered with matching keys"];

const $ = (id) => document.getElementById(id);
const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ---- local sample switch: fixtures are served and read on localhost only -----------------------
const SAMPLES = { online: "online", offline: "offline", refused: "refused", error: "error", "offline-retired": "offline-retired", stale: "online" };
const isLocal = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
const sampleParam = new URLSearchParams(location.search).get("sample");
const sample = isLocal && sampleParam !== null && Object.hasOwn(SAMPLES, sampleParam) ? sampleParam : null;

// ---- page memory (nothing is stored anywhere else) --------------------------------------------
let json;            // undefined = no response yet, null = the request failed, object = status.json
let failedAt = null; // when the last request failed
let skew = 0;        // sample mode only: shifts the clock to the sample's own time
let visitorIp;       // undefined = not asked yet, null = could not be read, string = the address
let shownState = null;
let openStage = { live: null, recorded: null };
let historyOpen = false;
let lighting = 0;    // token of the running lighting sequence
let holdPlate = false;
const lastHtml = new Map();

const now = () => Date.now() - skew;

// ---- small builders ---------------------------------------------------------------------------
const MARK_PATH = { pass: "M4 12.5l5 5L20 6.5", fail: "M6 6l12 12M18 6L6 18", skip: "M6 12h12" };
const MARK_WORD = { pass: "passed", fail: "failed", skip: "not checked" };
function mark(status, word) {
  return `<span class="mk" data-ok="${status}"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${MARK_PATH[status]}"/></svg><span class="vh">${esc(word ?? MARK_WORD[status])}</span></span>`;
}
const hash = (v) => (v ? `<span class="mono hash" title="${esc(v)}" data-full="${esc(v)}">${esc(short(v))}</span>` : "–");
const whole = (v) => (v === null || v === undefined || v === "" ? "–" : `<span class="mono">${esc(v)}</span>`);
const time = (iso, fmt = fmtDateHM) => (fmt(iso) ? `<time datetime="${esc(iso)}">${esc(fmt(iso))}</time>` : "–");
function txLink(tx, label) {
  const url = txUrl(json?.links, tx);
  const text = label ?? `<span class="mono" title="${esc(tx)}">${esc(short(tx))}</span>`;
  if (!tx) return "";
  return url ? `<a href="${esc(url)}" rel="noopener noreferrer">${text}</a>` : text;
}
function command(id, text, label = "Copy command") {
  return `<div class="cmd"><pre><code id="${id}">${esc(text)}</code></pre><button class="copy" type="button" data-copy-from="${id}" data-key="copy-${id}"><span>${label}</span></button></div>`;
}
const checkedAt = () => (json && Number.isFinite(Date.parse(json.checked_at)) ? json.checked_at : null);
const atTime = () => (checkedAt() ? fmtHM(checkedAt()) : failedAt ? fmtHM(failedAt) : fmtHM(now()));
const sentence = (s) => String(s ?? "").trim().replace(/[.\s]+$/, "");

/** Where keyboard focus sits inside a slot: a control's data-key, or a link's href and its place among equal links. */
function focusMark(el) {
  const a = document.activeElement;
  if (!a || a === el || !el.contains(a)) return null;
  if (a.dataset.key) return { sel: `[data-key="${CSS.escape(a.dataset.key)}"]`, n: 0 };
  if (!a.matches("a[href]")) return null;
  const sel = `a[href="${CSS.escape(a.getAttribute("href"))}"]`;
  return { sel, n: [...el.querySelectorAll(sel)].indexOf(a) };
}

/** Replace a slot's HTML only when it changed, keeping keyboard focus on the same control or link. */
function put(id, html) {
  if (lastHtml.get(id) === html) return false;
  const el = $(id);
  if (!el) return false;
  const mark = focusMark(el);
  el.innerHTML = html;
  lastHtml.set(id, html);
  if (mark) {
    const hits = el.querySelectorAll(mark.sel);
    (hits[mark.n] ?? hits[0])?.focus({ preventScroll: true });
  }
  return true;
}

/** Text that changes with the clock lives in its own element, so the slot around it is not rebuilt. */
function tick(id, text) {
  const el = $(id);
  if (el && el.textContent !== text) el.textContent = text;
}

// ---- hero -------------------------------------------------------------------------------------
const WORDS = { verified: "Verified", offline: "Offline", refused: "Refused", error: "No result", loading: "Checking", stale: "No recent result" };

function newestRevoke() {
  const events = Array.isArray(json?.registry?.events) ? json.registry.events : [];
  return events.find((e) => e?.kind === "revoke_compose") ?? null;
}

function plateText(state) {
  const n = checksOf(json?.verify).length;
  let line = "";
  let link = "";
  if (state === "verified") {
    line = `All ${n} checks passed at ${esc(fmtTime(checkedAt()))}.`;
  } else if (state === "offline") {
    line = "The exit is stopped, so there is nothing live to check. It is paid by the hour and runs for demos and judging.";
    if (json.replay?.captured_at && fmtDate(json.replay.captured_at)) {
      link = `<a href="#recorded">See the recorded check from ${esc(fmtDate(json.replay.captured_at))}</a>`;
    }
  } else if (state === "refused") {
    const f = failingCheck(json);
    const code = json.verify?.code;
    if (code === "E_COMPOSE_NOT_ALLOWED") {
      line = `The owner revoked this build on NEAR. The client stopped${f ? ` at check ${f.number}` : ""} and sent nothing.`;
      const revoke = newestRevoke();
      link = revoke?.tx ? txLink(revoke.tx, "See the revoke transaction") : `<a href="#history">See the history</a>`;
    } else if (f) {
      line = `Check ${f.number} failed: ${esc(f.check.name)}.${code ? ` Code <span class="mono">${esc(code)}</span>.` : ""} The client sent nothing.`;
    } else {
      line = `The client refused to connect${code ? ` with code <span class="mono">${esc(code)}</span>` : ""} and sent nothing.`;
    }
  } else if (state === "error") {
    const reason = json?.error ? sentence(json.error) : "this site's server did not return a result";
    line = `The check could not run at ${esc(atTime())}: ${esc(reason)}. Nothing on this page is confirmed until it runs again.`;
  } else if (state === "stale") {
    line = `The last check is ${esc(fmtSpan(now() - Date.parse(json.checked_at)))} old.`;
  } else {
    line = "Fetching the latest check.";
  }
  const long = state === "stale" ? " long" : "";
  return `<p class="plate-word${long}">${WORDS[state]}</p><p class="plate-line">${line}</p>${link ? `<p class="plate-link">${link}</p>` : ""}`;
}

function pipsHtml(state) {
  if (state === "loading") return "";
  const checks = checksOf(json?.verify);
  const live = state === "verified" || state === "refused";
  return checks
    .map((c, i) => {
      const s = live ? (c.ok === true ? "pass" : c.detail === "not checked" ? "skip" : "fail") : state === "offline" ? "skip" : "none";
      return `<li><a class="pip" href="#checks" tabindex="-1" data-pip="${i + 1}" data-ok="${s}" title="${i + 1}. ${esc(c.name)}"></a></li>`;
    })
    .join("");
}

function underPlate(state) {
  const run = `<a href="#run" data-key="run-yourself">Run the check yourself</a> to leave this page out of it.`;
  if (state === "loading") return "";
  if (sample) return `Sample data: a saved status response from ${esc(fmtDate(checkedAt()) || "an earlier day")}, shown on this machine only. Nothing here was checked just now. ${run}`;
  if (!checkedAt()) return run;
  const verb = state === "error" ? "Tried" : "Checked";
  return `${verb} by this site's server <span id="age"></span> ago. ${run}`;
}

function renderHero(state, animate) {
  $("plate-badge").hidden = !sample;
  const face = state === "verified" ? "go" : state === "refused" ? "stop" : "unlit";
  const chip = () => put("chip-text", (state === "verified" && checkedAt() ? `Verified <span class="chip-time">${esc(fmtHM(checkedAt()))}</span>` : WORDS[state]) + (sample ? ` <span class="chip-sample">sample</span>` : ""));
  put("platform", platformItems(json?.exit?.platform).map((p) => `<li>${esc(p)}</li>`).join(""));
  put("under-plate", underPlate(state));
  if (checkedAt()) tick("age", fmtSpan(now() - Date.parse(checkedAt())));
  const plate = $("plate");
  const pips = $("pips");
  const finish = () => {
    holdPlate = false;
    plate.dataset.face = face;
    document.documentElement.dataset.lit = "1";
    chip();
    put("plate-text", plateText(state));
    $("live").textContent = `Status: ${WORDS[state]}.`;
  };
  if (!animate) {
    put("pips", pipsHtml(state));
    if (!holdPlate) {
      plate.dataset.face = face;
      document.documentElement.dataset.lit = "1";
      chip();
      put("plate-text", plateText(state));
    }
    return;
  }
  delete document.documentElement.dataset.lit;
  // The sign lights: pips resolve in the order of the checks, then the face takes the verdict.
  const token = ++lighting;
  holdPlate = true;
  put("pips", pipsHtml(state));
  pips.classList.add("lighting");
  const items = [...pips.querySelectorAll(".pip")];
  const stopAt = items.findIndex((p) => p.dataset.ok === "fail");
  const count = stopAt < 0 ? items.length : stopAt + 1;
  items.forEach((p, i) => {
    if (i >= count) return p.classList.add("lit");
    setTimeout(() => token === lighting && p.classList.add("lit"), i * 40);
  });
  setTimeout(() => {
    if (token !== lighting) return;
    pips.classList.remove("lighting");
    finish();
  }, count * 40 + 60);
}

// ---- the checks -------------------------------------------------------------------------------
const ICONS = {
  hardware: '<rect x="8" y="8" width="18" height="18" rx="2"/><rect x="13" y="13" width="8" height="8"/><path d="M12 4v4M17 4v4M22 4v4M12 26v4M17 26v4M22 26v4M4 12h4M4 17h4M4 22h4M26 12h4M26 17h4M26 22h4"/>',
  keys: '<circle cx="11" cy="17" r="5"/><path d="M16 17h14M25 17v5M30 17v4"/>',
  image: '<path d="M17 4l11 6v14l-11 6-11-6V10z"/><path d="M6 10l11 6 11-6M17 16v14"/>',
  near: '<rect x="5" y="5" width="24" height="24" rx="3"/><path d="M10 12h14M10 17h14M10 22h8"/><path d="M21 23l2 2 4-4"/>',
  connection: '<path d="M8 15a9 9 0 0 1 16-5l2 2M26 19a9 9 0 0 1-16 5l-2-2"/><path d="M26 6v6h-6M8 28v-6h6"/>',
  other: '<circle cx="17" cy="17" r="12"/><path d="M11 17h12"/>',
};

function chainHtml(kind, checks) {
  const stages = groupChecks(checks);
  if (stages.length === 0) return "";
  const recorded = kind === "recorded";
  const open = openStage[kind];
  const tiles = stages
    .map((s, i) => {
      const total = s.rows.length;
      const failed = s.rows.find((r) => r.status === "fail");
      const count = s.status === "skip" ? "–" : `${s.passed}/${total}`;
      const m = s.status === "pass" ? mark("pass", "all passed") : s.status === "fail" ? mark("fail") : "";
      const line = s.status === "skip" ? "Not checked" : s.line;
      const code = s.status === "fail" && failed?.detail ? `<span class="tile-code mono">${esc(failed.detail)}</span>` : "";
      const joint = i === 0 ? "" : `<span class="joint" data-s="${recorded ? (s.status === "pass" ? "ink" : "none") : s.status}" aria-hidden="true"><i></i></span>`;
      const expanded = open === s.id;
      return `${joint}<button class="tile" type="button" data-kind="${kind}" data-stage="${s.id}" data-key="tile-${kind}-${s.id}" data-s="${s.status}" aria-expanded="${expanded}" aria-controls="rows-${kind}">
<svg class="tile-icon" viewBox="0 0 34 34" aria-hidden="true" focusable="false">${ICONS[s.id] ?? ICONS.other}</svg>
<span class="tile-title">${esc(s.title)}</span>
<span class="tile-count"><span>${count}</span>${m}</span>
<span class="tile-line">${esc(line)}</span>${code}
<span class="tile-more">${expanded ? "Hide the rows" : total === 1 ? "Show the row" : `Show the ${total} rows`}</span>
</button>`;
    })
    .join("");
  const s = stages.find((x) => x.id === open);
  const rows = s
    ? `<h4>${esc(s.title)}${recorded ? ", recorded" : ""}</h4>` +
      s.rows
        .map((r) => `<div class="check-row" data-ok="${r.status}"><span class="n">${r.number}</span>${mark(r.status)}<span><span>${esc(r.name)}</span>${r.detail ? `<span class="d">${esc(r.detail)}</span>` : ""}</span></div>`)
        .join("")
    : "";
  return `<div class="chain" data-chain="${kind}">${tiles}</div><div class="stage-rows" id="rows-${kind}"${s ? "" : " hidden"}>${rows}</div>`;
}

function recordedBlock() {
  const replay = json?.replay;
  const checks = checksOf(replay);
  if (!replay || checks.length === 0 || !fmtDateHM(replay.captured_at)) return "";
  const passed = checks.filter((c) => c.ok === true).length;
  const all = replay.verdict === "VERIFIED" && passed === checks.length;
  const line = all
    ? `All ${checks.length} checks passed when this was captured from the same exit. Replay it on your machine, without a network:`
    : `${passed} of ${checks.length} checks passed when this was captured. Replay it on your machine, without a network:`;
  return `<div class="recorded" id="recorded">
<h3>Recorded check, ${time(replay.captured_at)}</h3>
<p>${line}</p>
${command("cmd-replay-rec", CMD_REPLAY)}
${chainHtml("recorded", checks)}
</div>`;
}

function renderChecks(state) {
  const n = checksOf(json?.verify).length;
  $("checks-h").textContent = n > 0 && state !== "loading" && state !== "error" && state !== "stale"
    ? `The ${n} checks, in the order the client runs them`
    : "The checks, in the order the client runs them";
  let html = "";
  if (state === "verified" || state === "refused") {
    html = `<div class="live">${chainHtml("live", json.verify.checks)}</div>`;
  } else if (state === "offline") {
    const code = json.verify?.code ? ` (<span class="mono">${esc(json.verify.code)}</span>)` : "";
    html = `<p class="note-line">The exit did not answer${code}, so no check ran at ${esc(fmtHM(checkedAt()))}.</p>${recordedBlock()}`;
  } else if (state === "error") {
    html = `<p class="note-line">The checks could not run.</p>${recordedBlock()}`;
  } else if (state === "stale") {
    html = `<p class="note-line">The last result is from ${time(checkedAt(), fmtDateTime)}. It is more than five minutes old, so it is not shown.</p>${recordedBlock()}`;
  } else {
    html = `<p class="note-line quiet">Fetching the latest check.</p>`;
  }
  return put("checks-body", html);
}

function lightChain() {
  const chain = document.querySelector('.chain[data-chain="live"]');
  if (!chain) return;
  const token = lighting;
  chain.classList.add("lighting");
  const parts = [...chain.children];
  parts.forEach((el, k) => setTimeout(() => token === lighting && el.classList.add("lit"), Math.ceil(k / 2) * 150 - (k % 2 ? 75 : 0)));
  setTimeout(() => chain.classList.remove("lighting"), Math.ceil(parts.length / 2) * 150 + 400);
}

// ---- cards ------------------------------------------------------------------------------------
const CARD_ICONS = {
  log: '<rect x="7" y="4" width="18" height="24" rx="2"/><path d="M11 10h10M11 15h10M11 20h5"/><path d="M4 28L28 4"/>',
  ports: '<rect x="4" y="9" width="24" height="14" rx="2"/><path d="M9 14v4M14 14v4M19 14v4M24 14v4"/>',
  tunnel: '<path d="M4 26V15a12 12 0 0 1 24 0v11"/><path d="M10 26V16a6 6 0 0 1 12 0v10"/>',
  image: '<path d="M16 4l11 6v12l-11 6-11-6V10z"/><path d="M5 10l11 6 11-6M16 16v12"/>',
  chain: '<path d="M13 19l6-6"/><path d="M11 15l-3 3a4.2 4.2 0 0 0 6 6l3-3M21 17l3-3a4.2 4.2 0 0 0-6-6l-3 3"/>',
  gas: '<path d="M6 27V7a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v20M4 27h18M10 10h6"/><path d="M20 13h3a2 2 0 0 1 2 2v7a2 2 0 0 0 4 0V11l-4-4"/>',
  clock: '<circle cx="16" cy="16" r="11"/><path d="M16 9v7l5 3"/>',
  contract: '<path d="M8 4h12l6 6v18H8z"/><path d="M20 4v6h6M12 16h10M12 21h7"/>',
  key: '<circle cx="11" cy="16" r="5"/><path d="M16 16h12M24 16v5M28 16v4"/>',
  person: '<circle cx="16" cy="11" r="5"/><path d="M6 27a10 10 0 0 1 20 0"/>',
  globe: '<circle cx="16" cy="16" r="11"/><path d="M5 16h22M16 5c3.5 3.2 5 7 5 11s-1.5 7.8-5 11c-3.5-3.2-5-7-5-11s1.5-7.8 5-11z"/>',
  you: '<rect x="5" y="7" width="22" height="15" rx="2"/><path d="M2 25h28"/>',
  exit: '<rect x="6" y="5" width="20" height="9" rx="2"/><rect x="6" y="18" width="20" height="9" rx="2"/><path d="M10 9.5h2M10 22.5h2"/>',
};
const icon = (name) => `<span class="card-icon" aria-hidden="true"><svg viewBox="0 0 32 32" focusable="false">${CARD_ICONS[name]}</svg></span>`;

/** One card: an icon and a label, a big value, an optional unit line, then free text. */
function card({ ic, k, big = "", unit = "", body = "", hl = false, small = false }) {
  return `<article class="card${hl ? " card-hl" : ""}">
<div class="card-top">${icon(ic)}<h3 class="card-k">${k}</h3></div>
${big ? `<p class="card-big${small ? " sm" : ""}">${big}</p>` : ""}${unit ? `<p class="card-unit">${unit}</p>` : ""}
${body ? `<div class="card-body">${body}</div>` : ""}
</article>`;
}

/** A raw value in full, in mono, with a copy button. */
function rawRow(id, label, value, note = "") {
  if (value === null || value === undefined || value === "") return "";
  return `<div class="raw-row"><p class="raw-k">${label}</p><div class="raw-v"><code class="mono" id="${id}">${esc(value)}</code><button class="copy copy-sm" type="button" data-copy-from="${id}" data-key="copy-${id}"><span>Copy</span><span class="vh"> ${label.toLowerCase()}</span></button></div>${note ? `<p class="raw-note">${note}</p>` : ""}</div>`;
}
const raws = (rows) => (rows.join("") ? `<div class="raw">${rows.join("")}</div>` : "");
const countAttr = (n, key, suffix = "") => (typeof n === "number" && Number.isFinite(n) && n > 0 ? ` data-count="${n}" data-count-key="${key}"${suffix ? ` data-count-suffix="${suffix}"` : ""}` : "");

// ---- build ------------------------------------------------------------------------------------
const unavailable = (state, what = "the check could not run") =>
  state === "loading"
    ? `<p class="note-line quiet">Fetching the latest check.</p>`
    : state === "stale"
      ? `<p class="note-line">Not available: the last check is more than five minutes old.</p>`
      : `<p class="note-line">Not available: ${what}.</p>`;

function renderBuild(state) {
  const known = !(state === "loading" || state === "error" || state === "stale");
  const live = known && state === "verified" && json.exit?.compose ? json.exit.compose : null;
  const c = known ? (live ?? json.replay?.compose ?? null) : null;
  const status = c ? allowlistStatus(json.registry?.events, c.hash) : null;
  const approval = approvalSentence(status);
  put("build-lead", approval ? ` ${esc(approval)}` : "");
  if (!known) return put("build-body", unavailable(state));
  if (!c) return put("build-body", `<p class="note-line">Not available: this response carries no build values.</p>`);
  let label = "";
  if (!live) {
    const why = state === "offline" ? "The exit is stopped" : state === "refused" ? "The client refused to connect" : "The exit returned no build values";
    label = `<p class="label-recorded">Recorded ${time(json.replay.captured_at)}. ${why}, so these are not live values.</p>`;
  }
  let allow = `<span class="quiet">The history read at ${esc(atTime())} does not show this hash.</span>`;
  if (status?.allowed) allow = `<span class="live">${mark("pass", "allowed")}</span> Allowed on NEAR, ${time(status.event.at)}. ${txLink(status.event.tx)}`;
  else if (status) allow = `<span class="live">${mark("fail", "revoked")}</span> Revoked on NEAR, ${time(status.event.at)}. The registry no longer allows this build. ${txLink(status.event.tx)}`;
  const ports = Array.isArray(c.allowed_ports) ? c.allowed_ports.join(", ") : null;
  const pinned = typeof c.image === "string" && c.image.includes("@sha256:");
  const v = (x) => (x === null || x === undefined || x === "" ? "–" : esc(x));
  return put(
    "build-body",
    `${label}<div class="cards cards-4">
${card({ ic: "log", k: "Logging", big: c.logging ? `<span class="mono">logging: ${esc(c.logging)}</span>` : "–", body: c.logging === "none" ? "<p>Container logging is off.</p>" : "", hl: c.logging === "none" })}
${card({ ic: "ports", k: "Ports", big: v(ports), body: ports ? "<p>The exit dials nothing else.</p>" : "" })}
${card({ ic: "tunnel", k: "Tunnels", big: `<span${countAttr(c.max_tunnels, "tunnels")}>${v(c.max_tunnels)}</span>`, body: c.max_tunnels != null ? "<p>At most, at once.</p>" : "" })}
${card({ ic: "image", k: "Image", big: pinned ? "Pinned by digest" : "–", small: true, body: pinned ? "<p>The exact image, named by its sha256.</p>" : "" })}
</div>
${raws([rawRow("raw-image", "Image", c.image), rawRow("raw-compose", "Compose hash", c.hash, allow)])}`,
  );
}

// ---- NEAR -------------------------------------------------------------------------------------
function renderNear(state) {
  if (state === "loading" || state === "stale") return put("near-body", unavailable(state));
  if (state === "error") return put("near-body", unavailable(state, `the registry could not be read at ${esc(atTime())}`));
  const i = json.instance;
  if (!i) return put("near-body", `<p class="note-line">No registration found for this exit at ${esc(atTime())}.</p>`);
  const gasN = typeof i.registration_gas_tgas === "number" ? i.registration_gas_tgas : null;
  const gas = gasN !== null ? `, ${esc(gasN)} Tgas` : "";
  const exp = expiryOf(i, now());
  let expires = "–";
  if (exp?.expired) expires = `Expired ${time(i.expires_at)}. The exit registers again when it runs.`;
  else if (exp) expires = `Expires ${time(i.expires_at)}, in <span id="expires-in"></span>. The exit re-registers every 6 hours while it runs.`;
  const refusedNote = state === "refused"
    ? `<p class="note-line">A registration can stay in place while a build is revoked. The client reads the registry again before every connection.</p>`
    : "";
  const fact = (k, val) => `<div><dt>${k}</dt><dd>${val}</dd></div>`;
  const txUrlFull = txUrl(json?.links, i.registration_tx);
  put(
    "near-body",
    `<p class="gas">Before the registry listed this exit's keys, the contract verified the exit's Intel quote on chain: 13 checks in one transaction${gas}.</p>
${refusedNote}<div class="cards cards-3">
${card({ ic: "chain", k: "Intel check on chain", big: `<span data-count="13" data-count-key="near13" data-count-suffix="/13">13/13</span>`, unit: "checks, run by the NEAR contract", hl: true })}
${gasN !== null ? card({ ic: "gas", k: "Gas for the whole check", big: `<span${countAttr(gasN, "gas")}>${esc(gasN)}</span>`, unit: "Tgas, one transaction" }) : ""}
${card({ ic: "clock", k: "Registered", big: time(i.registered_at), small: true, body: `<p>${expires}</p>` })}
</div>
<dl class="facts">
${fact("Operator", whole(i.operator))}
${fact("Organisation", whole(i.organization))}
${fact("Registry", whole(json.registry?.account))}
${fact("Root", whole(json.registry?.root))}
</dl>
${raws([rawRow("raw-reg-tx", "Registration transaction", i.registration_tx, txUrlFull ? `<a href="${esc(txUrlFull)}" rel="noopener noreferrer">Open it on NearBlocks</a>` : "")])}`,
  );
  if (exp && !exp.expired) tick("expires-in", fmtSpan(exp.at - now()));
}

// ---- keys -------------------------------------------------------------------------------------
function renderKeys(state) {
  const read = state === "verified" || state === "offline" || state === "refused";
  const r = json?.registry;
  const notRead = `<p>Not read at ${esc(atTime())}.</p>`;
  const waiting = `<p class="quiet">Fetching the latest check.</p>`;
  const blank = state === "loading" ? waiting : notRead;

  let regBig = "–";
  let regUnit = "";
  let regWho = "";
  let regEv = blank;
  let codeRaw = "";
  if (read && typeof r?.full_access_keys === "number") {
    const n = r.full_access_keys;
    const acct = r.account ? `The account <span class="mono">${esc(r.account)}</span>` : "The account";
    regBig = `<span class="big-num">${esc(n)}</span>`;
    regUnit = n === 1 ? "full-access key" : "full-access keys";
    if (n === 0) {
      regWho = "Nobody.";
      regEv = `<ul><li>${mark("pass", "confirmed")}<span>${acct} has 0 full-access keys, so no one can deploy different code under its name.</span></li>`;
    } else {
      regWho = n === 1 ? "Whoever holds its key." : "Whoever holds one of its keys.";
      regEv = `<ul><li><span>${acct} has ${n} full-access ${n === 1 ? "key" : "keys"}. Whoever holds ${n === 1 ? "it" : "one"} can replace the contract.</span></li>`;
    }
    if (r.code_hash) {
      regEv += r.reproducible_build === true
        ? `<li>${mark("pass", "confirmed")}<span>It rebuilds from the repo to its code hash.</span></li>`
        : `<li><span>Its code hash is below.</span></li>`;
      codeRaw = raws([rawRow("raw-code", "Code hash", r.code_hash)]);
    }
    regEv += "</ul>";
  }

  let exitEv = blank;
  let keyRaw = "";
  if (read) {
    const kh = json.instance?.key_hash;
    if (!kh) {
      exitEv = `<p>No registration found for this exit at ${esc(atTime())}, so there is no key hash to show.</p>`;
    } else {
      exitEv = `<p data-more="keys-exit">The hash of its keys is inside the Intel-signed quote and in its NEAR registration. Nobody else can answer as this exit.</p>`;
      if (state === "offline") {
        const rec = checksOf(json.replay).filter((c) => KEY_CHECKS.includes(c.name) && c.ok === true).length;
        if (rec === KEY_CHECKS.length) exitEv += `<p>Both checks that bind the keys are in the <a href="#recorded">recorded check</a>.</p>`;
      } else {
        const rows = groupChecks(json.verify.checks).flatMap((s) => s.rows).filter((x) => KEY_CHECKS.includes(x.name));
        if (rows.length) exitEv += `<ul>${rows.map((x) => `<li>${mark(x.status)}<span class="mono">${esc(x.name)}</span></li>`).join("")}</ul>`;
      }
      keyRaw = raws([rawRow("raw-keyhash", "Key hash", kh)]);
    }
  }

  const owner = json?.registry?.owner;
  const who = (text) => (text ? `<p class="card-who">${text}</p>` : "");
  return put(
    "keys-body",
    `<div class="cards cards-2 live">
${card({ ic: "contract", k: "Registry contract", big: regBig, unit: regUnit, body: who(regWho) + regEv + codeRaw, hl: regWho === "Nobody." })}
${card({ ic: "key", k: "The exit", big: "In memory only", small: true, body: exitEv + keyRaw })}
${card({ ic: "person", k: "The owner", big: "One NEAR account", small: true, body: `<p>It allows and revokes builds from the command line. Every call is a transaction in the <a href="#history">history below</a>.</p>${owner ? raws([rawRow("raw-owner", "Owner account", owner)]) : ""}` })}
${card({ ic: "globe", k: "This site", big: "No key", small: true, body: "<p>No wallet, no signing, no transactions. It reads the registry and the exit and shows the result.</p>" })}
</div>`,
  );
}

// ---- history ----------------------------------------------------------------------------------
function renderHistory(state) {
  if (state === "loading" || state === "stale") return put("history-body", unavailable(state));
  const events = Array.isArray(json?.registry?.events) ? json.registry.events.filter((e) => e && typeof e === "object") : [];
  const account = json?.registry?.account;
  const url = accountUrl(json?.links, account);
  if (state === "error" || events.length === 0) {
    const open = url ? ` <a href="${esc(url)}" rel="noopener noreferrer">Open the registry on NearBlocks</a>.` : "";
    return put("history-body", `<p class="note-line">The history could not be read at ${esc(atTime())}.${open}</p>`);
  }
  const running = json.exit?.compose?.hash ?? json.replay?.compose?.hash ?? null;
  const allowed = allowlistStatus(events, running);
  const shown = historyOpen ? events : events.slice(0, HISTORY_SHOWN);
  const rows = shown
    .map((e) => {
      let m = "";
      if (isRevoke(e.kind)) m = mark("fail", "revoked");
      else if (allowed?.allowed && e === allowed.event) m = mark("pass", "allowed now");
      const subject = e.hash ? hash(e.hash) : e.account ? `${whole(e.account)}${e.org ? `, ${esc(e.org)}` : ""}` : "";
      return `<li class="row"><span>${time(e.at, fmtDateTime)}</span><span class="row-what">${m}<span>${esc(eventWords(e.kind))}</span></span><span>${subject}</span><span>${txLink(e.tx)}</span></li>`;
    })
    .join("");
  // Compact by default: the newest few, then one button that shows or hides the rest.
  const more = events.length > HISTORY_SHOWN
    ? `<button class="more-btn" type="button" data-action="history-all" data-key="history-all" aria-controls="history-events" aria-expanded="${historyOpen}">${historyOpen ? "Show the newest " + HISTORY_SHOWN : `Show all ${events.length} changes`}</button>`
    : "";

  const anchors = Array.isArray(json.receipts?.anchors) ? json.receipts.anchors.filter((a) => a && typeof a === "object") : [];
  const anchorRows = anchors
    .map((a) => `<li class="row"><span>${time(a.at, fmtDateTime)}</span><span class="row-what"><span>${esc(a.count)} ${a.count === 1 ? "receipt" : "receipts"} anchored</span></span><span>${Number.isInteger(a.first_seq) ? `From sequence ${a.first_seq}` : ""}</span><span>${txLink(a.tx)}</span></li>`)
    .join("");
  const receipts = `<div class="receipts"><h3>Session receipts</h3>
<p data-more="receipts">The exit anchors Merkle roots of its session receipts on the same contract. A receipt holds hashes, sequence numbers and times, never a destination.</p>
${anchors.length ? `<ol class="rows anchors">${anchorRows}</ol>` : `<p>No anchors were read at ${esc(atTime())}.</p>`}</div>`;
  return put("history-body", `<ol class="rows events live" id="history-events">${rows}</ol>${more}${receipts}`);
}

// ---- traffic ----------------------------------------------------------------------------------
function renderTraffic(state) {
  const you = visitorIp === undefined ? `<p class="pair-value word">Reading</p>` : visitorIp === null ? `<p class="pair-value word">Not read</p>` : `<p class="pair-value">${esc(visitorIp)}</p>`;
  const exitIp = state === "verified" && typeof json.exit?.egress_ip === "string" ? json.exit.egress_ip : null;
  let exit = `<p class="pair-value word">Not measured</p>`;
  let line = "";
  if (exitIp) {
    exit = `<p class="pair-value">${esc(exitIp)}</p>`;
    line = `<p class="traffic-line">A site opened through ProvenExit sees the second address, a Phala machine, and not yours. It was fetched through the verified tunnel at ${esc(fmtTime(checkedAt()))}.</p>`;
    if (visitorIp && visitorIp === exitIp) line = `<p class="traffic-line"><strong>You are coming through the exit.</strong></p>${line}`;
  } else if (state === "offline") {
    exit = `<p class="pair-value word">None</p><p class="pair-why">The exit is stopped, so nothing leaves through it.</p>`;
  } else if (state === "refused") {
    exit = `<p class="pair-value word">None</p><p class="pair-why">The client refused to connect, so nothing went through the exit.</p>`;
  } else if (state === "loading") {
    exit = `<p class="pair-value word">Checking</p>`;
  }
  return put("traffic-body", `<div class="pair"><div class="pair-card"><p class="pair-label">${icon("you")}You, now</p>${you}</div><div class="pair-arrow" aria-hidden="true"><svg viewBox="0 0 48 24" focusable="false"><path d="M2 12h42M34 3l10 9-10 9"/></svg></div><div class="pair-card pair-exit"><p class="pair-label">${icon("exit")}Through the exit</p>${exit}</div></div>${line}`);
}

// ---- run it, agents ---------------------------------------------------------------------------
function renderRun(state) {
  const repo = safeUrl(json?.links?.repo);
  let clone = "";
  if (repo) {
    const dir = new URL(repo).pathname.split("/").filter(Boolean).pop() ?? "";
    if (/^[\w.-]+$/.test(dir)) clone = `<div class="cmd-block clone"><h3>Get the code</h3>${command("cmd-clone", `git clone ${repo.replace(/\/$/, "")}.git && cd ${dir}`)}</div>`;
  }
  const note = state === "offline"
    ? `<p class="cmd-note">The exit is stopped right now, so this command reports it as unreachable.</p>`
    : state === "refused" && json.verify?.code === "E_COMPOSE_NOT_ALLOWED"
      ? `<p class="cmd-note">The build is revoked right now, so this command prints the same refusal.</p>`
      : state === "refused"
        ? `<p class="cmd-note">The client refuses the exit right now, so this command prints the same refusal.</p>`
        : "";
  const liveCmd = `<div class="cmd-block"><h3>Verify the live exit and send one request through it</h3>${command("cmd-live", CMD_LIVE)}${note}
<p data-more="run-live" data-more-label="What it does">Prints every check, starts a local SOCKS5 proxy on 127.0.0.1:18180, and shows your IP next to the IP a website sees through the exit. It changes no system settings and needs no sudo.</p></div>`;
  const captured = json?.replay?.captured_at && fmtDate(json.replay.captured_at) ? `, captured ${time(json.replay.captured_at, fmtDate)}` : "";
  const lines = checksOf(json?.replay).length;
  const see = lines > 0 ? `${lines} ✔ lines` : "one ✔ line for each check";
  const replayCmd = `<div class="cmd-block"><h3>Replay the recorded check without a network</h3>${command("cmd-replay", CMD_REPLAY)}
<p>Replays the same exit's quote and registry state${captured}. You see ${see} and ✔ VERIFIED (FIXTURE REPLAY …).</p></div>`;
  const video = safeUrl(CONFIG.demoVideoUrl);
  const videoLink = video ? `<p class="video"><a class="btn" href="${esc(video)}" rel="noopener noreferrer">Watch the demo video</a></p>` : "";
  return put("run-body", `${clone}${state === "offline" ? replayCmd + liveCmd : liveCmd + replayCmd}${videoLink}`);
}

function renderAgents(state) {
  const tool = `<span class="mono">fetch_via_exit</span>`;
  const code = json?.verify?.code ? ` and returns <span class="mono">${esc(json.verify.code)}</span>` : "";
  let html = "";
  if (state === "verified") {
    html = `<p class="agents-live">${mark("pass", "confirmed")}<span>As of ${esc(fmtTime(checkedAt()))} every check passes, so ${tool} fetches.</span></p>`;
  } else if (state === "offline") {
    html = `<p class="agents-live"><span>The exit is stopped, so ${tool} fetches nothing${code}.</span></p>`;
  } else if (state === "refused") {
    const why = json.verify?.code === "E_COMPOSE_NOT_ALLOWED" ? "The build is revoked" : "A check fails";
    html = `<p class="agents-live" data-ok="fail">${mark("fail", "refused")}<span>${why}, so ${tool} fetches nothing${code}.</span></p>`;
  }
  put("agents-live", html ? `<div class="live">${html}</div>` : "");
  const repo = safeUrl(json?.links?.repo);
  put("mcp-path", repo
    ? `<a class="mono" href="${esc(repo.replace(/\/$/, ""))}/tree/HEAD/mcp/dist" rel="noopener noreferrer">mcp/dist/provenexit-mcp.mjs</a>`
    : `<span class="mono">mcp/dist/provenexit-mcp.mjs</span>`);
}

// ---- static bindings --------------------------------------------------------------------------
const pathOf = (obj, path) => path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
function renderBindings() {
  for (const el of document.querySelectorAll("[data-bind]")) {
    el.dataset.fallback ??= el.textContent;
    const v = pathOf(json, el.dataset.bind);
    el.textContent = typeof v === "string" && v !== "" ? v : el.dataset.fallback;
  }
  for (const el of document.querySelectorAll("[data-bind-platform]")) {
    const items = platformItems(json?.exit?.platform);
    el.textContent = items.length ? items.join(", ") : "–";
  }
  for (const el of document.querySelectorAll("[data-href]")) {
    const url = safeUrl(pathOf(json, el.dataset.href));
    const holder = el.closest("p[hidden], li") ?? el;
    if (url) {
      el.href = url.replace(/\/$/, "") + (el.dataset.hrefSuffix ?? "");
      el.rel = "noopener noreferrer";
      el.hidden = false;
      if (holder.tagName === "P") holder.hidden = false;
    } else if (!el.hasAttribute("href")) {
      el.hidden = true;
    }
  }
}

// ---- render -----------------------------------------------------------------------------------
function render() {
  const state = deriveState(json, now());
  const changed = state !== shownState;
  const live = state === "verified" || state === "refused";
  const animate = changed && live && !reduced.matches && document.visibilityState === "visible";
  if (changed) {
    if (!animate) { lighting++; holdPlate = false; }
    openStage = { live: null, recorded: null };
    if (state === "refused") {
      const f = failingCheck(json);
      const stage = f && groupChecks(json.verify.checks).find((s) => s.rows.some((r) => r.number === f.number));
      openStage.live = stage?.id ?? null;
    }
    document.documentElement.dataset.state = state;
    shownState = state;
    const hm = state === "verified" && checkedAt() ? ` ${fmtHM(checkedAt())}` : "";
    document.title = { verified: `ProvenExit: verified${hm}`, offline: "ProvenExit: offline", refused: "ProvenExit: refused" }[state] ?? "ProvenExit";
    if (!animate) $("live").textContent = state === "loading" ? "" : `Status: ${WORDS[state]}.`;
  } else if (state === "verified" && checkedAt()) {
    document.title = `ProvenExit: verified ${fmtHM(checkedAt())}`;
  }
  renderHero(state, animate);
  renderChecks(state);
  if (animate) lightChain();
  renderBindings();
  renderBuild(state);
  renderNear(state);
  renderKeys(state);
  renderHistory(state);
  renderTraffic(state);
  renderRun(state);
  renderAgents(state);
  enhanceMore();
  scanMotion();
}

// ---- data -------------------------------------------------------------------------------------
let inFlight = false;
async function load() {
  if (inFlight || sample === "loading") return;
  inFlight = true;
  try {
    const url = sample ? `/fixtures/${SAMPLES[sample]}.json` : "/api/status";
    const res = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    json = body;
    failedAt = null;
    if (sample) {
      // Samples carry their own time. The clock is shifted so the sample reads as it did then.
      const at = Date.parse(body.checked_at);
      const age = sample === "stale" ? 12 * 60_000 : 3000;
      skew = Number.isFinite(at) ? Date.now() - (at + age) : 0;
    }
  } catch {
    json = null;
    failedAt = Date.now();
  } finally {
    inFlight = false;
  }
  render();
}

async function loadIp() {
  try {
    const res = await fetch("/api/ip", { cache: "no-store", signal: AbortSignal.timeout(10_000) });
    const body = res.ok ? await res.json() : null;
    visitorIp = typeof body?.ip === "string" && body.ip !== "" ? body.ip : null;
  } catch {
    visitorIp = null;
  }
  render();
}

// ---- events -----------------------------------------------------------------------------------
function openStageFor(kind, id, toggle) {
  openStage[kind] = toggle && openStage[kind] === id ? null : id;
  renderChecks(shownState);
}

document.addEventListener("click", (ev) => {
  const t = ev.target instanceof Element ? ev.target : null;
  if (!t) return;
  const tile = t.closest(".tile");
  if (tile) return openStageFor(tile.dataset.kind, tile.dataset.stage, true);

  const pip = t.closest(".pip");
  if (pip && (shownState === "verified" || shownState === "refused")) {
    const n = Number(pip.dataset.pip);
    const stage = groupChecks(json?.verify?.checks).find((s) => s.rows.some((r) => r.number === n));
    if (stage) openStageFor("live", stage.id, false);
    return;
  }

  if (t.closest('[data-action="history-all"]')) {
    historyOpen = !historyOpen;
    renderHistory(shownState);
    // The button is redrawn with its new state; keep the focus on it.
    document.querySelector('[data-action="history-all"]')?.focus({ preventScroll: true });
    enhanceMore();
    scanMotion();
    return;
  }

  const copy = t.closest(".copy");
  if (copy) {
    const text = $(copy.dataset.copyFrom)?.textContent ?? "";
    const label = copy.firstElementChild;
    const original = copy.dataset.label ?? (copy.dataset.label = label.textContent);
    const done = (word) => {
      label.textContent = word;
      clearTimeout(copy._t);
      copy._t = setTimeout(() => { label.textContent = original; }, 2000);
    };
    (navigator.clipboard?.writeText(text) ?? Promise.reject()).then(() => done("Copied ✓"), () => {
      // No clipboard access: select the command so it can be copied by hand.
      const range = document.createRange();
      range.selectNodeContents($(copy.dataset.copyFrom));
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      done("Selected");
    });
    return;
  }

  const menu = $("menu");
  const btn = $("menu-btn");
  if (t.closest("#menu-btn")) {
    const open = !menu.classList.contains("open");
    menu.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", String(open));
    btn.textContent = open ? "Close" : "Menu";
  } else if (menu.classList.contains("open") && (t.closest("#menu a") || t.closest(".brand") || t.closest("#chip"))) {
    menu.classList.remove("open");
    btn.setAttribute("aria-expanded", "false");
    btn.textContent = "Menu";
  }
});

document.addEventListener("keydown", (ev) => {
  const menu = $("menu");
  if (ev.key === "Escape" && menu.classList.contains("open")) {
    menu.classList.remove("open");
    $("menu-btn").setAttribute("aria-expanded", "false");
    $("menu-btn").textContent = "Menu";
    $("menu-btn").focus();
  }
});

// Copying a shortened hash copies the whole value.
document.addEventListener("copy", (ev) => {
  const sel = getSelection();
  if (!sel || sel.isCollapsed || sel.rangeCount !== 1) return;
  const node = sel.getRangeAt(0).commonAncestorContainer;
  const el = (node.nodeType === 1 ? node : node.parentElement)?.closest?.(".hash");
  if (el?.dataset.full && sel.toString().trim() === el.textContent.trim()) {
    ev.clipboardData.setData("text/plain", el.dataset.full);
    ev.preventDefault();
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") load();
});

function sampleTag() {
  if (!isLocal || sampleParam === null) return;
  const names = ["online", "offline", "refused", "error", "stale", "offline-retired"];
  const tag = document.createElement("nav");
  tag.className = "sample-tag";
  tag.setAttribute("aria-label", "Sample data");
  tag.innerHTML = `<span>Sample data, not live:</span>${names.map((n) => `<a href="?sample=${n}"${n === sample ? ' aria-current="true"' : ""}>${n}</a>`).join("")}<a href="/">live</a>`;
  document.body.append(tag);
}

// ---- start ------------------------------------------------------------------------------------
sampleTag();
startMotion();
startMore(scanMotion);
render();
load();
loadIp();
setInterval(() => document.visibilityState === "visible" && load(), POLL_MS);
setInterval(() => document.visibilityState === "visible" && shownState !== "loading" && render(), 1000);
