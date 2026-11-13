import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  deriveState, colourOf, failingCheck, groupChecks, allowlistStatus, approvalSentence, rowStatus, expiryOf,
  short, fmtDateTime, fmtHM, fmtSpan, platformItems, txUrl, safeUrl, accountUrl, STALE_MS,
} from "../assets/state.js";
import { DEADLINE_MS, TIMEOUTS, withDeadline } from "../api/_lib/deadline.mjs";

const here = new URL(".", import.meta.url);
const text = (p) => readFileSync(new URL(p, here), "utf8");
const fixture = (name) => JSON.parse(text(`../fixtures/${name}.json`));
const just = (json) => Date.parse(json.checked_at) + 14_000; // 14 s after the check
const clone = (v) => structuredClone(v);

const online = fixture("online");
const offline = fixture("offline");
const retired = fixture("offline-retired");
const refused = fixture("refused");
const error = fixture("error");

test("the state table, one case per row", () => {
  assert.equal(deriveState(undefined, Date.now()), "loading");
  assert.equal(deriveState(null, Date.now()), "error");
  assert.equal(deriveState("<html>", Date.now()), "error");
  assert.equal(deriveState([], Date.now()), "error");
  assert.equal(deriveState(error, just(error)), "error");
  assert.equal(deriveState(online, Date.parse(online.checked_at) + STALE_MS + 1), "stale");
  assert.equal(deriveState(offline, just(offline)), "offline");
  assert.equal(deriveState(retired, just(retired)), "offline");
  assert.equal(deriveState(online, just(online)), "verified");
  assert.equal(deriveState(refused, just(refused)), "refused");
});

test("offline wins over REFUSED", () => {
  assert.equal(offline.verify.verdict, "REFUSED");
  assert.equal(deriveState(offline, just(offline)), "offline");
  const j = clone(refused);
  j.exit.online = false;
  assert.equal(deriveState(j, just(j)), "offline");
});

test("a stopped exit is never verified, whatever the verdict says", () => {
  for (const value of [false, null, undefined, "true", 1]) {
    const j = clone(online);
    j.exit.online = value;
    assert.equal(deriveState(j, just(j)), "offline", `online=${String(value)}`);
  }
  const j = clone(online);
  delete j.exit;
  assert.equal(deriveState(j, just(j)), "offline");
});

test("error wins over VERIFIED", () => {
  const j = clone(online);
  j.error = "registry unreadable: fetch failed";
  assert.equal(deriveState(j, just(j)), "error");
  j.error = "";
  assert.equal(deriveState(j, just(j)), "error");
});

test("VERIFIED with a failed check, or with no checks, is not verified", () => {
  const a = clone(online);
  a.verify.checks[4].ok = false;
  assert.equal(deriveState(a, just(a)), "error");
  const b = clone(online);
  b.verify.checks = [];
  assert.equal(deriveState(b, just(b)), "error");
  const c = clone(online);
  delete c.verify.checks;
  assert.equal(deriveState(c, just(c)), "error");
  const d = clone(online);
  d.verify.checks[0].ok = "true";
  assert.equal(deriveState(d, just(d)), "error");
});

test("an unknown verdict or a missing checked_at is an error", () => {
  const a = clone(online);
  a.verify.verdict = "OK";
  assert.equal(deriveState(a, just(a)), "error");
  const b = clone(online);
  delete b.checked_at;
  assert.equal(deriveState(b, Date.now()), "error");
});

test("stale: a verified result older than five minutes is not shown as verified", () => {
  const at = Date.parse(online.checked_at);
  assert.equal(deriveState(online, at + STALE_MS), "verified");
  assert.equal(deriveState(online, at + STALE_MS + 1), "stale");
  assert.equal(colourOf(online, at + STALE_MS + 1).face, "unlit");
  assert.equal(colourOf(online, at + STALE_MS + 1).marks, false);
});

test("nothing is green unless the verdict is VERIFIED and the exit is online", () => {
  const variants = [];
  for (const base of [online, offline, retired, refused, error]) {
    for (const exitOnline of [true, false, null]) {
      for (const verdict of ["VERIFIED", "REFUSED", "OK", null]) {
        for (const err of [null, "registry unreadable"]) {
          for (const age of [14_000, STALE_MS + 1]) {
            for (const breakCheck of [false, true]) {
              const j = clone(base);
              j.exit.online = exitOnline;
              j.verify.verdict = verdict;
              j.error = err;
              if (breakCheck && j.verify.checks.length > 0) j.verify.checks[0].ok = false;
              variants.push([j, Date.parse(j.checked_at) + age]);
            }
          }
        }
      }
    }
  }
  let green = 0;
  for (const [j, now] of variants) {
    const c = colourOf(j, now);
    if (c.face === "go") {
      green++;
      assert.equal(j.verify.verdict, "VERIFIED");
      assert.equal(j.exit.online, true);
      assert.equal(j.error, null);
      assert.ok(j.verify.checks.length > 0 && j.verify.checks.every((x) => x.ok === true));
      assert.ok(now - Date.parse(j.checked_at) <= STALE_MS);
    }
    // No mark of any colour without a current answer from a running exit.
    if (c.marks) {
      assert.equal(j.exit.online, true);
      assert.equal(j.error, null);
      assert.ok(now - Date.parse(j.checked_at) <= STALE_MS);
    }
    assert.equal(c.face === "go", c.state === "verified");
    assert.equal(c.face === "stop", c.state === "refused");
  }
  assert.ok(green > 0, "the verified case is in the set");
  for (const input of [undefined, null, "x"]) {
    assert.deepEqual(colourOf(input, Date.now()), { state: input === undefined ? "loading" : "error", face: "unlit", marks: false });
  }
});

test("the stylesheet uses the green and red tokens only under a verified or refused page state", () => {
  const css = text("../assets/styles.css").replace(/\/\*[\s\S]*?\*\//g, "");
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => [m[1].trim(), m[2]]);
  const coloured = rules.filter(([, body]) => /var\(--(go|stop)[a-z-]*\)/.test(body));
  assert.ok(coloured.length > 0, "the state rules exist");
  for (const [selector, body] of coloured) {
    const allowed = /var\(--stop[a-z-]*\)/.test(body) && !/var\(--go[a-z-]*\)/.test(body)
      ? /^html\[data-state="refused"\]|^html\[data-state="verified"\]/
      : /^html\[data-state="verified"\]|^html\[data-state="refused"\]/;
    for (const part of selector.split(",").map((s) => s.trim())) {
      assert.match(part, allowed, `colour outside a state selector: ${part}`);
      assert.doesNotMatch(part, /\.recorded/, `colour inside a recorded block: ${part}`);
    }
  }
  // The raw hex values appear once, where the tokens are defined.
  for (const hex of ["#3DDC84", "#0E7A40", "#FF6B57", "#B4231A"]) {
    assert.equal(css.split(hex).length - 1, 1, `${hex} is used once`);
  }
  // The plate turns green only for the verified state.
  for (const [selector, body] of coloured.filter(([, b]) => /var\(--go\)/.test(b))) {
    for (const part of selector.split(",")) assert.match(part.trim(), /^html\[data-state="verified"\]/);
    assert.ok(body.length > 0);
  }
});

test("refused: the failing check is the first failed row, not a row that was never reached", () => {
  const f = failingCheck(refused);
  assert.equal(f.number, 16);
  assert.equal(f.check.name, "compose hash allowed by registry");
  assert.equal(f.check.detail, "E_COMPOSE_NOT_ALLOWED");
  assert.equal(failingCheck(online), null);
  assert.equal(rowStatus({ ok: false, detail: "not checked" }), "skip");
  assert.equal(rowStatus({ ok: false, detail: "" }), "fail");
  assert.equal(rowStatus({ ok: true, detail: "" }), "pass");
});

test("stages: counts come from the data, the live list has 20 rows and the replay 16", () => {
  const live = groupChecks(online.verify.checks);
  assert.deepEqual(live.map((s) => [s.id, s.passed, s.rows.length, s.status]), [
    ["hardware", 8, 8, "pass"], ["keys", 2, 2, "pass"], ["image", 4, 4, "pass"], ["near", 4, 4, "pass"], ["connection", 2, 2, "pass"],
  ]);
  // the registry code-hash check runs first (row 1) but belongs to the NEAR stage
  assert.deepEqual(live.flatMap((s) => s.rows.map((r) => r.number)).sort((a, b) => a - b), Array.from({ length: 20 }, (_, i) => i + 1));
  assert.equal(live.find((s) => s.id === "near").rows[0].number, 1);
  const rec = groupChecks(online.replay.checks);
  assert.deepEqual(rec.map((s) => [s.id, s.rows.length]), [["hardware", 7], ["keys", 2], ["image", 4], ["near", 3]]);
  const r = groupChecks(refused.verify.checks);
  assert.deepEqual(r.map((s) => s.status), ["pass", "pass", "pass", "fail", "skip"]);
  const off = groupChecks(offline.verify.checks);
  assert.deepEqual(off.map((s) => s.status), ["fail", "skip", "skip", "skip", "skip"]);
  const extra = groupChecks([...online.verify.checks, { name: "a new check", ok: true, detail: "" }]);
  assert.equal(extra.at(-1).id, "other");
  assert.equal(extra.at(-1).rows[0].number, 21);
  assert.deepEqual(groupChecks(undefined), []);
});

test("allowlist status comes from the newest matching event", () => {
  const hash = online.exit.compose.hash;
  assert.equal(allowlistStatus(online.registry.events, hash).allowed, true);
  assert.equal(allowlistStatus(refused.registry.events, hash).allowed, false);
  assert.equal(allowlistStatus([], hash), null);
  assert.equal(allowlistStatus(online.registry.events, null), null);
  // Real history: the first exit's compose was allowed at 12:43 and revoked at 20:06 after the redeploy.
  const old = "9411d0f7125c31e0d392a96d956bcc29c04ee801f0494a12be75ac68f081c85c";
  assert.equal(allowlistStatus(online.registry.events, old).allowed, false);
  assert.equal(allowlistStatus([...online.registry.events].reverse(), old).allowed, false);
});

test("expiry is compared with the clock", () => {
  const at = Date.parse(online.instance.expires_at);
  assert.equal(expiryOf(online.instance, at - 1).expired, false);
  assert.equal(expiryOf(online.instance, at).expired, true);
  assert.equal(expiryOf(null, at), null);
});

test("formatters", () => {
  assert.equal(short("9411d0f7125c31e0d392a96d956bcc29c04ee801f0494a12be75ac68f081c85c"), "9411d0f7…c85c");
  assert.equal(short("INTEL"), "INTEL");
  assert.equal(fmtDateTime("2026-11-12T12:55:50.318Z"), "12 Nov 2026, 12:55:50 UTC");
  assert.equal(fmtHM("2026-11-12T02:05:50.318Z"), "02:05 UTC");
  assert.equal(fmtDateTime("nope"), "");
  assert.equal(fmtSpan(14_900), "14 seconds");
  assert.equal(fmtSpan(1000), "1 second");
  assert.equal(fmtSpan(12 * 60_000), "12 minutes");
  assert.equal(fmtSpan(23.5 * 3600_000), "23 hours");
  assert.deepEqual(platformItems(online.exit.platform), ["Intel TDX", "Phala Cloud", "dstack-0.6.1"]);
  assert.deepEqual(platformItems(null), []);
  assert.equal(txUrl(online.links, "EZDv"), "https://testnet.nearblocks.io/txns/EZDv");
  assert.equal(txUrl(online.links, null), null);
  assert.equal(txUrl({ explorer_tx: "javascript:alert({tx})" }, "x"), null);
  assert.equal(safeUrl("http://example.com"), null);
  assert.equal(accountUrl(online.links, "vpnreg.pe-owner-erhan.testnet"), "https://testnet.nearblocks.io/address/vpnreg.pe-owner-erhan.testnet");
});

test("the status bundle next to the API function is the repo's bundle, unedited", () => {
  const sha = (p) => createHash("sha256").update(readFileSync(new URL(p, here))).digest("hex");
  assert.equal(sha("../api/_lib/provenexit-status.mjs"), sha("../../status/provenexit-status.mjs"));
});

test("the error fixture has the shape the page must survive", () => {
  assert.equal(typeof error.error, "string");
  assert.equal(error.instance, null);
  assert.deepEqual(error.registry.events, []);
  assert.ok(error.verify.checks.every((c) => c.ok === false));
});

test("the build lead claims approval only when the history shows it", () => {
  const hash = online.exit.compose.hash;
  assert.match(approvalSentence(allowlistStatus(online.registry.events, hash)), /approved this exact hash/);
  const revoked = approvalSentence(allowlistStatus(refused.registry.events, hash));
  assert.match(revoked, /revoked this exact hash/);
  assert.doesNotMatch(revoked, /approved/);
  assert.equal(approvalSentence(allowlistStatus([], hash)), "");
  assert.equal(approvalSentence(null), "");
  // The fixed copy makes neither claim; the sentence is set from the data.
  const html = text("../index.html");
  assert.doesNotMatch(html, /approved this exact hash|exit is running/);
  assert.match(html, /id="build-lead"/);
});

test("text that changes every second is not part of a slot that holds a link", () => {
  const app = text("../assets/app.js");
  const body = (name) => app.slice(app.indexOf(`function ${name}(`), app.indexOf("\n}\n", app.indexOf(`function ${name}(`)));
  assert.doesNotMatch(body("underPlate"), /fmtSpan/);
  assert.match(body("underPlate"), /<span id="age"><\/span>/);
  const near = body("renderNear");
  assert.match(near, /<span id="expires-in"><\/span>/);
  assert.match(near, /tick\("expires-in"/);
  assert.equal(near.match(/fmtSpan/g).length, 1);
});

test("the status function answers before the platform's limit", async () => {
  const limit = JSON.parse(text("../vercel.json")).functions["api/status.mjs"].maxDuration * 1000;
  assert.ok(DEADLINE_MS < limit);
  // The bundle's sequence: the parallel phase, then egress, get_instance, two rounds of tx details, two anchor reads.
  const T = { healthz: 5e3, ...TIMEOUTS };
  const parallel = Math.max(T.healthz + 500, T.verify, T.chain + 500, T.events + 500);
  const worst = parallel + (T.egress + 2e3) + T.chain + 2 * (T.chain + 500) + 2 * T.chain;
  assert.ok(worst < limit, `worst case ${worst} ms`);
  assert.match(text("../api/status.mjs"), /withDeadline\(getStatus\(\{ timeouts: TIMEOUTS \}\)\)/);

  const done = { checked_at: "2026-11-12T10:00:00.000Z", error: null };
  assert.equal(await withDeadline(Promise.resolve(done), 50), done);
  const late = await withDeadline(new Promise(() => {}), 20, () => new Date("2026-11-12T10:00:00.000Z"));
  assert.deepEqual(late, { checked_at: "2026-11-12T10:00:00.000Z", error: "status check timed out" });
  assert.equal(deriveState(late, Date.parse(late.checked_at) + 1000), "error");
  await assert.rejects(withDeadline(Promise.reject(new Error("boom")), 50), /boom/);
});

test("motion is scrubbed by scroll, never played on a clock", () => {
  const motion = text("../assets/motion.js");
  // No timers at all in the motion module: every effect is a function of scroll position.
  assert.doesNotMatch(motion, /setTimeout|setInterval|performance\.now|Date\.now/);
  assert.match(motion, /addEventListener\("scroll", queue, \{ passive: true \}\)/);
  assert.match(motion, /requestAnimationFrame\(update\)/);
  assert.match(motion, /getBoundingClientRect/);
  // The one timer is motion-flag.js's safety fallback: it switches motion off if app.js never starts.
  const flag = text("../assets/motion-flag.js");
  assert.equal(flag.match(/setTimeout/g).length, 1);
  assert.match(flag, /setTimeout\(function \(\) \{ if \(!root\.hasAttribute\("data-motion-ready"\)\) root\.classList\.remove\("motion"\); \}, 3000\)/);
  assert.doesNotMatch(flag, /setInterval/);
  // No playback controls and no looping keyframes left over from the timed version.
  const html = text("../index.html");
  assert.doesNotMatch(html, /flow-toggle|route-replay|Play the steps again|>Pause</);
  assert.doesNotMatch(text("../assets/styles.css"), /animation:[^;]*infinite|@keyframes (stream|ring|pop|blink)/);
});

test("the hero check-flow card is gone; the hero keeps headline, buttons and plate", () => {
  const html = text("../index.html");
  assert.doesNotMatch(html, /class="flow|id="flow|How the client decides, before the first byte/);
  assert.match(html, /<h1>/);
  assert.match(html, /class="btn" href="#run"/);
  assert.match(html, /id="plate"/);
  assert.doesNotMatch(text("../assets/styles.css"), /\.flow[-\s{]|\.g-tick/);
  assert.doesNotMatch(text("../assets/motion.js"), /setFlowStop|heroFlow|flow-/);
  assert.doesNotMatch(text("../assets/app.js"), /setFlowStop/);
});

test("the route section is four plain steps, with no pinned scroll scene", () => {
  const html = text("../index.html");
  const route = html.slice(html.indexOf('id="route"'), html.indexOf("</section>", html.indexOf('id="route"')));
  assert.equal(route.match(/<li>/g).length, 4);
  assert.doesNotMatch(route, /route-pin|route-stage|route-count|station/);
  const css = text("../assets/styles.css");
  assert.doesNotMatch(css, /position: sticky|route-pin|\.station/);
  assert.doesNotMatch(text("../assets/motion.js"), /routeSteps|route-pin/);
});

test("build, NEAR and keys share one proof section; the agent command lives under Run it", () => {
  const html = text("../index.html");
  const proof = html.slice(html.indexOf('id="proof"'), html.indexOf("</section>", html.indexOf('id="proof"')));
  for (const id of ["build", "near", "keys"]) assert.match(proof, new RegExp(`class="proof-part" id="${id}"`));
  assert.doesNotMatch(html, /id="agents"|href="#agents"/);
  const app = text("../assets/app.js");
  assert.match(app, /const CMD_MCP = "claude mcp add provenexit -- npx -y -p provenexit provenexit-mcp";/);
  assert.match(app, /const CMD_LIVE = "npx provenexit verify";/);
});

test("the limits heading and the compact history", () => {
  const html = text("../index.html");
  assert.doesNotMatch(html, /More limits/);
  assert.doesNotMatch(html, /Also true/);
  const app = text("../assets/app.js");
  assert.match(app, /const HISTORY_SHOWN = 3;/);
  assert.match(app, /aria-expanded="\$\{historyOpen\}"/);
  assert.match(app, /Show all \$\{events\.length\} changes/);
  assert.match(app, /historyOpen = !historyOpen/);
});

test("long explanations are folded behind disclosures, proof data is not", () => {
  const html = text("../index.html");
  const limits = html.slice(html.indexOf('id="limits"'), html.indexOf("</section>", html.indexOf('id="limits"')));
  // Three limits, each title-first with its explanation in a panel.
  assert.equal(limits.match(/data-more-title/g).length, 3);
  assert.equal(limits.match(/data-more="limit-\d+"/g).length, 3);
  const more = text("../assets/more.js");
  assert.match(more, /aria-expanded/);
  assert.match(more, /aria-controls/);
  assert.match(more, /btn\.type = "button"/);
  // Panels never hold a copy button, a hash or a verdict mark.
  const app = text("../assets/app.js");
  for (const m of app.matchAll(/<p data-more="[^"]+"[^>]*>(.*?)<\/p>/g)) assert.doesNotMatch(m[1], /copy|rawRow|mark\(|data-count/);
  assert.match(app, /enhanceMore\(\);\n  scanMotion\(\);/);
});
