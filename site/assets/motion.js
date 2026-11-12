// Motion for the page: section reveals, count-ups, the hero flow, the route steps and the history line.
// Every movement is transform or opacity, driven by requestAnimationFrame, so nothing shifts the layout.
// With prefers-reduced-motion none of it runs: motion-flag.js leaves the
// "motion" class off and every element keeps its final, static state.

const root = document.documentElement;
const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const on = () => root.classList.contains("motion") && !reduced.matches;
const outCubic = (t) => 1 - (1 - t) ** 3;
const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2);

/** The next frame, or 34 ms, whichever comes first (frames can stall in background or headless tabs). */
function frame(cb) {
  let fired = false;
  const go = () => { if (!fired) { fired = true; cb(performance.now()); } };
  requestAnimationFrame(go);
  setTimeout(go, 34);
}

/** Calls fn(progress 0..1) on each frame for ms milliseconds, then done(). */
function tween(ms, fn, done, ease = outCubic) {
  const t0 = performance.now();
  const step = (t) => {
    const p = Math.min(1, Math.max(0, (t - t0) / ms));
    fn(ease(p));
    if (p < 1) frame(step);
    else done?.();
  };
  frame(step);
}

// In-view checks run on scroll and resize (at most every 50 ms), not through IntersectionObserver, so they
// behave the same in every browser and in headless captures.
const waiting = new Set(); // { el, fn, ratio }
const inView = (el, ratio = 0.15) => {
  const r = el.getBoundingClientRect();
  if (r.width === 0 && r.height === 0) return false;
  const h = innerHeight;
  const seen = Math.min(r.bottom, h * 0.94) - Math.max(r.top, 0);
  return seen > 0 && seen >= Math.min(r.height, h) * ratio;
};
let queued = false;
function check() {
  queued = false;
  for (const w of [...waiting]) {
    if (inView(w.el, w.ratio)) { waiting.delete(w); w.fn(); }
  }
  for (const f of watchers) f();
}
function queue() {
  if (!queued) { queued = true; setTimeout(check, 50); }
}
const watchers = new Set();
addEventListener("scroll", queue, { passive: true });
addEventListener("resize", queue);

/** Calls fn once, the first time el is in view. */
function once(el, fn, ratio = 0.15) {
  waiting.add({ el, fn, ratio });
  queue();
}

// ---- reveals ----------------------------------------------------------------------------------
function rise(el, delay = 0) {
  el.style.opacity = "0";
  el.style.transform = "translateY(18px)";
  el.classList.add("in");
  setTimeout(() => tween(650, (p) => {
    el.style.opacity = String(p);
    el.style.transform = `translateY(${(1 - p) * 18}px)`;
  }, () => { el.style.removeProperty("opacity"); el.style.removeProperty("transform"); }), delay);
}

function reveal(el) {
  if (el.classList.contains("stagger")) {
    el.classList.add("in");
    [...el.querySelectorAll(":scope > :not(.cards):not(.rows), :scope > .cards > *, :scope > .rows > *")]
      .filter((k) => k.offsetParent !== null)
      .slice(0, 12)
      .forEach((k, i) => rise(k, i * 70));
  } else {
    rise(el);
  }
}

// ---- count-ups --------------------------------------------------------------------------------
const counted = new Set();
const watched = new WeakSet();
function countUp(el) {
  const key = el.dataset.countKey ?? el.textContent;
  if (counted.has(key)) return;
  counted.add(key);
  const final = el.textContent;
  const target = Number(el.dataset.count);
  if (!Number.isFinite(target)) return;
  const decimals = (el.dataset.count.split(".")[1] ?? "").length;
  const suffix = el.dataset.countSuffix ?? "";
  // Hold the final width so the digits can change without moving anything around them.
  el.style.minWidth = `${el.getBoundingClientRect().width}px`;
  el.classList.add("counting");
  tween(1100, (p) => { el.textContent = (target * p).toFixed(decimals) + suffix; }, () => {
    el.textContent = final;
    el.classList.remove("counting");
    el.style.removeProperty("min-width");
  });
}

// ---- hero flow: a packet passes three checks, then the tunnel opens ---------------------------
// An illustration of the order of the checks. When the current response is a refusal, app.js calls
// setFlowStop(gate) and the packet stops at that gate instead, so the picture never contradicts the plate.
const FLOW_SAY = [
  "Your client asks the exit for a fresh Intel quote.",
  "Check 1: Intel's signature on the quote, debug off.",
  "Check 2: the exact approved image, logging off.",
  "Check 3: the NEAR registry must still allow this build.",
  "Only when all three pass does the encrypted tunnel open.",
];
const FLOW_STATIC = "The client checks the exit's Intel quote, the image it runs and the NEAR registry. Only then does it open the tunnel.";
const FLOW_STOPPED = "A check fails here, so the client stops and sends nothing.";
const STOPS = [0.1, 0.3, 0.5, 0.7, 0.9];
const flow = { stop: null, apply: null };

/** null: the full illustration. 1, 2 or 3: the gate where the current refusal stops the client. */
export function setFlowStop(gate) {
  const g = gate === 1 || gate === 2 || gate === 3 ? gate : null;
  if (g === flow.stop) return;
  flow.stop = g;
  flow.apply?.(true);
}

function heroFlow(animated) {
  const fig = document.getElementById("flow");
  if (!fig) return;
  const packet = fig.querySelector(".flow-packet");
  const fill = fig.querySelector(".flow-fill");
  const say = document.getElementById("flow-say");
  const track = fig.querySelector(".flow-track");
  const gates = [...fig.querySelectorAll(".flow-gate")];
  const end = fig.querySelector(".flow-end-b");
  fig.dataset.js = "1";
  let at = 0;
  let timer = 0;
  let visible = false;
  let running = false;
  let gen = 0;

  const last = () => flow.stop ?? 4;
  const place = (x) => {
    packet.style.transform = `translateX(${x * track.clientWidth}px)`;
    fill.style.transform = `scaleX(${(x - 0.1) / 0.8})`;
  };
  const show = (step) => {
    gates.forEach((g, i) => {
      const n = i + 1;
      g.classList.toggle("pass", n <= step && n !== flow.stop);
      g.classList.toggle("blocked", n === flow.stop && step >= n);
    });
    end.classList.toggle("open", step === 4);
    fig.classList.toggle("tunnel", step === 4);
    say.textContent = flow.stop !== null && step === flow.stop ? FLOW_STOPPED : animated ? FLOW_SAY[step] : FLOW_STATIC;
  };
  const still = () => {
    // Reduced motion: the end state, drawn once.
    at = last();
    place(STOPS[at]);
    show(at);
    if (flow.stop === null) say.textContent = FLOW_STATIC;
  };
  if (!animated) {
    flow.apply = still;
    still();
    return;
  }

  // Two plays, then it rests in the end state (WCAG 2.2.2). The button pauses it at any time and
  // plays it again from the start.
  const PLAYS = 2;
  const HOLD = 1400;
  const btn = document.getElementById("flow-toggle");
  let plays = 0;
  let resting = false;
  const label = () => { if (btn) btn.textContent = resting ? "Play again" : "Pause"; };
  const rest = () => {
    clearTimeout(timer);
    gen += 1;
    resting = true;
    running = false;
    delete fig.dataset.reset;
    fig.classList.add("rest");
    still();
    label();
  };
  const next = (g) => {
    if (g !== gen) return;
    if (!visible || document.visibilityState !== "visible") { running = false; return; }
    running = true;
    if (at >= last()) {
      plays += 1;
      if (plays >= PLAYS) { timer = setTimeout(() => { if (g === gen) rest(); }, 1800); return; }
      timer = setTimeout(() => {
        fig.dataset.reset = "1";
        at = 0;
        place(STOPS[0]);
        show(0);
        timer = setTimeout(() => { delete fig.dataset.reset; next(g); }, 900);
      }, flow.stop === null ? 3200 : 3600);
      return;
    }
    const from = STOPS[at];
    at += 1;
    const ms = at === 4 ? 900 : 650;
    tween(ms, (p) => place(from + (STOPS[at] - from) * p), null, inOut);
    timer = setTimeout(() => { show(at); timer = setTimeout(() => next(g), at === 4 ? 0 : HOLD); }, ms);
  };
  const restart = () => {
    clearTimeout(timer);
    gen += 1;
    plays = 0;
    resting = false;
    fig.classList.remove("rest");
    label();
    delete fig.dataset.reset;
    at = 0;
    place(STOPS[0]);
    show(0);
    running = visible;
    if (visible) { const g = gen; timer = setTimeout(() => next(g), 500); }
  };
  // A new verdict while resting redraws the end state; while playing it starts over.
  flow.apply = () => (resting ? rest() : restart());
  fig.dataset.anim = "1";
  label();
  btn?.addEventListener("click", () => (resting ? restart() : rest()));
  place(STOPS[0]);
  show(0);
  watchers.add(() => {
    visible = inView(fig, 0.3);
    if (visible && !running && !resting) { running = true; const g = gen; clearTimeout(timer); timer = setTimeout(() => next(g), 500); }
  });
  queue();
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && visible && !running && !resting) { running = true; next(gen); }
  });
  addEventListener("resize", () => place(STOPS[at]));
}

// ---- the route: four steps, one after another --------------------------------------------------
function routeSteps() {
  const fig = document.getElementById("route-fig");
  const list = document.getElementById("route-steps");
  const again = document.getElementById("route-replay");
  if (!fig || !list) return;
  const line = fig.querySelector(".route-line i");
  const drop = fig.querySelector(".route-drop");
  const items = [...list.children];
  let lineAt = 0;
  let playing = false;

  const lineTo = (to, ms) => {
    const from = lineAt;
    lineAt = to;
    tween(ms, (p) => { line.style.transform = `scaleX(${from + (to - from) * p})`; });
  };
  const show = (n) => {
    fig.dataset.step = String(n);
    items.forEach((li, i) => {
      li.classList.toggle("on", i < n);
      li.classList.toggle("now", i === n - 1);
    });
  };
  const play = () => {
    if (playing) return;
    playing = true;
    again.hidden = true;
    lineAt = 0;
    line.style.transform = "scaleX(0)";
    drop.style.transform = "scaleY(0)";
    show(0);
    const at = [300, 1500, 2700, 3900];
    setTimeout(() => { show(1); lineTo(0.5, 900); }, at[0]);
    setTimeout(() => show(2), at[1]);
    setTimeout(() => { show(3); tween(700, (p) => { drop.style.transform = `scaleY(${p})`; }); }, at[2]);
    setTimeout(() => { show(4); lineTo(1, 900); }, at[3]);
    setTimeout(() => {
      playing = false;
      items.forEach((li) => li.classList.remove("now"));
      again.hidden = false;
    }, at[3] + 1300);
  };

  fig.dataset.anim = "1";
  list.dataset.anim = "1";
  line.style.transform = "scaleX(0)";
  drop.style.transform = "scaleY(0)";
  show(0);
  once(fig, play, 0.6);
  again.addEventListener("click", play);
}

// ---- history: the timeline draws down, the rows follow ----------------------------------------
function historyDraw() {
  const sec = document.getElementById("history-body");
  if (!sec) return;
  sec.dataset.anim = "1";
  once(sec, () => {
    sec.dataset.drawn = "1";
    const list = sec.querySelector(".events");
    if (!list) return;
    tween(1200, (p) => list.style.setProperty("--draw", String(p)), () => list.style.removeProperty("--draw"));
    [...list.children].forEach((li, i) => rise(li, 120 + i * 90));
  }, 0.15);
}

// ---- public -----------------------------------------------------------------------------------
/** Called once at start. */
export function startMotion() {
  root.dataset.motionReady = "1";
  if (!on()) {
    root.classList.remove("motion");
    heroFlow(false);
    return;
  }
  // The headline rises line by line from behind its mask, then the lead and the buttons follow.
  document.querySelectorAll(".h1-line > span").forEach((el, i) => {
    el.style.transform = "translateY(105%)";
    el.classList.add("in");
    setTimeout(() => tween(700, (p) => { el.style.transform = `translateY(${(1 - p) * 105}%)`; }, () => el.style.removeProperty("transform")), i * 80);
  });
  document.querySelectorAll(".rise").forEach((el, i) => rise(el, 320 + i * 80));
  for (const el of document.querySelectorAll(".reveal, .stagger")) once(el, () => reveal(el));
  heroFlow(true);
  routeSteps();
  historyDraw();
  reduced.addEventListener?.("change", () => { if (reduced.matches) root.classList.remove("motion"); });
}

/** Called after every render: picks up numbers that were just drawn. */
export function scanMotion() {
  if (!on()) return;
  for (const el of document.querySelectorAll("[data-count]")) {
    if (watched.has(el)) continue;
    watched.add(el);
    const key = el.dataset.countKey ?? el.textContent;
    if (counted.has(key)) continue;
    once(el, () => countUp(el), 0.9);
  }
}
