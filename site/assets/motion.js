// Motion for the page, scrubbed by scroll position: section reveals, the hero flow, the route steps and
// the history line. Nothing plays on a clock. One requestAnimationFrame-throttled scroll/resize handler
// measures each element (getBoundingClientRect), turns its scroll position into a progress 0..1 and
// writes it as a CSS custom property (--p, --draw) or a class; CSS turns that into transform and
// opacity, so nothing shifts the layout. Scrolling back reverses every effect.
// With prefers-reduced-motion none of it runs: motion-flag.js leaves the "motion" class off and every
// element keeps its final, static state.

const root = document.documentElement;
const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const on = () => root.classList.contains("motion") && !reduced.matches;
const clamp = (x) => (x < 0 ? 0 : x > 1 ? 1 : x);

/**
 * Scroll progress 0..1 between two moments: when the point at fraction `fromAt` of `from` meets the
 * viewport line `fromVp` (0 top, 1 bottom), and when the point `toAt` of `to` meets the line `toVp`.
 * Both moments are clamped to the scroll range, so an effect at the end of the page still completes.
 * With startAtTop the first moment is never before the top of the page: at load it reads 0.
 */
function progress(from, fromAt, fromVp, to, toAt, toVp, startAtTop = false) {
  const a = from.getBoundingClientRect();
  const b = to === from ? a : to.getBoundingClientRect();
  if (a.height === 0 && a.width === 0) return 1;
  const y = scrollY;
  const vh = innerHeight;
  const max = Math.max(0, root.scrollHeight - vh);
  let s0 = a.top + y + a.height * fromAt - vh * fromVp;
  let s1 = b.top + y + b.height * toAt - vh * toVp;
  s1 = Math.min(s1, max);
  if (startAtTop) s0 = Math.max(0, s0);
  s0 = Math.min(s0, s1);
  if (s1 - s0 < 24) return y >= s1 ? 1 : 0; // no scroll room: the end state
  return clamp((y - s0) / (s1 - s0));
}

const parts = []; // functions that read positions and write progress
let queued = false;
function update() {
  queued = false;
  for (const f of parts) f();
}
function queue() {
  if (!queued) { queued = true; requestAnimationFrame(update); }
}

// ---- reveals ----------------------------------------------------------------------------------
// Each revealed element fades and rises as its top moves from the bottom edge to 85% of the viewport.
function revealTargets() {
  const out = [];
  for (const el of document.querySelectorAll(".reveal")) out.push(el);
  for (const el of document.querySelectorAll(".stagger")) {
    out.push(...el.querySelectorAll(":scope > :not(.cards):not(.rows), :scope > .cards > *, :scope > .rows > *"));
  }
  return out;
}
function reveals() {
  for (const el of revealTargets()) {
    if (el.offsetParent === null) continue;
    el.style.setProperty("--p", progress(el, 0, 1, el, 0, 0.85).toFixed(3));
  }
}

// ---- hero flow: a packet passes three checks, then the tunnel opens ---------------------------
// An illustration of the order of the checks, drawn by how far the flow card has scrolled. When the
// current response is a refusal, app.js calls setFlowStop(gate) and the packet stops at that gate,
// so the picture never contradicts the plate.
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
  flow.apply?.();
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

  /** x: the packet's place along the track, 0.1 (your machine) to 0.9 (the exit). */
  const draw = (x, scrubbed) => {
    const last = STOPS[flow.stop ?? 4];
    x = Math.min(x, last);
    const step = STOPS.filter((s) => x >= s - 0.001).length - 1; // gates passed, 4 = tunnel open
    fig.style.setProperty("--p", ((x - 0.1) / 0.8).toFixed(3));
    packet.style.transform = `translateX(${x * track.clientWidth}px)`;
    fill.style.transform = `scaleX(${(x - 0.1) / 0.8})`;
    gates.forEach((g, i) => {
      const n = i + 1;
      g.classList.toggle("pass", n <= step && n !== flow.stop);
      g.classList.toggle("blocked", n === flow.stop && step >= n);
    });
    end.classList.toggle("open", step === 4);
    fig.classList.toggle("tunnel", step === 4);
    const text = flow.stop !== null && step === flow.stop ? FLOW_STOPPED : scrubbed ? FLOW_SAY[step] : FLOW_STATIC;
    if (say.textContent !== text) say.textContent = text;
  };

  if (!animated) {
    // Reduced motion: the end state, drawn once (and again when the verdict changes).
    flow.apply = () => draw(0.9, false);
    flow.apply();
    return;
  }
  // From the moment the card's middle is near the bottom of the viewport until it is a little above
  // the middle. At load that reads 0; with no scroll room it reads 1 (the end state).
  const scrub = () => draw(0.1 + 0.8 * progress(fig, 0.5, 0.95, fig, 0.5, 0.4, true), true);
  flow.apply = scrub;
  fig.dataset.anim = "1";
  parts.push(scrub);
}

// ---- the route: four steps, one after another --------------------------------------------------
function routeSteps() {
  const fig = document.getElementById("route-fig");
  const list = document.getElementById("route-steps");
  if (!fig || !list) return;
  const line = fig.querySelector(".route-line i");
  const drop = fig.querySelector(".route-drop");
  const items = [...list.children];
  // Where each step lights, as a fraction of the section's scroll progress.
  const AT = [0.08, 0.32, 0.56, 0.8];
  const seg = (p, a, b) => clamp((p - a) / (b - a));

  fig.dataset.anim = "1";
  list.dataset.anim = "1";
  parts.push(() => {
    // From the diagram's top at 85% of the viewport until the step cards' bottom is at 85%.
    const p = progress(fig, 0, 0.85, list, 1, 0.85);
    const n = AT.filter((a) => p >= a).length;
    fig.dataset.step = String(n);
    // Step 1 draws the line to the exit, step 3 drops the registry read, step 4 draws on to the website.
    line.style.transform = `scaleX(${(seg(p, AT[0], AT[1]) * 0.5 + seg(p, AT[3], 1) * 0.5).toFixed(3)})`;
    drop.style.transform = `scaleY(${seg(p, AT[2], AT[3]).toFixed(3)})`;
    items.forEach((li, i) => {
      li.style.setProperty("--p", seg(p, AT[i] - 0.1, AT[i]).toFixed(3));
      li.classList.toggle("on", i < n);
      li.classList.toggle("now", i === n - 1 && p < 1);
    });
  });
}

// ---- history: the timeline draws down, rows appear as the line reaches them --------------------
function historyDraw() {
  const sec = document.getElementById("history-body");
  if (!sec) return;
  sec.dataset.anim = "1";
  parts.push(() => {
    const list = sec.querySelector(".events");
    if (!list) return;
    // The tip of the line follows a line at 90% of the viewport.
    const draw = progress(list, 0, 0.9, list, 1, 0.9);
    list.style.setProperty("--draw", draw.toFixed(3));
    const tip = draw * list.clientHeight;
    for (const li of list.children) {
      li.style.setProperty("--p", clamp((tip - li.offsetTop) / Math.max(1, li.offsetHeight * 0.6)).toFixed(3));
    }
  });
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
  parts.push(reveals);
  heroFlow(true);
  routeSteps();
  historyDraw();
  addEventListener("scroll", queue, { passive: true });
  addEventListener("resize", queue);
  update();
  reduced.addEventListener?.("change", () => {
    if (!reduced.matches) return;
    // Switched to reduced motion: drop the scroll effects and show every final state.
    root.classList.remove("motion");
    removeEventListener("scroll", queue);
    removeEventListener("resize", queue);
    parts.length = 0;
    for (const el of document.querySelectorAll("[style*='--p'], [style*='--draw'], .flow-packet, .flow-fill, .route-line i, .route-drop")) {
      el.style.removeProperty("--p");
      el.style.removeProperty("--draw");
      el.style.removeProperty("transform");
    }
    document.getElementById("flow")?.removeAttribute("data-anim");
    document.getElementById("route-fig")?.removeAttribute("data-anim");
    document.getElementById("route-steps")?.removeAttribute("data-anim");
    document.getElementById("history-body")?.removeAttribute("data-anim");
    heroFlow(false);
  });
}

/** Called after every render: measures what was just drawn, before it paints. */
export function scanMotion() {
  if (on()) update();
}
