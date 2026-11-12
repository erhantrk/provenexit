// Motion for the page, scrubbed by scroll position: section reveals, the pinned route scene and the
// history line. Nothing plays on a clock. One requestAnimationFrame-throttled scroll/resize handler
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

// ---- the route: a pinned scene, four steps one after another ----------------------------------
// The section is a tall track and its stage is position: sticky (styles.css), so the page seems to
// stop while scrolling plays the steps. p is how far the track has scrolled past the stage, 0..1.
// When the stage does not fit the viewport, the section gets data-nopin and the same steps are
// scrubbed by the plain scroll position instead.
function routeSteps() {
  const sec = document.getElementById("route");
  const pin = document.getElementById("route-pin");
  const fig = document.getElementById("route-fig");
  const list = document.getElementById("route-steps");
  if (!sec || !pin || !fig || !list) return;
  const stage = pin.querySelector(".route-stage");
  const wrap = stage.querySelector(".wrap");
  const line = fig.querySelector(".route-line i");
  const drop = fig.querySelector(".route-drop");
  const [machine, exit, site] = fig.querySelectorAll(".station");
  const registry = fig.querySelector(".route-registry");
  const items = [...list.children];
  const count = document.getElementById("route-count");
  const num = document.getElementById("route-n");
  const seg = (p, a, b) => clamp((p - a) / (b - a));

  // Pin only when the stage's content fits in it.
  let width = -1;
  const fit = () => {
    // Recheck on a new width, or when content drawn later (live data) outgrows the pinned stage.
    if (innerWidth === width && (sec.dataset.nopin || wrap.offsetHeight <= stage.clientHeight)) return;
    width = innerWidth;
    sec.removeAttribute("data-nopin");
    if (wrap.offsetHeight > stage.clientHeight) sec.dataset.nopin = "1";
  };

  fig.dataset.anim = "1";
  list.dataset.anim = "1";
  parts.push(() => {
    fit();
    let p;
    if (sec.dataset.nopin) {
      // From the diagram's top at 85% of the viewport until the step cards' bottom is at 85%.
      p = progress(fig, 0, 0.85, list, 1, 0.85);
    } else {
      const r = pin.getBoundingClientRect();
      const room = r.height - stage.clientHeight;
      p = room > 0 ? clamp((stage.getBoundingClientRect().top - r.top) / room) : 1;
    }
    const q = clamp(p / 0.92); // the last stretch holds the finished picture before the page moves on
    const n = Math.min(4, Math.floor(q * 4) + 1);
    // Step 1 draws the line to the exit, step 2 lights the exit, step 3 draws the read up to the
    // registry and lights it, step 4 draws on to the website.
    line.style.transform = `scaleX(${(seg(q, 0.02, 0.2) * 0.5 + seg(q, 0.76, 0.96) * 0.5).toFixed(3)})`;
    drop.style.transform = `scaleY(${seg(q, 0.52, 0.7).toFixed(3)})`;
    machine.classList.add("lit");
    exit.classList.toggle("lit", q >= 0.25);
    registry.classList.toggle("lit", q >= 0.7);
    site.classList.toggle("lit", q >= 0.96);
    fig.dataset.step = String(n);
    items.forEach((li, i) => {
      li.classList.toggle("done", i < n - 1);
      li.classList.toggle("now", i === n - 1);
    });
    count.style.setProperty("--p", q.toFixed(3));
    if (num.textContent !== String(n)) num.textContent = String(n);
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
    return;
  }
  parts.push(reveals);
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
    for (const el of document.querySelectorAll("[style*='--p'], [style*='--draw'], .route-line i, .route-drop")) {
      el.style.removeProperty("--p");
      el.style.removeProperty("--draw");
      el.style.removeProperty("transform");
    }
    document.getElementById("route-fig")?.removeAttribute("data-anim");
    document.getElementById("route-steps")?.removeAttribute("data-anim");
    document.getElementById("history-body")?.removeAttribute("data-anim");
    for (const el of document.querySelectorAll("#route .lit, #route-steps .done, #route-steps .now")) el.classList.remove("lit", "done", "now");
  });
}

/** Called after every render: measures what was just drawn, before it paints. */
export function scanMotion() {
  if (on()) update();
}
