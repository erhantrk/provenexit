// Motion for the page, scrubbed by scroll position: section reveals and the
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
    for (const el of document.querySelectorAll("[style*='--p'], [style*='--draw']")) {
      el.style.removeProperty("--p");
      el.style.removeProperty("--draw");
      el.style.removeProperty("transform");
    }
    document.getElementById("history-body")?.removeAttribute("data-anim");
  });
}

/** Called after every render: measures what was just drawn, before it paints. */
export function scanMotion() {
  if (on()) update();
}
