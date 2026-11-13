// Motion for the page, scrubbed by scroll position: section reveals, the pinned route story and the
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

// ---- the route: a pinned story, four beats played by the scroll ------------------------------
// The section's .story is a tall driver and its stage is position: sticky (styles.css), so the page
// seems to stop while the scroll plays the map: a fresh number goes to the exit and its Intel quote
// comes back, the client's checks fill in, it asks the NEAR registry, then the tunnel opens through
// the exit to the website. Every frame is computed from the scroll position alone, so scrolling back
// plays it backwards. Live only when the stage has room (else, and under reduced motion, the static
// map with the four step cards stays).
function routeStory() {
  const sec = document.getElementById("route");
  const story = document.getElementById("story");
  const stage = document.getElementById("story-stage");
  if (!sec || !story || !stage) return;
  const $ = (id) => document.getElementById(id);
  const seg = (t, a, b) => clamp((t - a) / (b - a));
  const ease = (t) => t * t * (3 - 2 * t);
  const at = (path, f) => { const L = path.getTotalLength(); return path.getPointAtLength(L * clamp(f)); };
  const place = (el, path, f, show) => {
    el.style.opacity = show ? "1" : "0";
    if (!show) return;
    const p = at(path, f);
    el.setAttribute("transform", `translate(${p.x.toFixed(1)} ${p.y.toFixed(1)})`);
  };
  // Two drawings of the same map (wide, and tall for phones); both are driven, CSS shows one.
  const maps = [...stage.querySelectorAll(".story-map")].map((svg) => {
    const q = (k) => svg.querySelector(".k-" + k);
    const tunnel = q("tunnel");
    const twin = document.createElementNS("http://www.w3.org/2000/svg", "path");
    twin.setAttribute("d", tunnel.getAttribute("d")); // without pathLength, for positions
    return {
      svg, ask: q("ask"), read: q("read"), tunnel, twin, readLit: q("read-lit"), nonce: q("nonce"), quote: q("quote"),
      ping: q("ping"), pkts: [...q("flow").children], exit: q("exit"), registry: q("registry"), site: q("site"),
      regSub: q("reg-sub"), checks: [...svg.querySelectorAll(".chk")],
    };
  });
  const chip = $("story-chip");
  const bars = [...stage.querySelectorAll(".story-bars span")];
  const steps = [...$("route-steps").children];

  const fits = () => innerHeight >= 560 && innerWidth >= 340;
  let live = false;
  const setLive = (v) => { live = v; sec.classList.toggle("story-live", v); };
  setLive(fits());
  let text = "";
  const say = (s, ok) => { if (s !== text) { chip.textContent = text = s; } chip.toggleAttribute("data-ok", !!ok); };

  parts.push(() => {
    if (fits() !== live) setLive(fits());
    if (!live) return;
    const r = story.getBoundingClientRect();
    const room = r.height - stage.clientHeight;
    const top = parseFloat(getComputedStyle(stage).top) || 0;
    const p = room > 0 ? clamp((top - r.top) / room) : 1;
    const u = clamp(p / 0.94) * 4; // the last stretch holds the open tunnel before the page moves on
    const k = Math.min(3, Math.floor(u));
    const t = u - k;
    const in_ = (b) => (k > b ? 1 : k < b ? 0 : t);

    const b0 = in_(0), b1 = in_(1), b2 = in_(2), b3 = in_(3);
    // checks: sixteen on the quote (beat 2), three on the registry (beat 3), the last as the tunnel opens
    const n = Math.round(16 * ease(seg(b1, 0.05, 0.9))) + Math.round(3 * seg(b2, 0.46, 0.9)) + (b3 >= 0.06 ? 1 : 0);
    for (const s of maps) {
      if (s.svg.getBoundingClientRect().width === 0) continue; // the hidden drawing
      // beat 1: the number goes out, the quote comes back
      place(s.nonce, s.ask, ease(seg(b0, 0.06, 0.46)), k === 0 && b0 > 0.04 && b0 < 0.5);
      place(s.quote, s.ask, 1 - ease(seg(b0, 0.54, 0.94)), k === 0 && b0 >= 0.5 && b0 < 0.98);
      // beat 2: the exit turns green once Intel's signature and the quote checks hold
      s.exit.classList.toggle("ok", b1 >= 0.9);
      // beat 3: the read goes up to the registry and the answer lights it
      s.readLit.style.setProperty("--off", (1 - ease(seg(b2, 0.04, 0.42))).toFixed(3));
      place(s.ping, s.read, ease(seg(b2, 0.04, 0.42)), k === 2 && b2 < 0.44);
      s.registry.classList.toggle("lit", b2 >= 0.44);
      const sub = b2 >= 0.44 ? "allowed and registered" : "is this build allowed?";
      if (s.regSub.textContent !== sub) s.regSub.textContent = sub;
      // beat 4: the tunnel draws through the exit to the website and traffic flows along it
      s.tunnel.style.setProperty("--off", (1 - ease(seg(b3, 0.08, 0.62))).toFixed(3));
      s.site.classList.toggle("lit", b3 >= 0.62);
      s.pkts.forEach((c, i) => place(c, s.twin, (u * 1.6 + i / s.pkts.length) % 1, b3 > 0.64));
      s.checks.forEach((c, i) => c.classList.toggle("on", i < n));
    }

    if (k === 0) say("Asking the exit for proof");
    else if (k === 3 && b3 >= 0.62) say("20 of 20, tunnel open", true);
    else say(`Checks: ${n} of 20`);
    bars.forEach((s, i) => s.style.setProperty("--f", (i < k ? 1 : i === k ? t : 0).toFixed(3)));
    steps.forEach((li, i) => li.classList.toggle("on", i === k));
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
  routeStory();
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
    document.getElementById("route")?.classList.remove("story-live");
    document.getElementById("history-body")?.removeAttribute("data-anim");
    for (const el of document.querySelectorAll("#route .lit, #route .on, #route .ok")) el.classList.remove("lit", "on", "ok");
  });
}

/** Called after every render: measures what was just drawn, before it paints. */
export function scanMotion() {
  if (on()) update();
}
