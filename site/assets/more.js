// "Show more": longer explanations stay folded until the reader asks for them.
// Markup: any element with data-more="<key>" is a panel. Without JavaScript it simply shows.
// With JavaScript it is hidden and gets a disclosure button (aria-expanded, aria-controls):
//  - if the element just before it has data-more-title (a heading), that heading's text becomes the button;
//  - otherwise a small button is placed before the panel, labelled data-more-label (default "Read more")
//    and data-more-less when open (default "Show less").
// Open panels are remembered by key, so a slot that app.js redraws keeps what the reader opened.
// Proof data (verdicts, counts, hashes and their copy buttons) is never put inside a panel.

const open = new Set();
let changed = () => {};

const label = (panel, isOpen) =>
  isOpen ? panel.dataset.moreLess ?? "Show less" : panel.dataset.moreLabel ?? "Read more";

/** Adds buttons to panels not seen yet. Safe to call after every render. */
export function enhanceMore(root = document) {
  for (const panel of root.querySelectorAll("[data-more]:not([data-more-ready])")) {
    const key = panel.dataset.more;
    panel.dataset.moreReady = "1";
    if (!panel.id) panel.id = `more-${key}`;
    const isOpen = open.has(key);
    panel.hidden = !isOpen;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.dataset.moreFor = key;
    btn.setAttribute("aria-controls", panel.id);
    btn.setAttribute("aria-expanded", String(isOpen));
    const title = panel.previousElementSibling?.matches("[data-more-title]") ? panel.previousElementSibling : null;
    if (title) {
      // The heading itself is the control: its words stay a heading, the button sits inside it.
      btn.className = "more-title";
      btn.append(...title.childNodes);
      title.append(btn);
    } else {
      btn.className = panel.dataset.moreButton === "big" ? "more-btn more-link" : "more-link";
      btn.textContent = label(panel, isOpen);
      panel.before(btn);
    }
  }
}

function toggle(btn) {
  const key = btn.dataset.moreFor;
  const panel = document.getElementById(btn.getAttribute("aria-controls"));
  if (!panel) return;
  const isOpen = panel.hidden;
  panel.hidden = !isOpen;
  if (isOpen) open.add(key);
  else open.delete(key);
  btn.setAttribute("aria-expanded", String(isOpen));
  if (btn.classList.contains("more-link")) btn.textContent = label(panel, isOpen);
  changed();
}

/** Starts listening for clicks; onChange runs after a panel opens or closes (the page height changed). */
export function startMore(onChange) {
  if (onChange) changed = onChange;
  document.addEventListener("click", (ev) => {
    const btn = ev.target instanceof Element ? ev.target.closest("button[data-more-for]") : null;
    if (btn) toggle(btn);
  });
  enhanceMore();
}
