// Runs before the page paints: turns motion on only when the visitor allows it. If app.js has not
// started within three seconds, motion is switched off again so nothing stays hidden.
(function () {
  var root = document.documentElement;
  if (!window.matchMedia || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  root.classList.add("motion");
  setTimeout(function () { if (!root.hasAttribute("data-motion-ready")) root.classList.remove("motion"); }, 3000);
})();
