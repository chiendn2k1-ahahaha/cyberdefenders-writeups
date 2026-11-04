/* Deterrents only: block copy, context menu, print, save and view-source shortcuts,
   hide content while the window is not focused or when PrintScreen is pressed.
   A determined reader can still bypass these (OS screenshot tools, phone camera, devtools). */
(function () {
  "use strict";
  var doc = document, root = doc.documentElement;

  function editable(t) {
    return t && t.closest && t.closest("input, textarea, [contenteditable='true']");
  }
  function stop(e) {
    if (!editable(e.target)) { e.preventDefault(); e.stopPropagation(); }
  }
  ["copy", "cut", "contextmenu", "selectstart", "dragstart"].forEach(function (ev) {
    doc.addEventListener(ev, stop, true);
  });

  var BLOCK = { c: 1, x: 1, a: 1, s: 1, p: 1, u: 1 };
  doc.addEventListener("keydown", function (e) {
    var k = (e.key || "").toLowerCase();
    if ((e.ctrlKey || e.metaKey) && BLOCK[k] && !(editable(e.target) && "cxa".indexOf(k) >= 0)) {
      e.preventDefault(); e.stopPropagation();
    }
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && "sicjk".indexOf(k) >= 0) {
      e.preventDefault(); e.stopPropagation();
    }
    if (k === "f12" || (e.metaKey && e.altKey && "ijcu".indexOf(k) >= 0)) {
      e.preventDefault(); e.stopPropagation();
    }
    if (k === "printscreen") shieldFor(1500);
    // Win+Shift+S, Win+PrtScn, Win+Alt+PrtScn, Win+G: the Windows key reaches the page first,
    // so hide the content before the snipping overlay freezes the screen.
    if (k === "meta" || k === "os" || e.metaKey) shieldFor(3000);
  }, true);
  doc.addEventListener("keyup", function (e) {
    if ((e.key || "").toLowerCase() === "printscreen") {
      shieldFor(1500);
      try { navigator.clipboard.writeText(""); } catch (_) { /* clipboard may be unavailable */ }
    }
  }, true);

  var timer = null;
  function shield(on) { root.classList.toggle("shield", on); }
  function shieldFor(ms) {
    shield(true); clearTimeout(timer);
    timer = setTimeout(function () { if (doc.hasFocus()) shield(false); }, ms);
  }
  window.addEventListener("blur", function () { shield(true); });
  window.addEventListener("focus", function () { shield(false); });
  doc.addEventListener("visibilitychange", function () { shield(doc.hidden); });
  window.addEventListener("beforeprint", function () { shield(true); });
  window.addEventListener("afterprint", function () { shield(!doc.hasFocus()); });

  // Content is hidden by an inline rule until this script marks the page (class "pv").
  // Blocking this file, disabling JavaScript or loading the page offline without it keeps the page blank.
  root.classList.add("pv");

  // DevTools docked to the window shrinks the viewport: hide content while it is open.
  // Watchdog: if the copy-protection CSS or the page marker is removed, hide content too.
  function tampered() {
    var b = doc.body;
    if (!b) return false;
    var us = getComputedStyle(b).userSelect || getComputedStyle(b).webkitUserSelect;
    var css = doc.querySelector('link[rel="stylesheet"][href*="style.css"]');
    return !css || us !== "none" || !root.classList.contains("pv");
  }
  // Baseline taken at load and re-taken whenever the zoom level (devicePixelRatio) changes,
  // so browser zoom or window resizing does not look like DevTools.
  var base = null;
  function snap() {
    base = { dpr: window.devicePixelRatio, kw: window.outerWidth / Math.max(1, window.innerWidth),
             dh: window.outerHeight - window.innerHeight * (window.outerWidth / Math.max(1, window.innerWidth)) };
  }
  function devtoolsOpen() {
    if (!window.outerWidth) return false;
    if (!base || base.dpr !== window.devicePixelRatio) { snap(); return false; }
    var dw = window.outerWidth - window.innerWidth * base.kw;
    var dh = (window.outerHeight - window.innerHeight * base.kw) - base.dh;
    return dw > 160 || dh > 160;
  }
  setInterval(function () {
    root.classList.toggle("dt", tampered() || devtoolsOpen());
  }, 800);
})();
