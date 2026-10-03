"use strict";
// Loaded as a small BLOCKING script in <head> (no defer) so the saved theme is applied before first
// paint and the page never flashes the wrong colours. External file: the CSP forbids inline scripts.
// Choices: "system" (follow the OS; no data-theme attribute so CSS media query decides), "light", "dark".
(function () {
  var KEY = "sv-theme";
  var root = document.documentElement;
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function saved() {
    try { var v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : "system"; }
    catch (e) { return "system"; }          // storage blocked: treat as System, never fail
  }
  function effective(choice) { return choice === "system" ? (mq && mq.matches ? "dark" : "light") : choice; }

  function apply(choice) {
    if (choice === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", choice);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", effective(choice) === "dark" ? "#0e1626" : "#f4f6f9");
  }
  function choose(choice) {
    try { if (choice === "system") localStorage.removeItem(KEY); else localStorage.setItem(KEY, choice); } catch (e) {}
    apply(choice); mark(choice);
  }
  function mark(choice) {
    document.querySelectorAll("#theme-toggle button[data-theme-choice]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-theme-choice") === choice));
    });
  }

  apply(saved());                            // before first paint

  document.addEventListener("DOMContentLoaded", function () {
    mark(saved());
    var box = document.getElementById("theme-toggle");
    if (box) box.addEventListener("click", function (e) {
      var b = e.target.closest("button[data-theme-choice]"); if (b) choose(b.getAttribute("data-theme-choice"));
    });
    // Smooth transitions are switched on only AFTER first paint, so loading never animates.
    requestAnimationFrame(function () { requestAnimationFrame(function () { root.classList.add("theme-ready"); }); });
  });
  if (mq) {
    var onChange = function () { if (saved() === "system") apply("system"); };   // live OS change
    if (mq.addEventListener) mq.addEventListener("change", onChange); else if (mq.addListener) mq.addListener(onChange);
  }
})();
