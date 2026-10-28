// Applies the saved theme before first paint (external file: the CSP forbids inline scripts).
(function () {
  try {
    var pref = localStorage.getItem("memtrace.theme") || "system";
    var dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }
})();
