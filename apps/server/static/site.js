// The site's only script (CSP: script-src 'self', no inline code). It never makes
// network requests. Without it every page still works: the theme follows the
// system setting and the copy/theme buttons stay hidden.
// Loaded in <head> without defer so a remembered theme applies before the page
// is drawn (no flash); the buttons are wired once the document is parsed.
(function () {
  // ---- Light/dark theme: the header button switches, the choice is kept in
  // this browser only (localStorage).

  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem("theme"); } catch (e) { saved = null; }
  if (saved === "light" || saved === "dark") { root.setAttribute("data-theme", saved); }

  function current() {
    var set = root.getAttribute("data-theme");
    if (set) { return set; }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  function label(button) {
    button.textContent = current() === "light" ? "深色" : "浅色";
    button.setAttribute("aria-label", current() === "light" ? "切换到深色主题" : "切换到浅色主题");
  }
  function themeButton() {
    var button = document.querySelector("button[data-theme-toggle]");
    if (!button) { return; }
    button.hidden = false;
    label(button);
    button.addEventListener("click", function () {
      var next = current() === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) { /* private mode: not remembered */ }
      label(button);
    });
  }

  // ---- Copy buttons.
  function copyButtons() {
    // A hello for whoever opens the developer tools.
    if (window.console && console.log) {
      console.log("%c lysec %c 打开开发者工具的你，大概也是同道中人。想聊安全或提建议：io@u2ly.com",
        "background:#3fb950;color:#0d1117;font-weight:700;border-radius:3px", "color:inherit");
    }
    function flash(button, text) {
      var label = button.getAttribute("data-label") || button.textContent;
      button.setAttribute("data-label", label);
      button.textContent = text;
      setTimeout(function () { button.textContent = label; }, 1600);
    }
    function fallback(text) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.className = "copy-buffer";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(area);
      return ok;
    }
    var buttons = document.querySelectorAll("button[data-copy]");
    for (var i = 0; i < buttons.length; i++) {
      var button = buttons[i];
      button.hidden = false;
      button.addEventListener("click", function (event) {
        var b = event.currentTarget;
        var text = b.getAttribute("data-copy");
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(text).then(
            function () { flash(b, "已复制"); },
            function () { flash(b, fallback(text) ? "已复制" : "请手动复制"); }
          );
        } else {
          flash(b, fallback(text) ? "已复制" : "请手动复制");
        }
      });
    }
  }

  function ready() { themeButton(); copyButtons(); }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
