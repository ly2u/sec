// Copy buttons. The page works without this file: buttons stay hidden until it runs.
(function () {
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
})();
