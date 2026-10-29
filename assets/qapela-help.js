/* Qapela Help button — adds a floating "Help" button with a WhatsApp assistant and an email assistant.
   Include on any page with: <script src="assets/qapela-help.js" defer></script> */
(function () {
  var WHATSAPP = "2349039300602";          // +234 903 930 0602
  var WHATSAPP_LABEL = "+234 903 930 0602";
  var EMAIL = "qapela.zrofeet@gmail.com";

  var css = ".qh-btn{position:fixed;right:14px;bottom:88px;z-index:9990;display:flex;align-items:center;gap:7px;background:#0B5CFF;color:#fff;border:none;border-radius:26px;padding:11px 16px;font:700 13px 'Segoe UI',system-ui,sans-serif;box-shadow:0 8px 24px rgba(11,92,255,.45);cursor:pointer}" +
    ".qh-shade{position:fixed;inset:0;background:rgba(8,8,20,.55);z-index:9991}" +
    ".qh-sheet{position:fixed;left:50%;transform:translateX(-50%);bottom:0;width:100%;max-width:440px;background:#fff;color:#1B2559;border-radius:22px 22px 0 0;z-index:9992;padding:18px 18px calc(24px + env(safe-area-inset-bottom,0px));font-family:'Segoe UI',system-ui,sans-serif}" +
    ".qh-sheet .qh-grab{width:44px;height:4px;background:#E6EAF2;border-radius:2px;margin:0 auto 14px}" +
    ".qh-sheet h3{margin:0 0 4px;font-size:18px}.qh-sheet p{margin:0 0 16px;font-size:13px;color:#6B7590;line-height:1.5}" +
    ".qh-opt{display:flex;align-items:center;gap:13px;text-decoration:none;color:#1B2559;border:1px solid #E6EAF2;border-radius:16px;padding:14px;margin-bottom:10px;background:#F8FAFF}" +
    ".qh-ic{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:21px;flex-shrink:0}" +
    ".qh-opt b{display:block;font-size:14.5px}.qh-opt small{display:block;color:#6B7590;font-size:12px;margin-top:2px;word-break:break-all}" +
    ".qh-close{width:100%;border:none;background:none;color:#6B7590;font-weight:700;font-size:13px;padding:10px;cursor:pointer}";
  var style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  var page = (document.title || "Qapela").replace(/^Qapela\s*[—-]\s*/i, "");
  var wa = "https://wa.me/" + WHATSAPP + "?text=" + encodeURIComponent("Hello Qapela, I need help with: " + page);
  var mail = "mailto:" + EMAIL + "?subject=" + encodeURIComponent("Help needed: " + page);

  var btn = document.createElement("button");
  btn.className = "qh-btn";
  btn.type = "button";
  btn.setAttribute("aria-label", "Help");
  btn.textContent = "💬 Help";
  document.body.appendChild(btn);

  var host = null;
  function close() { if (host) { host.remove(); host = null; } }
  function open() {
    close();
    host = document.createElement("div");
    host.innerHTML =
      '<div class="qh-shade"></div><div class="qh-sheet"><div class="qh-grab"></div>' +
      "<h3>How can we help?</h3><p>Pick the way that suits you. Tell us what you were doing and we'll sort it out.</p>" +
      '<a class="qh-opt" href="' + wa + '" target="_blank" rel="noopener noreferrer"><span class="qh-ic" style="background:#DCFCE7">🟢</span><span><b>WhatsApp Assistant</b><small>' + WHATSAPP_LABEL + "</small></span></a>" +
      '<a class="qh-opt" href="' + mail + '"><span class="qh-ic" style="background:#DBEAFE">✉️</span><span><b>Email Assistant</b><small>' + EMAIL + "</small></span></a>" +
      '<button class="qh-close" type="button">Close</button></div>';
    document.body.appendChild(host);
    host.querySelector(".qh-shade").onclick = close;
    host.querySelector(".qh-close").onclick = close;
  }
  btn.onclick = open;
})();
