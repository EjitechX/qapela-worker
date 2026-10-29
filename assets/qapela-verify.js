/* Qapela email-verification helper. Include on app pages with <script src="assets/qapela-verify.js" defer></script>.
   - shows a slim banner while the signed-in user's email isn't verified (with a Resend link)
   - exposes window.qapelaPopup(title, message) — a simple popup used for "we'll send it tomorrow" notices */
(function () {
  var API = "https://capella-api-5c6c.drthankgod08.workers.dev";

  window.qapelaPopup = function (title, message) {
    var old = document.getElementById("qv-pop"); if (old) old.remove();
    var host = document.createElement("div");
    host.id = "qv-pop";
    host.style.cssText = "position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(8,8,20,.6);font-family:'Segoe UI',system-ui,sans-serif;";
    host.innerHTML = '<div style="background:#fff;color:#1B2559;border-radius:20px;max-width:360px;width:100%;padding:24px 22px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.4)">' +
      '<div style="font-size:38px;margin-bottom:6px">🕐</div><h3 style="margin:0 0 8px;font-size:18px"></h3><p style="margin:0 0 18px;font-size:13.5px;line-height:1.6;color:#6B7590"></p>' +
      '<button style="background:#0B5CFF;color:#fff;border:none;border-radius:12px;padding:12px 28px;font-weight:700;font-size:14px;cursor:pointer">OK, got it</button></div>';
    host.querySelector("h3").textContent = title;
    host.querySelector("p").textContent = message;
    host.querySelector("button").onclick = function () { host.remove(); };
    document.body.appendChild(host);
  };

  async function api(path, opts) {
    var res = await fetch(API + path, Object.assign({}, opts, { headers: { "Content-Type": "application/json", Authorization: "Bearer " + localStorage.getItem("qapela_token") } }));
    var renewed = res.headers.get("X-Renewed-Token"); if (renewed) localStorage.setItem("qapela_token", renewed);
    var data = await res.json().catch(function () { return {}; });
    return { ok: res.ok, data: data };
  }

  async function init() {
    if (!localStorage.getItem("qapela_token")) return;
    var me = await api("/auth/me");
    if (!me.ok || me.data.emailVerified) return;
    var bar = document.createElement("div");
    bar.id = "qv-bar";
    bar.style.cssText = "background:#FEF3C7;color:#92400E;font:600 12.5px/1.45 'Segoe UI',system-ui,sans-serif;padding:9px 14px;text-align:center;";
    var email = me.data.email;
    if (!email) {
      bar.innerHTML = 'Add an email address to enable withdrawals. <a href="qapela-account.html" style="color:#92400E;text-decoration:underline">Account settings</a>';
    } else if (me.data.verificationEmail === "queued") {
      bar.textContent = "Your verification email will be sent tomorrow from 1:00 AM (Nigeria time). Withdrawals unlock once you confirm it.";
    } else {
      bar.innerHTML = 'Please confirm your email — we sent a link to <b></b>. Withdrawals stay locked until you do. <a href="#" style="color:#92400E;text-decoration:underline">Resend</a>';
      bar.querySelector("b").textContent = email;
      var link = bar.querySelector("a");
      link.onclick = async function (e) {
        e.preventDefault(); link.textContent = "Sending…";
        var r = await api("/auth/resend-verification", { method: "POST", body: "{}" });
        link.textContent = "Resend";
        if (r.ok && r.data.status === "queued") window.qapelaPopup("Your email is queued", r.data.message);
        else if (r.ok && r.data.status === "already_verified") bar.remove();
        else if (r.ok && r.data.status === "sent") alert(r.data.message);
        else alert(r.data.message || "Could not send right now. Try again later.");
      };
    }
    document.body.insertBefore(bar, document.body.firstChild);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
