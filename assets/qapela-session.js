/* Qapela session helper — include in the <head> of every app page, BEFORE the page's own scripts.
   Honours this device's "how long to stay signed in" setting (Account settings → Staying signed in):
     "6m"    (default) stay signed in until the app has been unused for 6 months
     "24h"   sign in again after 24 hours of not using the app
     "close" sign in again after the app is closed
   The server enforces the 6m / 24h lifetimes itself; this file only handles "close" (only the device can tell). */
(function () {
  var POL_KEY = "qapela_session_policy", BEAT_KEY = "qapela_heartbeat", ALIVE_KEY = "qapela_tab_alive";
  try {
    var pol = localStorage.getItem(POL_KEY) || "6m";
    if (localStorage.getItem("qapela_token") && pol === "close" && !sessionStorage.getItem(ALIVE_KEY)) {
      // A brand-new browser session. If no Qapela page has been alive in the last ~90s, the app was closed.
      var beat = Number(localStorage.getItem(BEAT_KEY) || 0);
      if (Date.now() - beat > 90000) ["token", "uid", "role", "profile"].forEach(function (k) { localStorage.removeItem("qapela_" + k); });
    }
    sessionStorage.setItem(ALIVE_KEY, "1");
    var beatNow = function () { try { localStorage.setItem(BEAT_KEY, String(Date.now())); } catch (e) {} };
    beatNow();
    setInterval(beatNow, 5000);
    document.addEventListener("visibilitychange", beatNow);
    window.addEventListener("pagehide", beatNow);
  } catch (e) { /* storage blocked: nothing to do */ }
})();
