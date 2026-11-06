/* Qapela PWA: registers the service worker and shows an "Install app" button. */
(function () {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('sw.js').catch(function () {});
    });
  }

  var standalone = (window.matchMedia && matchMedia('(display-mode: standalone)').matches) || navigator.standalone;
  if (standalone || window.top !== window.self) return;

  var DISMISS_KEY = 'qapela_install_dismissed';
  function dismissed() {
    try { return Date.now() - Number(localStorage.getItem(DISMISS_KEY) || 0) < 7 * 864e5; } catch (e) { return false; }
  }
  if (dismissed()) return;

  function bar(text, onGo) {
    var d = document.createElement('div');
    d.id = 'qapela-install';
    d.style.cssText = 'position:fixed;left:12px;right:12px;bottom:12px;z-index:99999;display:flex;align-items:center;gap:10px;max-width:420px;margin:0 auto;padding:10px 12px;border-radius:14px;background:#0E2A6B;color:#fff;font:600 14px system-ui,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.3)';
    var img = document.createElement('img');
    img.src = 'icons/icon-192.png'; img.width = 36; img.height = 36; img.style.borderRadius = '8px';
    var t = document.createElement('span'); t.textContent = text; t.style.flex = '1';
    var go = document.createElement('button'); go.textContent = onGo ? 'Install' : 'OK';
    go.style.cssText = 'border:0;border-radius:999px;padding:8px 16px;background:#F5B301;color:#111;font-weight:700';
    var x = document.createElement('button'); x.textContent = '✕'; x.setAttribute('aria-label', 'Close');
    x.style.cssText = 'border:0;background:none;color:#fff;font-size:16px;padding:4px';
    function close(save) { if (save) { try { localStorage.setItem(DISMISS_KEY, String(Date.now())); } catch (e) {} } d.remove(); }
    go.onclick = function () { if (onGo) onGo(); close(!onGo); };
    x.onclick = function () { close(true); };
    d.appendChild(img); d.appendChild(t); d.appendChild(go); d.appendChild(x);
    document.body.appendChild(d);
  }

  var deferred = null;
  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault(); deferred = e;
    bar('Install Qapela on your device', function () { deferred.prompt(); deferred = null; });
  });
  window.addEventListener('appinstalled', function () {
    var b = document.getElementById('qapela-install'); if (b) b.remove();
  });

  // iPhone / iPad Safari has no install prompt: show how to add it manually
  if (/iphone|ipad|ipod/i.test(navigator.userAgent)) {
    window.addEventListener('load', function () { bar('To install: tap Share, then Add to Home Screen', null); });
  }
})();
