// Qapela service worker. Bump VERSION on every site deploy so devices pick up the new pages.
const VERSION = 'qapela-pwa-v1';
const SHELL = [
  './offline.html',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './assets/qapela-logo-icon.png',
  './assets/qapela-theme.css',
  './assets/qapela-session.js',
  './assets/qapela-pwa.js'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  const url = new URL(req.url);

  // Only our own GET requests. The API Worker, Paystack, emails etc. are other
  // origins or non-GET, so money, balances and logins always go live to the server.
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // Pages: always try the network first so users never see stale balances/pages
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).catch(() => caches.match(req).then(r => r || caches.match('./offline.html')))
    );
    return;
  }

  // Static files (logos, css, js): serve from cache, refresh in the background
  e.respondWith(
    caches.match(req).then(cached => {
      const fresh = fetch(req).then(res => {
        if (res && res.ok) { const copy = res.clone(); caches.open(VERSION).then(c => c.put(req, copy)); }
        return res;
      }).catch(() => cached);
      return cached || fresh;
    })
  );
});
