const CACHE = "apex-protocol-v4";
const FILES = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icon.svg",
  "./apple-touch-icon.png",
  "./apex-security.js",
  "./rest-notify.js",
  "./backup-share.js"
];

// Precache each file separately: one missing file must not stop the worker installing.
self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => Promise.allSettled(FILES.map(file => cache.add(file))))
      .then(() => self.skipWaiting())
  );
});

// Remove old caches (v3 and earlier).
self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

// Network-first: always try for the newest files (so security fixes reach everyone),
// and fall back to the cache when offline.
self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;
  if (new URL(req.url).origin !== self.location.origin) return; // leave other sites alone

  event.respondWith(
    fetch(req, { cache: "no-cache" })
      .then(res => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(cache => cache.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req).then(hit => hit || caches.match("./index.html")))
  );
});
