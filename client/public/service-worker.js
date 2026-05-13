// service-worker.js
// ─────────────────────────────────────────────────────────────
// Service Worker — runs in the background in the browser.
//
// WHAT A SERVICE WORKER DOES:
// It sits between your app and the network. When the browser
// requests a file (HTML, CSS, JS), the service worker can
// serve it from its own cache instead of the network.
// This makes the app load instantly on repeat visits and
// work even when the user has no internet connection.
//
// HOW CACHING WORKS HERE:
// Strategy: "Cache First, then Network"
// 1. When a file is requested, check the cache first
// 2. If found in cache → serve immediately (fast)
// 3. If not in cache → fetch from network, then cache it
// 4. API calls (/api/*) are NEVER cached — always fresh from server
// ─────────────────────────────────────────────────────────────

const CACHE_NAME = "scamshield-v1";

// Files to cache immediately when the service worker installs.
// These are the core files the app needs to run.
const PRECACHE_URLS = [
  "/",
  "/index.html",
  "/static/js/main.chunk.js",
  "/static/js/bundle.js",
  "/manifest.json",
];

// ── Install Event ─────────────────────────────────────────────
// Fired once when the service worker is first registered.
// We pre-cache the core app files here.
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log("[SW] Pre-caching app shell");
      // addAll() fetches and caches all URLs in the array.
      // If any URL fails to cache, the entire install fails.
      return cache.addAll(PRECACHE_URLS).catch((err) => {
        // Log but don't crash — some files may not exist yet in dev
        console.warn("[SW] Pre-cache partial failure:", err);
      });
    })
  );
  // skipWaiting() activates the new service worker immediately
  // instead of waiting for old tabs to close.
  self.skipWaiting();
});

// ── Activate Event ────────────────────────────────────────────
// Fired after install. We clean up old caches here so
// users don't get stale files from previous app versions.
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME) // Old cache names
          .map((name) => {
            console.log("[SW] Deleting old cache:", name);
            return caches.delete(name);
          })
      );
    })
  );
  // Claim all open tabs immediately — no refresh needed
  self.clients.claim();
});

// ── Fetch Event ───────────────────────────────────────────────
// Fired every time the app makes a network request.
// We intercept it here and decide: cache or network?
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // ── Never cache API calls ─────────────────────────────────
  // API responses must always be fresh — we never want the
  // service worker returning a cached scan result.
  if (url.pathname.startsWith("/api")) {
    return; // Let the browser handle it normally
  }

  // ── Never cache cross-origin requests ─────────────────────
  // e.g. Google Fonts, Tailwind CDN, OpenRouter
  if (url.origin !== location.origin) {
    return;
  }

  // ── Cache-first strategy for everything else ──────────────
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Serve from cache — instant load
        return cachedResponse;
      }

      // Not in cache — fetch from network, then cache for next time
      return fetch(event.request).then((networkResponse) => {
        // Only cache successful GET responses
        if (
          !networkResponse ||
          networkResponse.status !== 200 ||
          event.request.method !== "GET"
        ) {
          return networkResponse;
        }

        // Clone the response — a response can only be consumed once.
        // We need one copy for the cache and one to return to the browser.
        const responseToCache = networkResponse.clone();

        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });

        return networkResponse;
      });
    })
  );
});
