/**
 * Omada API Hub — Service Worker
 * Stratégie : cache-first pour les assets statiques, network-first pour les pages/API
 */

const CACHE_NAME = 'omada-hub-v1';

const STATIC_ASSETS = [
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/img/logo.svg',
  '/static/img/favicon.svg',
  '/static/img/icon-pwa.svg',
  '/static/manifest.json',
];

// ── Installation : mise en cache des assets statiques ──────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

// ── Activation : nettoyage des anciens caches ──────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Fetch : cache-first pour /static/*, network-first pour le reste ────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Ne pas intercepter les requêtes non-GET ou les API
  if (request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/')) return;

  if (url.pathname.startsWith('/static/')) {
    // Cache-first : assets statiques
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        return fetch(request).then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        });
      })
    );
  } else {
    // Network-first : pages HTML
    event.respondWith(
      fetch(request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => caches.match(request))
    );
  }
});
