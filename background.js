/*
 * Background service worker.
 *
 * Receives page-level findings from content scripts, fetches the JavaScript the
 * page already loaded (deduped, throttled, no credentials) plus source maps,
 * scans them with the shared rule pack, persists findings locally, and raises
 * notifications / badge counts.
 */
importScripts('lib/entropy.js', 'lib/rules.js', 'lib/scan.js');

const DEFAULT_SETTINGS = {
  enabled: true,
  scanHtml: true,
  scanExternalJs: true,
  scanSourceMaps: true,
  scanLazyChunks: true,
  scanApiResponses: true,
  scanStorage: true,
  fetchWithCredentials: false,
  notifications: true,
  notifyMinSeverity: 'medium',
  onlyInScope: false,
  scope: [],
};

const MAX_FINDINGS = 5000;
const MAX_SEEN = 20000;
const MAX_SCANNED = 20000;
const MAX_IGNORED = 5000;
const SCANNED_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FETCH_BYTES = 5 * 1024 * 1024;
const MAX_MAP_BYTES = 16 * 1024 * 1024;
const MAX_API_BODY_CHARS = 512 * 1024;
const MAX_CONCURRENT_FETCHES = 2;
const FETCH_GAP_MS = 150;
const FETCH_TIMEOUT_MS = 15000;
const NOTIFY_THROTTLE_MS = 5 * 60 * 1000;
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

let settings = { ...DEFAULT_SETTINGS };
const settingsReady = chrome.storage.local
  .get({ settings: DEFAULT_SETTINGS })
  .then((data) => {
    settings = { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
  })
  .catch(() => {});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.settings) return;
  settings = { ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) };
});

/* ---------------------------------------------------------------- storage */

let store = null;
const storeReady = chrome.storage.local
  .get({ findings: [], seen: {}, scanned: {}, ignored: {} })
  .then((data) => {
    store = {
      findings: Array.isArray(data.findings) ? data.findings : [],
      seen: data.seen && typeof data.seen === 'object' ? data.seen : {},
      scanned: data.scanned && typeof data.scanned === 'object' ? data.scanned : {},
      ignored: data.ignored && typeof data.ignored === 'object' ? data.ignored : {},
    };
    pruneScanned();
    return store;
  });

let persistTimer = null;

function persist() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    persistNow();
  }, 250);
}

async function persistNow() {
  if (!store) return;
  try {
    await chrome.storage.local.set({
      findings: store.findings,
      seen: store.seen,
      scanned: store.scanned,
      ignored: store.ignored,
    });
  } catch (err) {
    console.warn('[PSS] persist failed:', err);
  }
}

function pruneScanned() {
  const cutoff = Date.now() - SCANNED_TTL_MS;
  for (const [key, ts] of Object.entries(store.scanned)) {
    if (!ts || ts < cutoff) delete store.scanned[key];
  }
}

function trimStore() {
  if (store.findings.length > MAX_FINDINGS) {
    store.findings.splice(0, store.findings.length - MAX_FINDINGS);
  }
  const seenKeys = Object.keys(store.seen);
  if (seenKeys.length > MAX_SEEN) {
    seenKeys.slice(0, seenKeys.length - MAX_SEEN).forEach((k) => delete store.seen[k]);
  }
  const scannedKeys = Object.keys(store.scanned);
  if (scannedKeys.length > MAX_SCANNED) {
    scannedKeys.slice(0, scannedKeys.length - MAX_SCANNED).forEach((k) => delete store.scanned[k]);
  }
  const ignoredKeys = Object.keys(store.ignored);
  if (ignoredKeys.length > MAX_IGNORED) {
    ignoredKeys.slice(0, ignoredKeys.length - MAX_IGNORED).forEach((k) => delete store.ignored[k]);
  }
}

/* ------------------------------------------------------------------ utils */

function hashString(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

function scopeMatches(host, patterns) {
  const h = host.toLowerCase();
  return (patterns || []).some((raw) => {
    const p = String(raw || '').trim().toLowerCase();
    if (!p) return false;
    if (p.startsWith('*.')) {
      const suffix = p.slice(2);
      return h === suffix || h.endsWith('.' + suffix);
    }
    return h === p || h.endsWith('.' + p);
  });
}

function inScope(host) {
  if (!settings.onlyInScope) return true;
  return scopeMatches(host, settings.scope);
}

function safeHttpUrl(value, base) {
  try {
    const url = new URL(String(value), base || undefined);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    url.hash = '';
    return url.href;
  } catch (_) {
    return null;
  }
}

/*
 * Per-source scoping: a secret in page HTML / JS / maps / inline scripts is
 * recorded once per host; API responses, cookies, storage, and URL findings
 * keep their source URL so findings stay attributable. The rule id is not part
 * of the key, so the same value found by a better rule can upgrade the entry.
 */
const SCOPED_SOURCE_TYPES = new Set(['xhr', 'storage', 'cookie', 'idb', 'url']);

function dedupeKey(item) {
  const base = [item.match, item.host || ''];
  if (SCOPED_SOURCE_TYPES.has(item.sourceType)) {
    base.push(item.sourceType, item.sourceUrl || '');
  }
  return base.join('|');
}

/* --------------------------------------------------------------- findings */

function addFindings(items) {
  const added = [];
  if (!store || !Array.isArray(items)) return added;
  let mutated = false;

  for (const item of items) {
    if (!item || !item.match || !item.ruleId) continue;
    const key = hashString(dedupeKey(item));
    if (store.ignored[key]) continue;

    const existingId = store.seen[key];
    if (existingId) {
      // The same value can be seen first in JS and later in its source map,
      // where the context often proves it is worse. Keep the better finding.
      const existing = store.findings.find((f) => f.id === existingId);
      if (
        existing &&
        (SEVERITY_RANK[item.severity] ?? 9) < (SEVERITY_RANK[existing.severity] ?? 9)
      ) {
        existing.severity = item.severity;
        existing.ruleId = item.ruleId;
        existing.ruleName = item.ruleName || item.ruleId;
        existing.snippet = item.snippet || existing.snippet;
        existing.line = Number(item.line) || existing.line;
        existing.sourceType = item.sourceType || existing.sourceType;
        existing.sourceUrl = item.sourceUrl || existing.sourceUrl;
        existing.pageUrl = item.pageUrl || existing.pageUrl;
        existing.upgradedAt = Date.now();
        mutated = true;
      }
      continue;
    }

    const finding = {
      id: crypto.randomUUID ? crypto.randomUUID() : key + '-' + Date.now(),
      time: Date.now(),
      severity: item.severity || 'medium',
      ruleId: item.ruleId,
      ruleName: item.ruleName || item.ruleId,
      match: String(item.match),
      redacted: item.redacted || (self.PSS && self.PSS.maskMatch ? self.PSS.maskMatch(item.match) : '***'),
      snippet: item.snippet || '',
      line: Number(item.line) || 0,
      sourceType: item.sourceType || 'html',
      sourceUrl: item.sourceUrl || '',
      pageUrl: item.pageUrl || '',
      host: item.host || '',
    };
    store.findings.push(finding);
    store.seen[key] = finding.id;
    added.push(finding);
  }

  if (added.length || mutated) {
    trimStore();
    persist();
  }
  return added;
}

/* ------------------------------------------------------------------- badge */

async function updateBadge(tabId, host) {
  if (typeof tabId !== 'number' || !host) return;
  await storeReady;
  const count = store.findings.filter((f) => f.host === host).length;
  try {
    await chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId });
    await chrome.action.setBadgeText({
      tabId,
      text: count ? (count > 999 ? '999+' : String(count)) : '',
    });
  } catch (_) {
    /* tab closed mid-flight */
  }
}

/* ---------------------------------------------------------- notifications */

const lastNotified = new Map();

function notify(host, added) {
  const rankLimit = SEVERITY_RANK[settings.notifyMinSeverity];
  const limit = typeof rankLimit === 'number' ? rankLimit : SEVERITY_RANK.medium;
  const notable = added.filter((f) => (SEVERITY_RANK[f.severity] ?? 9) <= limit);
  if (notable.length === 0) return;

  const now = Date.now();
  if (now - (lastNotified.get(host) || 0) < NOTIFY_THROTTLE_MS) return;
  lastNotified.set(host, now);

  const names = Array.from(new Set(notable.map((f) => f.ruleName)));
  const preview = names.slice(0, 3).join(', ') + (names.length > 3 ? ', …' : '');
  try {
    const created = chrome.notifications.create(`pss-${host}-${now}`, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon128.png'),
      title: `${host}: ${notable.length} new finding${notable.length === 1 ? '' : 's'}`,
      message: preview,
      priority: 1,
    });
    if (created && typeof created.catch === 'function') created.catch(() => {});
  } catch (err) {
    console.warn('[PSS] notification failed:', err);
  }
}

/* --------------------------------------------------------------- fetching */

const fetchQueue = [];
let activeFetches = 0;

function enqueueFetch(job) {
  if (!store) return;
  const key = hashString(job.url);
  if (store.scanned[key]) return;
  fetchQueue.push(job);
  pumpQueue();
}

function pumpQueue() {
  while (activeFetches < MAX_CONCURRENT_FETCHES && fetchQueue.length > 0) {
    const job = fetchQueue.shift();
    activeFetches++;
    setTimeout(() => {
      runFetchJob(job)
        .catch((err) => console.warn('[PSS] fetch job failed:', job.url, err))
        .finally(() => {
          activeFetches--;
          setTimeout(pumpQueue, FETCH_GAP_MS);
        });
    }, FETCH_GAP_MS);
  }
}

async function readCapped(response, cap) {
  if (!response.body || !response.body.getReader) {
    const text = await response.text();
    return text.slice(0, cap);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < cap) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
  } finally {
    try {
      await reader.cancel();
    } catch (_) {
      /* already closed */
    }
  }
  const merged = new Uint8Array(Math.min(total, cap));
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= merged.length) break;
    const slice = chunk.subarray(0, Math.min(chunk.length, merged.length - offset));
    merged.set(slice, offset);
    offset += slice.length;
  }
  try {
    return new TextDecoder('utf-8').decode(merged);
  } catch (_) {
    return '';
  }
}

function isScannableContentType(value) {
  if (!value) return true;
  return /(?:javascript|ecmascript|json|text\/|xml|octet-stream)/i.test(value);
}

function findSourceMapUrl(text, baseUrl) {
  const re = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g;
  let m;
  let last = null;
  while ((m = re.exec(text)) !== null) last = m[1];
  if (!last) return null;
  if (last.startsWith('data:')) return last;
  return safeHttpUrl(last, baseUrl);
}

/*
 * Webpack runtime chunks: main.js contains "static/js/"+id+"."+{id:"hash"}[id]
 * +".chunk.js". Those lazy bundles are often never loaded by the page you are
 * on, but their JS and source maps are usually public and can hold secrets.
 */
function discoverChunkUrls(text, baseUrl) {
  const urls = new Set();
  const blockRe = /\{([^{}]{0,4000})\}\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*\+\s*["']\.chunk\.js["']/g;
  let block;
  while ((block = blockRe.exec(text)) !== null && urls.size < 50) {
    const pairRe = /"?(\d{1,5})"?\s*:\s*"([0-9a-f]{4,32})"/g;
    let pair;
    while ((pair = pairRe.exec(block[1])) !== null && urls.size < 50) {
      try {
        const url = new URL(`${pair[1]}.${pair[2]}.chunk.js`, baseUrl);
        url.hash = '';
        if (url.protocol === 'http:' || url.protocol === 'https:') urls.add(url.href);
      } catch (_) {
        /* skip malformed */
      }
    }
  }
  return urls;
}

function decodeDataUri(uri, cap) {
  try {
    const comma = uri.indexOf(',');
    if (comma === -1) return null;
    const meta = uri.slice(5, comma);
    const payload = uri.slice(comma + 1);
    if (/;base64/i.test(meta)) {
      if (payload.length > cap * 1.4) return null;
      const binary = atob(payload);
      if (binary.length > cap) return null;
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    }
    const decoded = decodeURIComponent(payload);
    return decoded.length > cap ? decoded.slice(0, cap) : decoded;
  } catch (_) {
    return null;
  }
}

async function scanAndStore(text, meta) {
  const findings = self.PSS.scanText(text, {
    sourceType: meta.sourceType,
    sourceUrl: meta.sourceUrl,
    pageUrl: meta.pageUrl,
    host: meta.host,
  }).map((f) => ({
    ...f,
    sourceType: meta.sourceType,
    sourceUrl: meta.sourceUrl,
    pageUrl: meta.pageUrl,
    host: meta.host,
  }));

  const added = addFindings(findings);
  if (added.length > 0) {
    updateBadge(meta.tabId, meta.host);
    if (settings.notifications) notify(meta.host, added);
  }
  return added;
}

async function runFetchJob(job) {
  await storeReady;
  await settingsReady;
  if (!settings.enabled) return;
  if (job.sourceType === 'map' && !settings.scanSourceMaps) return;
  if (job.sourceType !== 'map' && !settings.scanExternalJs) return;
  if (!inScope(job.host)) return;

  const key = hashString(job.url);
  if (store.scanned[key]) return;
  store.scanned[key] = Date.now();
  persist();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(job.url, {
      credentials: settings.fetchWithCredentials ? 'include' : 'omit',
      cache: 'default',
      redirect: 'follow',
      signal: controller.signal,
    });
  } catch (_) {
    return;
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) return;
  const sourceType = job.sourceType || 'js';
  const byteCap = sourceType === 'map' ? MAX_MAP_BYTES : MAX_FETCH_BYTES;
  const declaredLength = Number(response.headers.get('content-length') || 0);
  if (declaredLength > byteCap) return;
  if (!isScannableContentType(response.headers.get('content-type'))) return;

  const text = await readCapped(response, byteCap);
  if (!text) return;

  await scanAndStore(text, {
    sourceType,
    sourceUrl: job.url,
    pageUrl: job.pageUrl,
    host: job.host,
    tabId: job.tabId,
  });

  if (sourceType === 'map') return;

  if (settings.scanLazyChunks) {
    for (const chunkUrl of discoverChunkUrls(text, job.url)) {
      enqueueFetch({
        url: chunkUrl,
        pageUrl: job.pageUrl,
        host: job.host,
        tabId: job.tabId,
        sourceType: 'js',
      });
    }
  }

  if (settings.scanSourceMaps) {
    const mapRef = findSourceMapUrl(text, job.url);
    if (!mapRef) return;

    const inline = mapRef.startsWith('data:');
    const mapMatch = inline ? `${job.url}#inline-source-map` : mapRef;

    // Flag the exposure as soon as the reference is seen. The map may be too
    // large, blocked, or deleted by the time anything tries to fetch it.
    const info = addFindings([
      {
        ruleId: 'source-map-exposed',
        ruleName: 'Source map exposed',
        severity: 'low',
        match: mapMatch,
        redacted: mapMatch,
        snippet: inline
          ? 'Inline source map embedded in the bundle; original source may be recoverable.'
          : 'Source map is publicly reachable; original source may be recoverable.',
        line: 0,
        sourceType: 'map',
        sourceUrl: mapMatch,
        pageUrl: job.pageUrl,
        host: job.host,
      },
    ]);
    if (info.length > 0) {
      updateBadge(job.tabId, job.host);
      if (settings.notifications) notify(job.host, info);
    }

    if (inline) {
      const decoded = decodeDataUri(mapRef, MAX_MAP_BYTES);
      if (decoded) {
        await scanAndStore(decoded, {
          sourceType: 'map',
          sourceUrl: mapMatch,
          pageUrl: job.pageUrl,
          host: job.host,
          tabId: job.tabId,
        });
      }
      return;
    }

    enqueueFetch({
      url: mapRef,
      pageUrl: job.pageUrl,
      host: job.host,
      tabId: job.tabId,
      sourceType: 'map',
    });
  }
}

/* ------------------------------------------------------------ page intake */

function resolvePage(msg) {
  try {
    const url = new URL(msg.pageUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    const host = url.hostname.toLowerCase();
    if (String(msg.host || '').toLowerCase() !== host) return null;
    return { pageUrl: url.href, host };
  } catch (_) {
    return null;
  }
}

function sanitizeFindings(list, host) {
  if (!Array.isArray(list)) return [];
  const allowedTypes = new Set(['html', 'inline', 'storage', 'cookie', 'idb', 'url']);
  return list.slice(0, 300).map((f) => ({
    ruleId: String(f.ruleId || ''),
    ruleName: String(f.ruleName || ''),
    severity: String(f.severity || 'medium'),
    match: String(f.match || ''),
    redacted: String(f.redacted || ''),
    snippet: String(f.snippet || ''),
    line: Number(f.line) || 0,
    sourceType: allowedTypes.has(f.sourceType) ? f.sourceType : 'html',
    sourceUrl: String(f.sourceUrl || ''),
    pageUrl: String(f.pageUrl || ''),
    host,
  }));
}

async function handlePageScan(msg, sender) {
  await settingsReady;
  await storeReady;
  if (!settings.enabled) return;

  const page = resolvePage(msg);
  if (!page) return;
  if (!inScope(page.host)) return;

  const tabId = sender && sender.tab ? sender.tab.id : undefined;
  const added = addFindings(sanitizeFindings(msg.findings, page.host));
  if (added.length > 0) {
    updateBadge(tabId, page.host);
    if (settings.notifications) notify(page.host, added);
  }

  if (settings.scanExternalJs && Array.isArray(msg.scripts)) {
    for (const raw of msg.scripts.slice(0, 80)) {
      const url = safeHttpUrl(raw, page.pageUrl);
      if (!url) continue;
      enqueueFetch({ url, pageUrl: page.pageUrl, host: page.host, tabId, sourceType: 'js' });
    }
  }
}

/* --------------------------------------------------------- API responses */

const recentApiBodies = new Map();

async function handleApiBody(msg, sender) {
  await settingsReady;
  await storeReady;
  if (!settings.enabled || settings.scanApiResponses === false) return;

  const page = resolvePage(msg);
  if (!page || !inScope(page.host)) return;

  const url = safeHttpUrl(msg.url, page.pageUrl);
  if (!url) return;

  const body = typeof msg.body === 'string' ? msg.body : '';
  if (!body || body.length > MAX_API_BODY_CHARS) return;

  const signature = hashString(
    `${url}|${body.length}|${body.slice(0, 64)}|${body.slice(-64)}`
  );
  if (recentApiBodies.has(signature)) return;
  if (recentApiBodies.size >= 500) {
    recentApiBodies.delete(recentApiBodies.keys().next().value);
  }
  recentApiBodies.set(signature, Date.now());

  const findings = self.PSS.scanText(body, {
    sourceType: 'xhr',
    sourceUrl: url,
    pageUrl: page.pageUrl,
    host: page.host,
  }).map((f) => ({
    ...f,
    sourceType: 'xhr',
    sourceUrl: url,
    pageUrl: page.pageUrl,
    host: page.host,
  }));

  const added = addFindings(findings);
  if (added.length > 0) {
    updateBadge(sender && sender.tab ? sender.tab.id : undefined, page.host);
    if (settings.notifications) notify(page.host, added);
  }
}

/* --------------------------------------------------------- false-positive */

async function dismissFinding(id) {
  await storeReady;
  if (typeof id !== 'string') return false;
  const index = store.findings.findIndex((f) => f.id === id);
  if (index === -1) return false;

  const [finding] = store.findings.splice(index, 1);
  store.ignored[hashString(dedupeKey(finding))] = Date.now();
  trimStore();
  await persistNow();
  return true;
}

/* --------------------------------------------------------------- clearing */

async function clearAllData() {
  await storeReady;
  store.findings = [];
  store.seen = {};
  store.scanned = {};
  store.ignored = {};
  recentApiBodies.clear();
  lastNotified.clear();
  if (persistTimer) {
    clearTimeout(persistTimer);
    persistTimer = null;
  }
  await chrome.storage.local.set({ findings: [], seen: {}, scanned: {}, ignored: {} });
  try {
    await chrome.action.setBadgeText({ text: '' });
  } catch (_) {
    /* no tabs */
  }
}

/* ---------------------------------------------------------------- wiring */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return false;

  if (msg.type === 'page-scan') {
    handlePageScan(msg, sender).catch((err) => console.warn('[PSS] page scan failed:', err));
    return false;
  }

  if (msg.type === 'api-body') {
    handleApiBody(msg, sender).catch((err) => console.warn('[PSS] api scan failed:', err));
    return false;
  }

  if (msg.type === 'dismiss-finding') {
    dismissFinding(msg.id)
      .then((ok) => sendResponse({ ok }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (msg.type === 'clear-all') {
    clearAllData()
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  return false;
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.tabs.sendMessage(details.tabId, { type: 'rescan' }).catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
  }
});
