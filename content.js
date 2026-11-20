/*
 * Page-side collector (isolated world).
 *
 *  - scans the served HTML locally (cheap; keeps large documents out of messages)
 *  - scans localStorage / sessionStorage, non-HttpOnly cookies, IndexedDB
 *  - scans the page URL (query strings and fragments)
 *  - reports script URLs so the service worker can re-fetch them
 *  - watches for dynamically inserted <script> elements (lazy chunks, inline text)
 *  - forwards API response bodies captured by capture.js (MAIN world)
 *  - rescans on SPA navigations
 */
(function () {
  if (window !== window.top) return;

  const MAX_HTML_CHARS = 5_000_000;
  const MAX_STORAGE_VALUE_CHARS = 256_000;
  const STORAGE_TOTAL_BUDGET = 1_500_000;
  const MAX_INLINE_CHARS = 512_000;
  const MAX_API_BODY_CHARS = 512 * 1024;
  const MIN_SCAN_GAP_MS = 1500;

  const MAX_IDB_DBS = 8;
  const MAX_IDB_STORES = 8;
  const MAX_IDB_RECORDS = 25;
  const MAX_IDB_VALUE_CHARS = 64_000;
  const IDB_BUDGET_CHARS = 1_000_000;
  const IDB_DEADLINE_MS = 2000;

  let lastScanAt = 0;
  let timer = null;
  let dynamicTimer = null;
  let idbScanDone = false;

  const knownScripts = new Set();
  const knownInline = new Set();
  const pendingInline = [];
  const pendingScripts = new Set();

  /* ---------------------------------------------------------------- basics */

  function schedule(delay) {
    clearTimeout(timer);
    timer = setTimeout(runScan, delay);
  }

  async function getSettings() {
    try {
      const data = await chrome.storage.local.get({ settings: {} });
      return data.settings || {};
    } catch (_) {
      return {};
    }
  }

  function send(payload) {
    try {
      const pending = chrome.runtime.sendMessage(payload);
      if (pending && typeof pending.catch === 'function') pending.catch(() => {});
    } catch (_) {
      /* extension context can be invalidated on reload */
    }
  }

  /* --------------------------------------------------------------- sources */

  function collectScriptUrls() {
    const urls = new Set();
    for (const script of document.scripts) {
      if (script.src && /^https?:/i.test(script.src)) urls.add(script.src);
    }
    try {
      for (const entry of performance.getEntriesByType('resource')) {
        if (!entry.name || !/^https?:/i.test(entry.name)) continue;
        if (entry.initiatorType === 'script' || /\.m?js([?#]|$)/i.test(entry.name)) {
          urls.add(entry.name);
        }
      }
    } catch (_) {
      /* Resource Timing unavailable */
    }
    const list = Array.from(urls).slice(0, 80);
    for (const url of list) knownScripts.add(url);
    return list;
  }

  function scanStorage() {
    const findings = [];
    const scanner = self.PSS && self.PSS.scanText;
    if (!scanner) return findings;

    const stores = [];
    try {
      if (window.localStorage) stores.push(['localStorage', window.localStorage]);
    } catch (_) {
      /* storage blocked */
    }
    try {
      if (window.sessionStorage) stores.push(['sessionStorage', window.sessionStorage]);
    } catch (_) {
      /* storage blocked */
    }

    let budget = STORAGE_TOTAL_BUDGET;
    for (const [kind, storage] of stores) {
      let keys;
      try {
        keys = Object.keys(storage);
      } catch (_) {
        continue;
      }
      for (const key of keys.slice(0, 200)) {
        let value;
        try {
          value = storage.getItem(key);
        } catch (_) {
          continue;
        }
        if (typeof value !== 'string' || value.length === 0) continue;
        if (value.length > MAX_STORAGE_VALUE_CHARS) value = value.slice(0, MAX_STORAGE_VALUE_CHARS);
        budget -= value.length;
        if (budget <= 0) break;
        findings.push(
          ...scanner(value, {
            sourceType: 'storage',
            sourceUrl: `${location.origin}#storage:${kind}:${key}`,
            pageUrl: location.href,
            host: location.hostname,
          })
        );
        if (findings.length >= 300) return findings;
      }
    }
    return findings;
  }

  function scanUrl() {
    const scanner = self.PSS && self.PSS.scanText;
    if (!scanner) return [];
    const pageUrl = location.href;
    let safeUrl = pageUrl;
    try {
      const parsed = new URL(pageUrl);
      safeUrl = `${parsed.origin}${parsed.pathname}#url`;
    } catch (_) {
      /* keep the raw URL if parsing fails */
    }
    return scanner(pageUrl, {
      sourceType: 'url',
      sourceUrl: safeUrl,
      pageUrl,
      host: location.hostname,
    });
  }

  function scanCookies() {
    const findings = [];
    const scanner = self.PSS && self.PSS.scanText;
    if (!scanner) return findings;

    let cookie = '';
    try {
      cookie = document.cookie || '';
    } catch (_) {
      return findings;
    }
    if (!cookie) return findings;

    let budget = 200_000;
    for (const part of cookie.split(';').slice(0, 100)) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      const name = part.slice(0, eq).trim();
      let value = part.slice(eq + 1).trim();
      if (!name || !value || value.length > MAX_STORAGE_VALUE_CHARS) continue;
      try {
        value = decodeURIComponent(value);
      } catch (_) {
        /* keep encoded value */
      }
      budget -= value.length;
      if (budget <= 0) break;
      findings.push(
        ...scanner(value, {
          sourceType: 'cookie',
          sourceUrl: `${location.origin}#cookie:${name}`,
          pageUrl: location.href,
          host: location.hostname,
        })
      );
      if (findings.length >= 100) break;
    }
    return findings;
  }

  function openDatabase(name, version) {
    return new Promise((resolve, reject) => {
      let request;
      try {
        request = version ? indexedDB.open(name, version) : indexedDB.open(name);
      } catch (err) {
        reject(err);
        return;
      }
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error('open failed'));
      request.onblocked = () => reject(new Error('blocked'));
    });
  }

  function readStoreRecords(db, storeName, limit) {
    return new Promise((resolve, reject) => {
      let tx;
      let store;
      let cursorRequest;
      try {
        tx = db.transaction(storeName, 'readonly');
        store = tx.objectStore(storeName);
        cursorRequest = store.openCursor();
      } catch (err) {
        reject(err);
        return;
      }

      const records = [];
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result;
        if (!cursor || records.length >= limit) {
          resolve(records);
          return;
        }
        records.push({ key: String(cursor.key), value: cursor.value });
        try {
          cursor.continue();
        } catch (_) {
          resolve(records);
        }
      };
      cursorRequest.onerror = () => reject(cursorRequest.error || new Error('cursor failed'));
    });
  }

  async function scanIndexedDb(pageUrl, host) {
    const findings = [];
    const scanner = self.PSS && self.PSS.scanText;
    if (!scanner || !window.indexedDB || typeof indexedDB.databases !== 'function') return findings;

    let databases = [];
    try {
      databases = await indexedDB.databases();
    } catch (_) {
      return findings;
    }

    let origin = location.origin;
    try {
      origin = new URL(pageUrl).origin;
    } catch (_) {
      /* keep current origin */
    }

    const deadline = Date.now() + IDB_DEADLINE_MS;
    let budget = IDB_BUDGET_CHARS;

    for (const info of (databases || []).slice(0, MAX_IDB_DBS)) {
      if (!info || !info.name || Date.now() > deadline || budget <= 0) break;

      let db;
      try {
        db = await openDatabase(info.name, info.version);
      } catch (_) {
        continue;
      }

      try {
        const stores = Array.from(db.objectStoreNames).slice(0, MAX_IDB_STORES);
        for (const storeName of stores) {
          if (Date.now() > deadline || budget <= 0) break;

          let records;
          try {
            records = await readStoreRecords(db, storeName, MAX_IDB_RECORDS);
          } catch (_) {
            continue;
          }

          for (const record of records) {
            if (Date.now() > deadline || budget <= 0) break;
            let text;
            try {
              text =
                typeof record.value === 'string' ? record.value : JSON.stringify(record.value);
            } catch (_) {
              continue;
            }
            if (typeof text !== 'string' || text.length === 0) continue;
            if (text.length > MAX_IDB_VALUE_CHARS) text = text.slice(0, MAX_IDB_VALUE_CHARS);
            budget -= text.length;
            findings.push(
              ...scanner(text, {
                sourceType: 'idb',
                sourceUrl: `${origin}#idb:${info.name}/${storeName}/${record.key}`,
                pageUrl,
                host,
              })
            );
            if (findings.length >= 200) return findings;
          }
        }
      } finally {
        try {
          db.close();
        } catch (_) {
          /* already closed */
        }
      }
    }
    return findings;
  }

  /* ------------------------------------------------------------- main scan */

  async function runScan() {
    const now = Date.now();
    if (now - lastScanAt < MIN_SCAN_GAP_MS) return;
    lastScanAt = now;

    const settings = await getSettings();
    if (settings.enabled === false) return;

    const host = location.hostname;
    if (!host) return;
    const pageUrl = location.href;

    const findings = [];
    if (settings.scanHtml !== false && self.PSS && self.PSS.scanText) {
      const html = document.documentElement ? document.documentElement.outerHTML : '';
      findings.push(
        ...self.PSS.scanText(html.slice(0, MAX_HTML_CHARS), {
          sourceType: 'html',
          sourceUrl: pageUrl,
          pageUrl,
          host,
        })
      );
    }
    if (settings.scanStorage !== false) {
      findings.push(...scanStorage());
      findings.push(...scanCookies());
    }
    findings.push(...scanUrl());

    send({
      type: 'page-scan',
      pageUrl,
      host,
      findings: findings.slice(0, 300),
      scripts: collectScriptUrls(),
    });

    if (settings.scanStorage !== false && !idbScanDone) {
      idbScanDone = true;
      scanIndexedDb(pageUrl, host)
        .then((idbFindings) => {
          if (idbFindings.length === 0) return;
          send({
            type: 'page-scan',
            pageUrl,
            host,
            findings: idbFindings.slice(0, 300),
            scripts: [],
          });
        })
        .catch(() => {});
    }
  }

  /* ----------------------------------------------------- dynamic elements */

  function scheduleDynamicFlush() {
    clearTimeout(dynamicTimer);
    dynamicTimer = setTimeout(flushDynamic, 800);
  }

  async function flushDynamic() {
    const scripts = Array.from(pendingScripts).slice(0, 50);
    pendingScripts.clear();
    const inlineTexts = pendingInline.splice(0, pendingInline.length);
    if (scripts.length === 0 && inlineTexts.length === 0) return;

    const settings = await getSettings();
    if (settings.enabled === false) return;
    const host = location.hostname;
    if (!host) return;

    const findings = [];
    if (settings.scanHtml !== false && self.PSS && self.PSS.scanText) {
      for (const text of inlineTexts) {
        findings.push(
          ...self.PSS.scanText(text, {
            sourceType: 'inline',
            sourceUrl: location.href,
            pageUrl: location.href,
            host,
          })
        );
      }
    }

    send({
      type: 'page-scan',
      pageUrl: location.href,
      host,
      findings: findings.slice(0, 300),
      scripts,
    });
  }

  function watchDynamicScripts() {
    if (!document.documentElement || typeof MutationObserver !== 'function') return;

    const observer = new MutationObserver((records) => {
      let queued = false;
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (!(node instanceof Element)) continue;
          const scripts =
            node.tagName === 'SCRIPT' ? [node] : Array.from(node.querySelectorAll('script'));
          for (const script of scripts) {
            if (script.src) {
              if (!knownScripts.has(script.src)) {
                knownScripts.add(script.src);
                pendingScripts.add(script.src);
                queued = true;
              }
            } else if (script.textContent) {
              const signature = `${script.textContent.length}:${script.textContent.slice(0, 160)}`;
              if (knownInline.has(signature)) continue;
              knownInline.add(signature);
              if (knownInline.size > 1000) knownInline.clear();
              if (script.textContent.length <= MAX_INLINE_CHARS && pendingInline.length < 20) {
                pendingInline.push(script.textContent);
                queued = true;
              }
            }
          }
        }
      }
      if (queued) scheduleDynamicFlush();
    });

    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  /* -------------------------------------------------- captured API bodies */

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.__pss_scan__ !== true) return;
    if (typeof data.body !== 'string' || data.body.length === 0) return;
    if (data.body.length > MAX_API_BODY_CHARS) return;
    const url = typeof data.url === 'string' ? data.url : '';
    if (url && !/^https?:/i.test(url)) return;
    const host = location.hostname;
    if (!host) return;
    send({
      type: 'api-body',
      pageUrl: location.href,
      host,
      url: url || location.href,
      body: data.body,
    });
  });

  /* ---------------------------------------------------------------- wiring */

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'rescan') schedule(600);
    return false;
  });

  window.addEventListener('hashchange', () => schedule(600));
  window.addEventListener('popstate', () => schedule(600));

  /*
   * Runs at document_start so the API-body listener exists before early
   * fetches resolve. DOM work waits for parsing, but DOMContentLoaded and load
   * can both be missed (stalled third-party scripts, document replacement), so
   * a timer starts the scan even when neither event arrives.
   */
  let started = false;

  function start() {
    schedule(600);
    if (started) return;
    started = true;
    watchDynamicScripts();
  }

  setTimeout(() => {
    if (!started) start();
  }, 1500);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
    window.addEventListener('load', start, { once: true });
  } else {
    start();
  }
})();
