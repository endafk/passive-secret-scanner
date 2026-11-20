#!/usr/bin/env node
/*
 * Real-browser smoke test.
 *
 * Launches a Chromium-based browser (Brave Origin by default, or $BROWSER_BIN /
 * any of the common binaries) with this directory loaded as an unpacked
 * extension, serves demo/ on localhost, lets the page scan, then reads the
 * extension's chrome.storage.local over the DevTools protocol.
 *
 * Run: node tools/browser-test.js
 * Requires: a Chromium-family browser; no puppeteer/playwright.
 */
"use strict";

const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const DEMO = path.join(ROOT, "demo");
const PROFILE = fs.mkdtempSync(path.join(os.tmpdir(), "pss-brave-"));
let PORT = 0;
let CDP_PORT = 0;

const CANDIDATES = [
  process.env.BROWSER_BIN,
  "brave-origin",
  "brave-browser",
  "brave",
  "chromium",
  "chromium-browser",
  "google-chrome",
  "google-chrome-stable",
].filter(Boolean);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function findBrowser() {
  for (const name of CANDIDATES) {
    const dirs = (process.env.PATH || "").split(":");
    for (const dir of dirs) {
      const full = path.join(dir, name);
      try {
        fs.accessSync(full, fs.constants.X_OK);
        return full;
      } catch (_) {
        /* keep looking */
      }
    }
  }
  return null;
}

function startServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const urlPath = decodeURIComponent((req.url || "/").split("?")[0]);
      const relative = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
      const file = path.join(DEMO, relative);
      if (!file.startsWith(DEMO)) {
        res.statusCode = 403;
        res.end("forbidden");
        return;
      }
      fs.readFile(file, (err, data) => {
        if (err) {
          res.statusCode = 404;
          res.end("not found");
          return;
        }
        res.setHeader("content-type", MIME[path.extname(file)] || "application/octet-stream");
        res.end(data);
      });
    });
    server.once("error", reject);
    server.listen(PORT, "127.0.0.1", () => resolve(server));
  });
}

async function listTargets() {
  const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`);
  if (!res.ok) throw new Error(`target list ${res.status}`);
  return res.json();
}

function cdpSend(wsUrl, method, params = {}, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const timer = setTimeout(() => {
      try {
        ws.close();
      } catch (_) {
        /* noop */
      }
      reject(new Error(`${method} timed out`));
    }, timeoutMs);

    ws.addEventListener("open", () => {
      ws.send(JSON.stringify({ id: 1, method, params }));
    });
    ws.addEventListener("message", (event) => {
      let message;
      try {
        message = JSON.parse(String(event.data));
      } catch (_) {
        return;
      }
      if (message.id !== 1) return;
      clearTimeout(timer);
      try {
        ws.close();
      } catch (_) {
        /* noop */
      }
      if (message.error) reject(new Error(message.error.message || `${method} error`));
      else resolve(message.result);
    });
    ws.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error(`${method}: websocket error`));
    });
  });
}

function cdpEvaluate(wsUrl, expression) {
  return cdpSend(wsUrl, "Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
}

async function findTarget(predicate) {
  const targets = await listTargets();
  return targets.find(predicate) || null;
}

async function waitForTarget(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const target = await findTarget(predicate);
      if (target) return target;
    } catch (_) {
      /* CDP not up yet */
    }
    await sleep(250);
  }
  return null;
}

async function openTab(url) {
  const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
  if (!res.ok) throw new Error(`version endpoint ${res.status}`);
  const info = await res.json();
  return cdpSend(info.webSocketDebuggerUrl, "Target.createTarget", { url });
}

async function readStorage() {
  const targets = await listTargets();
  const worker = targets.find(
    (t) => t.type === "service_worker" && String(t.url || "").startsWith("chrome-extension://")
  );
  if (!worker) return null;

  const expression = `(async () => {
    const data = await chrome.storage.local.get(null);
    const findings = data.findings || [];
    return JSON.stringify({
      extensionId: new URL(chrome.runtime.getURL('')).host,
      version: chrome.runtime.getManifest().version,
      sanitizeProbe:
        typeof sanitizeFindings === 'function'
          ? sanitizeFindings([{ ruleId: 'probe', match: 'X', sourceType: 'storage', sourceUrl: 'u' }], 'h')[0].sourceType
          : 'n/a',
      count: findings.length,
      rules: [...new Set(findings.map((f) => f.ruleId))],
      types: [...new Set(findings.map((f) => f.sourceType))],
      hosts: [...new Set(findings.map((f) => f.host))],
      severities: findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {}),
      items: findings.map((f) => ({ rule: f.ruleId, type: f.sourceType, redacted: f.redacted, source: f.sourceUrl })),
    });
  })()`;

  const result = await cdpEvaluate(worker.webSocketDebuggerUrl, expression);
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.text || "evaluation threw");
  }
  return JSON.parse(result.result.value);
}

let failures = 0;
function check(name, condition, detail = "") {
  if (condition) console.log(`PASS  ${name}`);
  else {
    failures++;
    console.log(`FAIL  ${name}${detail ? `  (${detail})` : ""}`);
  }
}

async function main() {
  const browserPath = findBrowser();
  if (!browserPath) {
    console.log("SKIP  no Chromium-family browser found");
    process.exit(0);
  }
  console.log(`Using ${browserPath}`);

  PORT = await freePort();
  CDP_PORT = await freePort();
  const server = await startServer();
  const args = [
    "--headless=new",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    `--user-data-dir=${PROFILE}`,
    `--disable-extensions-except=${ROOT}`,
    `--load-extension=${ROOT}`,
    `--remote-debugging-port=${CDP_PORT}`,
    "--remote-allow-origins=*",
    "--window-size=1280,900",
    `http://127.0.0.1:${PORT}/`,
  ];

  // detached → own process group, so the whole browser tree can be killed.
  const browser = spawn(browserPath, args, {
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  let stopped = false;
  const stopBrowser = () => {
    if (stopped) return;
    stopped = true;
    try {
      process.kill(-browser.pid, "SIGKILL");
    } catch (_) {
      try {
        browser.kill("SIGKILL");
      } catch (_) {
        /* already gone */
      }
    }
  };
  process.once("exit", stopBrowser);
  let stderr = "";
  browser.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
    if (stderr.length > 20000) stderr = stderr.slice(-20000);
  });

  // Brave-style builds open their own start page instead of the URL argument,
  // so drive navigation explicitly.
  const demoUrl = `http://127.0.0.1:${PORT}/`;
  const pageTarget = await waitForTarget(
    (t) => t.type === "page" && Boolean(t.webSocketDebuggerUrl),
    15000
  );
  if (!pageTarget) {
    console.log("FAIL  no page target exposed over CDP");
    console.log(stderr.slice(-4000));
    stopBrowser();
    server.close();
    process.exit(1);
  }
  try {
    await cdpSend(pageTarget.webSocketDebuggerUrl, "Page.navigate", { url: demoUrl });
  } catch (err) {
    console.log(`WARN  page navigation failed: ${String(err)}`);
  }

  let data = null;
  let lastError = null;
  const deadline = Date.now() + 25000;

  while (Date.now() < deadline) {
    await sleep(1000);
    try {
      data = await readStorage();
      lastError = null;
      if (data && data.count >= 9) break;
    } catch (err) {
      lastError = err;
    }
  }

  if (!data || data.count === 0) {
    try {
      const state = await cdpEvaluate(
        pageTarget.webSocketDebuggerUrl,
        `JSON.stringify({ url: location.href, title: document.title, scripts: document.scripts.length, store: localStorage.getItem('demoConfig'), api: Boolean(window.__demoApi) })`
      );
      console.log(`Page state: ${state.result.value}`);
    } catch (_) {
      /* diagnostics only */
    }
  } else {
    try {
      const state = await cdpEvaluate(
        pageTarget.webSocketDebuggerUrl,
        `JSON.stringify({ url: location.href, store: localStorage.getItem('demoConfig'), api: Boolean(window.__demoApi) })`
      );
      console.log(`Page state: ${state.result.value}`);
    } catch (_) {
      /* diagnostics only */
    }
  }

  if (!data) {
    console.log("FAIL  extension storage unreadable");
    console.log(lastError ? String(lastError) : "no service-worker target found");
    console.log(stderr.slice(-4000));
    failures++;
  } else {
    console.log(`Extension ${data.extensionId}: ${data.count} finding(s)`);
    console.log(`  worker v${data.version}, sanitizeProbe=${data.sanitizeProbe}`);
    console.log(`  rules: ${data.rules.join(", ")}`);
    console.log(`  types: ${data.types.join(", ")}`);
    console.log(`  hosts: ${data.hosts.join(", ")}`);
    console.log(`  severities: ${JSON.stringify(data.severities)}`);
    for (const item of data.items || []) {
      console.log(`    - ${item.rule} [${item.type}] ${item.redacted}  ${item.source}`);
    }

    check("demo produces the expected 9 findings", data.count === 9, `got ${data.count}`);
    for (const type of ["html", "js", "xhr", "storage"]) {
      check(`findings from ${type}`, data.types.includes(type), data.types.join(","));
    }
    for (const rule of [
      "aws-access-key-id",
      "aws-secret-access-key",
      "stripe-secret-key",
      "db-uri",
      "jwt",
      "generic-secret",
    ]) {
      check(`rule ${rule} fired`, data.rules.includes(rule), data.rules.join(","));
    }
    check("all findings attributed to the demo host", data.hosts.length === 1 && data.hosts[0] === "127.0.0.1", data.hosts.join(","));
    check("no source-map finding for a map-less bundle", !data.rules.includes("source-map-exposed"));

    // Popup smoke check: open the popup page as a tab and count rendered cards.
    try {
      const popupUrl = `chrome-extension://${data.extensionId}/popup.html`;
      await openTab(popupUrl);
      const popupTarget = await waitForTarget(
        (t) => t.type === "page" && String(t.url || "").includes("/popup.html"),
        8000
      );
      if (!popupTarget) throw new Error("popup tab did not open");
      await sleep(1500);
      const rendered = await cdpEvaluate(
        popupTarget.webSocketDebuggerUrl,
        `JSON.stringify({ cards: document.querySelectorAll('.finding').length, stats: (document.getElementById('stats') || {}).textContent || '' })`
      );
      const parsed = JSON.parse(rendered.result.value);
      check("popup renders all findings", parsed.cards === 9, `cards=${parsed.cards}`);
      check("popup shows populated stats", /9 findings/.test(parsed.stats), parsed.stats);
    } catch (err) {
      failures++;
      console.log(`FAIL  popup smoke: ${String(err)}`);
    }
  }

  stopBrowser();
  server.close();
  await sleep(300);
  fs.rmSync(PROFILE, { recursive: true, force: true });

  console.log(failures === 0 ? "\nBrowser smoke test passed." : `\n${failures} browser check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  try {
    fs.rmSync(PROFILE, { recursive: true, force: true });
  } catch (_) {
    /* noop */
  }
  process.exit(1);
});
