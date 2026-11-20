#!/usr/bin/env node
/*
 * Background-worker integration harness.
 *
 * Loads the real background.js in a VM with stubbed Chrome APIs and a fake
 * network, then drives the message pipeline end to end:
 *   page intake → JS re-fetch → source map → API body → dismiss → scope → clear
 *
 * Run: node tools/test-background.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { webcrypto } = require("node:crypto");

const root = path.join(__dirname, "..");
const storage = {};
const messageListeners = [];
const changeListeners = [];
const notifications = [];
const badges = {};
const fetchCalls = [];
const longHex = Array.from({ length: 256 }, (_, i) => (i % 16).toString(16)).join("");

const chromeStub = {
  storage: {
    local: {
      async get(defaults) {
        const out = {};
        for (const key of Object.keys(defaults)) {
          out[key] = key in storage ? storage[key] : defaults[key];
        }
        return out;
      },
      async set(values) {
        Object.assign(storage, values);
      },
    },
    onChanged: {
      addListener(fn) {
        changeListeners.push(fn);
      },
    },
  },
  runtime: {
    onMessage: {
      addListener(fn) {
        messageListeners.push(fn);
      },
    },
    getURL(p) {
      return `chrome-extension://test/${p}`;
    },
  },
  action: {
    async setBadgeBackgroundColor() {},
    async setBadgeText(opts) {
      badges[opts.tabId ?? "global"] = opts.text;
    },
  },
  notifications: {
    create(id, options) {
      notifications.push({ id, options });
      return Promise.resolve(id);
    },
  },
  tabs: {
    sendMessage() {
      return Promise.resolve();
    },
    onUpdated: { addListener() {} },
  },
  webNavigation: {
    onHistoryStateUpdated: { addListener() {} },
  },
};

function fakeFetch(url) {
  fetchCalls.push(url);
  if (url.endsWith("/app.js")) {
    return Promise.resolve(
      new Response('const k = "sk_live_51H8xQ2eZvKYlo2CxAbCdEfGh";\n//# sourceMappingURL=app.js.map', {
        status: 200,
        headers: { "content-type": "application/javascript" },
      })
    );
  }
  if (url.endsWith("/app.js.map")) {
    return Promise.resolve(
      new Response(
        JSON.stringify({ version: 3, sourcesContent: ['const k = "AKIAZ7Q2XJ5V4R3T2W1Y";'] }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    );
  }
  if (url.endsWith("/broken.js")) {
    return Promise.resolve(
      new Response("const x = 1;\n//# sourceMappingURL=broken.js.map", {
        status: 200,
        headers: { "content-type": "application/javascript" },
      })
    );
  }
  if (url.endsWith("/broken.js.map")) {
    return Promise.resolve(new Response("", { status: 404 }));
  }
  if (url.endsWith("/upgrade.js")) {
    return Promise.resolve(
      new Response(`CryptoJS.HmacSHA256(t, "${longHex}");\n//# sourceMappingURL=upgrade.js.map`, {
        status: 200,
        headers: { "content-type": "application/javascript" },
      })
    );
  }
  if (url.endsWith("/upgrade.js.map")) {
    return Promise.resolve(
      new Response(
        JSON.stringify({
          version: 3,
          sourcesContent: [`const SECRET_KEY =\n  '${longHex}';`],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    );
  }
  return Promise.resolve(new Response("", { status: 404 }));
}

const context = vm.createContext({
  self: {},
  console,
  chrome: chromeStub,
  crypto: webcrypto,
  fetch: fakeFetch,
  Response,
  TextDecoder,
  TextEncoder,
  AbortController,
  URL,
  atob,
  btoa,
  setTimeout,
  clearTimeout,
});

function loadScript(relPath) {
  const source = fs.readFileSync(path.join(root, relPath), "utf8");
  vm.runInContext(source, context, { filename: relPath });
}

loadScript("lib/entropy.js");
loadScript("lib/rules.js");
loadScript("lib/scan.js");

context.importScripts = (...files) => files.forEach(loadScript);
loadScript("background.js");

const sendMessage = (msg, sender = { tab: { id: 1 } }) =>
  new Promise((resolve) => {
    let settled = false;
    let keepOpen = false;
    const done = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    for (const listener of messageListeners) {
      if (listener(msg, sender, done) === true) keepOpen = true;
    }
    if (!keepOpen) done(undefined);
  });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let failures = 0;
function check(name, condition, detail = "") {
  if (condition) {
    console.log(`PASS  ${name}`);
  } else {
    failures++;
    console.log(`FAIL  ${name}${detail ? `  (${detail})` : ""}`);
  }
}

const htmlFinding = {
  ruleId: "generic-secret",
  ruleName: "Generic secret assignment",
  severity: "medium",
  match: "Zx8Qw2Er5Ty9Ui3Op7As",
  redacted: "Zx8Q****p7As",
  snippet: 'data-api-key="Zx8Q****p7As"',
  line: 12,
  sourceType: "html",
  sourceUrl: "http://test.local/",
  pageUrl: "http://test.local/",
  host: "test.local",
};

const storageFinding = {
  ruleId: "generic-secret",
  ruleName: "Generic secret assignment",
  severity: "medium",
  match: "Nq7Rt2Wx9Zc4Vb8Ml3Kp",
  redacted: "Nq7R****3Kp",
  snippet: 'apiKey":"Nq7R****3Kp"',
  line: 0,
  sourceType: "storage",
  sourceUrl: "http://test.local#storage:localStorage:demoConfig",
  pageUrl: "http://test.local/",
  host: "test.local",
};

async function run() {
  await sleep(60); // let settings/store promises settle

  const chunkText =
    'n.u=function(e){return"static/js/"+e+"."+{13:"c837f840",36:"1bda3a00",844:"3e0cb438"}[e]+".chunk.js"}';
  const discovered = JSON.parse(
    vm.runInContext(
      `JSON.stringify(Array.from(discoverChunkUrls(${JSON.stringify(
        chunkText
      )}, "https://app.test/static/js/main.e1fa5173.js")))`,
      context
    )
  );
  check(
    "webpack chunk map parsed",
    discovered.length === 3 && discovered.includes("https://app.test/static/js/36.1bda3a00.chunk.js"),
    discovered.join(",")
  );

  await sendMessage({
    type: "page-scan",
    pageUrl: "http://test.local/",
    host: "test.local",
    findings: [htmlFinding, storageFinding],
    scripts: ["http://test.local/app.js"],
  });
  await sleep(1400); // fetch queue: app.js, then its map

  const findings = storage.findings || [];
  const ruleIds = findings.map((f) => f.ruleId);
  check("page finding stored", ruleIds.includes("generic-secret"), JSON.stringify(ruleIds));
  check(
    "storage finding keeps its type",
    findings.some((f) => f.sourceType === "storage"),
    JSON.stringify(findings.map((f) => f.sourceType))
  );
  check("JS finding stored", ruleIds.includes("stripe-secret-key"), JSON.stringify(ruleIds));
  check("source map finding stored", ruleIds.includes("aws-access-key-id"), JSON.stringify(ruleIds));
  check("source-map-exposed note stored", ruleIds.includes("source-map-exposed"), JSON.stringify(ruleIds));
  check("JS fetched once", fetchCalls.filter((u) => u === "http://test.local/app.js").length === 1);
  check("badge reflects host findings", badges[1] === String(storage.findings.length), `badge=${badges[1]}`);
  check("notification raised", notifications.length === 1, `count=${notifications.length}`);

  const countBefore = storage.findings.length;
  await sendMessage({
    type: "page-scan",
    pageUrl: "http://test.local/",
    host: "test.local",
    findings: [htmlFinding, storageFinding],
    scripts: ["http://test.local/app.js"],
  });
  await sleep(500);
  check("repeat page scan is deduped", storage.findings.length === countBefore, `${storage.findings.length} vs ${countBefore}`);
  check("JS not re-fetched", fetchCalls.filter((u) => u === "http://test.local/app.js").length === 1);

  await sendMessage({
    type: "page-scan",
    pageUrl: "http://test.local/",
    host: "test.local",
    findings: [],
    scripts: ["http://test.local/broken.js"],
  });
  await sleep(1000);
  check(
    "map flagged even when the fetch fails",
    (storage.findings || []).some(
      (f) => f.ruleId === "source-map-exposed" && String(f.match).includes("broken.js.map")
    ),
    JSON.stringify((storage.findings || []).map((f) => f.ruleId))
  );

  await sendMessage({
    type: "page-scan",
    pageUrl: "http://test.local/",
    host: "test.local",
    findings: [],
    scripts: ["http://test.local/upgrade.js"],
  });
  await sleep(1600);
  const upgraded = (storage.findings || []).find((f) => f.match === longHex);
  check(
    "duplicate severity upgrades to critical",
    Boolean(upgraded) && upgraded.severity === "critical",
    upgraded ? upgraded.severity : "missing"
  );

  await sendMessage({
    type: "api-body",
    pageUrl: "http://test.local/",
    host: "test.local",
    url: "http://test.local/api/config",
    body: JSON.stringify({ apiKey: "Nq7Rt2Wx9Zc4Vb8Ml3Kp" }),
  });
  await sleep(300);
  const apiFinding = (storage.findings || []).find((f) => f.sourceType === "xhr");
  check("API body finding stored", Boolean(apiFinding), JSON.stringify((storage.findings || []).map((f) => f.sourceType)));
  check("notification throttled per host", notifications.length === 1, `count=${notifications.length}`);

  const dismissResult = await sendMessage({ type: "dismiss-finding", id: apiFinding.id });
  check("dismiss succeeds", dismissResult && dismissResult.ok === true, JSON.stringify(dismissResult));
  check("dismissed finding removed", !(storage.findings || []).some((f) => f.id === apiFinding.id));

  await sendMessage({
    type: "api-body",
    pageUrl: "http://test.local/",
    host: "test.local",
    url: "http://test.local/api/config",
    body: JSON.stringify({ note: "changed", apiKey: "Nq7Rt2Wx9Zc4Vb8Ml3Kp" }),
  });
  await sleep(300);
  check("dismissed value stays suppressed", !(storage.findings || []).some((f) => f.sourceType === "xhr"));

  // Scope: flip to in-scope-only for an unrelated host.
  for (const listener of changeListeners) {
    listener(
      { settings: { newValue: { ...(storage.settings || {}), onlyInScope: true, scope: ["other.test"] } } },
      "local"
    );
  }
  const scopedCount = (storage.findings || []).length;
  await sendMessage({
    type: "page-scan",
    pageUrl: "http://test.local/scope-check",
    host: "test.local",
    findings: [{ ...htmlFinding, match: "Mm4Nn8Pp2Qq6Rr0Ss", sourceUrl: "http://test.local/scope-check" }],
    scripts: [],
  });
  await sleep(300);
  check("out-of-scope host ignored", (storage.findings || []).length === scopedCount);

  const clearResult = await sendMessage({ type: "clear-all" });
  check("clear succeeds", clearResult && clearResult.ok === true);
  check("findings cleared", (storage.findings || []).length === 0);
  check("badge cleared", badges.global === "");

  console.log(failures === 0 ? "\nAll background checks passed." : `\n${failures} background check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
