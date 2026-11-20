/* Popup UI. Everything from the page is rendered with textContent. */

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const FILTER_LIMITS = { all: 3, medium: 2, high: 1, critical: 0 };
const SOURCE_LABELS = {
  html: 'HTML',
  inline: 'INLINE',
  js: 'JS',
  map: 'MAP',
  xhr: 'API',
  storage: 'STORE',
  cookie: 'COOKIE',
  idb: 'IDB',
  url: 'URL',
};

let allFindings = [];
let currentHost = '';
let thisSiteOnly = true;

init();

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && /^https?:/i.test(tab.url || '')) {
      currentHost = new URL(tab.url).hostname.toLowerCase();
    }
  } catch (_) {
    currentHost = '';
  }

  if (!currentHost) {
    thisSiteOnly = false;
    document.getElementById('thisSite').checked = false;
  }

  const data = await chrome.storage.local.get({ findings: [], settings: {} });
  allFindings = Array.isArray(data.findings) ? data.findings : [];

  if (data.settings && data.settings.enabled === false) {
    const slot = document.getElementById('banner-slot');
    const banner = document.createElement('div');
    banner.className = 'banner';
    banner.textContent = 'Scanning is disabled. Enable it in Settings (⚙).';
    slot.append(banner);
  }

  document.getElementById('thisSite').addEventListener('change', (event) => {
    thisSiteOnly = event.target.checked;
    render();
  });
  document.getElementById('search').addEventListener('input', render);
  document.getElementById('severity').addEventListener('change', render);
  document.getElementById('options').addEventListener('click', () => chrome.runtime.openOptionsPage());
  document.getElementById('export').addEventListener('click', exportJson);
  document.getElementById('clear').addEventListener('click', clearAll);

  render();
}

function visibleFindings() {
  const query = document.getElementById('search').value.trim().toLowerCase();
  const limit = FILTER_LIMITS[document.getElementById('severity').value] ?? 3;
  let items = allFindings.filter((f) => (SEVERITY_RANK[f.severity] ?? 9) <= limit);

  if (thisSiteOnly && currentHost) {
    items = items.filter((f) => f.host === currentHost);
  }
  if (query) {
    items = items.filter((f) =>
      [f.ruleName, f.host, f.sourceUrl, f.sourceType, f.snippet]
        .join(' ')
        .toLowerCase()
        .includes(query)
    );
  }
  items.sort((a, b) => {
    const rank = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    return rank !== 0 ? rank : (b.time || 0) - (a.time || 0);
  });
  return items;
}

function render() {
  const items = visibleFindings();
  renderStats(items);

  const list = document.getElementById('list');
  list.textContent = '';

  if (items.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    const strong = document.createElement('strong');
    strong.textContent = thisSiteOnly
      ? currentHost
        ? 'No findings on this site'
        : 'No findings yet'
      : 'No findings yet';
    const text = document.createElement('span');
    text.textContent = thisSiteOnly && currentHost
      ? 'Browse pages on this host. The scanner reports what the browser already loaded.'
      : 'Visit sites with the extension enabled. Detections appear here as you browse.';
    empty.append(strong, text);
    list.append(empty);
    return;
  }

  for (const finding of items) {
    list.append(renderFinding(finding));
  }
}

function renderStats(items) {
  const stats = document.getElementById('stats');
  stats.textContent = '';

  const total = document.createElement('span');
  total.className = 'pill';
  total.textContent = `${items.length} finding${items.length === 1 ? '' : 's'}`;
  stats.append(total);

  const highPlus = items.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  if (highPlus > 0) {
    const alert = document.createElement('span');
    alert.className = 'pill alert';
    alert.textContent = `${highPlus} high+`;
    stats.append(alert);
  }

  if (thisSiteOnly && currentHost) {
    const hostPill = document.createElement('span');
    hostPill.className = 'pill';
    hostPill.textContent = currentHost;
    stats.append(hostPill);
  }
}

function renderFinding(finding) {
  const card = document.createElement('article');
  card.className = 'finding';

  const head = document.createElement('div');
  head.className = 'finding-head';

  const severity = document.createElement('span');
  severity.className = `sev ${finding.severity || 'medium'}`;
  severity.textContent = finding.severity || 'medium';

  const rule = document.createElement('span');
  rule.className = 'rule';
  rule.textContent = finding.ruleName || finding.ruleId;

  const type = document.createElement('span');
  type.className = 'chip';
  type.textContent = SOURCE_LABELS[finding.sourceType] || String(finding.sourceType || '').toUpperCase();

  head.append(severity, rule, type);

  if (!thisSiteOnly && finding.host) {
    const hostChip = document.createElement('span');
    hostChip.className = 'chip';
    hostChip.textContent = finding.host;
    head.append(hostChip);
  }

  const meta = document.createElement('div');
  meta.className = 'meta';
  const sourcePath = describeSource(finding);
  meta.textContent = `${sourcePath}${finding.line ? ` · line ${finding.line}` : ''}`;
  meta.title = finding.sourceUrl || finding.pageUrl || '';

  const snippet = document.createElement('pre');
  snippet.className = 'snippet';
  snippet.textContent = finding.snippet || finding.redacted || '';

  const secret = document.createElement('pre');
  secret.className = 'secret';
  secret.hidden = true;
  secret.textContent = finding.match || '';

  const actions = document.createElement('div');
  actions.className = 'card-actions';

  const reveal = document.createElement('button');
  reveal.className = 'btn small';
  reveal.textContent = 'Show secret';
  reveal.addEventListener('click', () => {
    secret.hidden = !secret.hidden;
    reveal.textContent = secret.hidden ? 'Show secret' : 'Hide secret';
  });

  const copy = document.createElement('button');
  copy.className = 'btn small';
  copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(finding.match || '');
      copy.textContent = 'Copied';
      setTimeout(() => {
        copy.textContent = 'Copy';
      }, 1200);
    } catch (_) {
      copy.textContent = 'Copy failed';
    }
  });

  const open = document.createElement('button');
  open.className = 'btn small';
  open.textContent = 'Open source';
  open.addEventListener('click', () => {
    const url = finding.sourceUrl || finding.pageUrl;
    if (url) {
      chrome.tabs.create({ url });
      window.close();
    }
  });

  const dismiss = document.createElement('button');
  dismiss.className = 'btn small danger';
  dismiss.textContent = 'Dismiss';
  dismiss.title = 'Remove this finding and ignore this value on this host in future scans';
  dismiss.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'dismiss-finding', id: finding.id }, (result) => {
      if (result && result.ok) {
        allFindings = allFindings.filter((f) => f.id !== finding.id);
        render();
      }
    });
  });

  actions.append(reveal, copy, open, dismiss);
  card.append(head, meta, snippet, secret, actions);
  return card;
}

function describeSource(finding) {
  const url = finding.sourceUrl || finding.pageUrl || '';
  if (!url) return finding.host || 'unknown source';
  try {
    const parsed = new URL(url);
    const path = parsed.pathname + parsed.search;
    return parsed.hostname + (path.length > 64 ? path.slice(0, 64) + '…' : path);
  } catch (_) {
    return url.slice(0, 80);
  }
}

function exportJson() {
  if (allFindings.length === 0) return;
  const payload = {
    exportedAt: new Date().toISOString(),
    tool: 'Passive Secret Scanner',
    count: allFindings.length,
    note: 'Contains unredacted secrets. Store this file accordingly.',
    findings: allFindings,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const anchor = document.createElement('a');
  anchor.href = URL.createObjectURL(blob);
  anchor.download = `passive-secrets-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(anchor.href), 5000);
}

let clearArmed = false;
let clearTimer = null;

function clearAll() {
  const button = document.getElementById('clear');
  if (!clearArmed) {
    clearArmed = true;
    button.textContent = 'Confirm clear';
    clearTimer = setTimeout(() => {
      clearArmed = false;
      button.textContent = 'Clear all';
    }, 4000);
    return;
  }

  clearTimeout(clearTimer);
  clearArmed = false;
  button.textContent = 'Clear all';
  chrome.runtime.sendMessage({ type: 'clear-all' }, () => {
    allFindings = [];
    render();
  });
}
