/* Options page controller. */

const DEFAULTS = {
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

const CHECKBOXES = [
  'enabled',
  'scanHtml',
  'scanExternalJs',
  'scanSourceMaps',
  'scanLazyChunks',
  'scanApiResponses',
  'scanStorage',
  'fetchWithCredentials',
  'notifications',
  'onlyInScope',
];

const form = document.getElementById('settings-form');
const statusEl = document.getElementById('status');

init();

async function init() {
  const data = await chrome.storage.local.get({ settings: DEFAULTS });
  const settings = { ...DEFAULTS, ...(data.settings || {}) };

  for (const id of CHECKBOXES) {
    document.getElementById(id).checked = settings[id] !== false;
  }
  document.getElementById('scope').value = Array.isArray(settings.scope)
    ? settings.scope.join('\n')
    : '';
  document.getElementById('notifyMinSeverity').value = settings.notifyMinSeverity || 'medium';

  form.addEventListener('submit', save);
}

async function save(event) {
  event.preventDefault();

  const settings = { ...DEFAULTS };
  for (const id of CHECKBOXES) {
    settings[id] = document.getElementById(id).checked;
  }
  settings.scope = document
    .getElementById('scope')
    .value.split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 200);
  settings.notifyMinSeverity = document.getElementById('notifyMinSeverity').value;

  await chrome.storage.local.set({ settings });
  statusEl.textContent = 'Saved.';
  setTimeout(() => {
    statusEl.textContent = '';
  }, 1800);
}
