# Store notes

Listing text and permission justifications for the Chrome Web Store.

## Name
Passive Secret Scanner

## Category
Developer Tools

## Short description
Finds secrets, keys, and credentials in page source and JavaScript while you browse.

## Detailed description
Passive recon for authorized security testing. The extension scans the HTML,
JavaScript, source maps, lazy route chunks, API responses, storage, cookies, and
IndexedDB, then keeps a local log you can filter and export.

No servers. No analytics. Nothing leaves the browser.

Use only on systems you have permission to test.

## Permissions
- `host_permissions` (http/https): reads page source and fetches the scripts the
  page already loaded.
- `storage`: keeps findings and settings in `chrome.storage.local`.
- `notifications`: alerts when a new finding appears.
- `webNavigation`: rescans after single-page-app route changes.
- `activeTab`: reads the current tab URL when the popup opens.

## Data use
No data is collected, sold, or transmitted. Scans and findings stay local.
Privacy policy: PRIVACY.md in the source repo.

## Assets
- Icon 128x128: icons/icon128.png
- Screenshots: still needed, 1280x800 or 640x400.
