# Privacy

Short version: nothing leaves your browser.

- No analytics, no telemetry, no accounts.
- Page content is scanned inside your browser. Findings are stored in
  `chrome.storage.local`.
- Storage, cookies, and IndexedDB values are read locally, on the current
  origin only.
- Findings can contain real secrets. Exports are unredacted. Delete them when
  you are done.
- The optional cookie re-fetch toggle sends your cookie header to the same
  script URLs the page already loaded. It is off by default.
- No remote code. Everything ships in the extension package.

Contact: https://github.com/endafk/passive-secret-scanner/issues
