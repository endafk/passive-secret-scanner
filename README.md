# Passive Secret Scanner

I built this for my own pentests. It watches pages as you browse and logs
secrets that leak into them: HTML, JavaScript, source maps, API responses,
storage, cookies, and the page URL.

Everything stays on your machine. No server, no analytics, no sync.

Only use it on systems you have permission to test.

## Install

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Click "Load unpacked" and choose this folder.
4. Pin it and start browsing.

Chrome 111 or newer.

## Quick demo

```sh
cd demo && python3 -m http.server 8080
```

Open http://localhost:8080/ and click the extension. You should get nine
findings: five from the HTML, two from app.js, one API response, one storage
entry. The placeholder values get ignored.

## What it looks at

- Served HTML, inline scripts, `data-api-key` attributes
- External JS and source maps, inline maps included
- Lazy route chunks listed in the webpack runtime, even on other routes
- JSON and text API responses the page already fetched
- localStorage, sessionStorage, non-HttpOnly cookies, IndexedDB
- The page URL, including query strings and fragments
- Scripts SPAs add after first paint, plus route changes

There are 37 rules. AWS, Azure, GitHub, GitLab, Stripe, Slack, SendGrid,
OpenAI, Anthropic, Google, database URIs, connection strings, private keys,
JWTs, generic assignments, and a bare high-entropy blob rule.

## Why it is passive

Re-fetches normally touch only scripts the page already loaded. Once per URL,
mostly cache hits. API bodies are read inside the page's own context.

Lazy chunk discovery is on by default. When the webpack runtime lists route
bundles, the scanner fetches them and their source maps, even when the current
page never loaded them. Turn it off in Settings if you want strictly loaded
assets.

One opt-in exception: you can let re-fetches send cookies so auth-gated bundles
get scanned. Those requests are attributable to you, so it is off by default.

## Working with findings

Filter by severity in the popup. Dismiss a false positive and it stays gone on
that host. Notifications have a minimum severity and a five-minute per-host
cooldown. Export JSON for reports. Exports are unredacted, so treat them like
engagement data.

## How severity works

Not every match is equal.

- Live Stripe keys are critical. Test keys are low.
- Long signing secrets (secret, private, signing, HMAC) are critical.
- A JWT with `alg: none` is critical. Admin claims are high.
- A bare high-entropy string near crypto or auth code is high.
- If the same value shows up in a bundle and later in its source map, the
  better context upgrades the finding.

## Scope

Turn on "only scan in-scope hosts" and add lines like `example.com` or
`*.client.com`. An empty list means everything.

## Honest limits

- Auth-gated JS returns 401 unless you enable the cookie option.
- No WebSocket or SSE bodies. No requests from workers.
- Source maps above 16 MB are flagged but not scanned.
- A page can notice the wrapped fetch/XHR and can post fake messages. Treat
  findings as leads, not proof.
- Passive can prove exposure, not that a key still works. Verification and
  active probes are the next level. Neither is included yet.
- Regex rules need tuning. Start with `lib/rules.js`.

## Tests

```sh
node tools/test-scan.js
node tools/test-background.js
node tools/browser-test.js
```

The last one launches Brave or Chromium headless, loads the unpacked extension,
and checks findings end to end. No Playwright needed.

## License and privacy

MIT. See LICENSE.

Nothing leaves your browser. See PRIVACY.md.
