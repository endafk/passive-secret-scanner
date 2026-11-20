/*
 * Text scanner. Runs synchronously in the content script (page HTML) and in
 * the service worker (fetched JS / source maps). Returns at most 100 findings
 * per source, deduped by rule + value.
 */
(function () {
  const PLACEHOLDER_RE =
    /(?:example|sample|placeholder|dummy|change[_-]?me|your[_-]?(?:api|key|token|secret|password|pass)|redacted|xx{3,}|lorem|ipsum|foo[_-]?bar|abc123)/i;

  function maskMatch(value) {
    const v = String(value);
    if (v.length <= 8) return '*'.repeat(v.length);
    const keep = Math.min(4, Math.floor(v.length / 4));
    const mid = Math.min(12, Math.max(3, v.length - keep * 2));
    return v.slice(0, keep) + '*'.repeat(mid) + v.slice(-keep);
  }

  function newlinePositions(text) {
    const positions = [];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) positions.push(i);
    }
    return positions;
  }

  function lineOf(positions, index) {
    let lo = 0;
    let hi = positions.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (positions[mid] < index) lo = mid + 1;
      else hi = mid;
    }
    return lo + 1;
  }

  function decodeBase64Url(value) {
    if (typeof atob !== 'function') return '';
    const s = String(value).replace(/-/g, '+').replace(/_/g, '/');
    const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    try {
      return new TextDecoder('utf-8').decode(bytes);
    } catch (_) {
      return '';
    }
  }

  function jwtSeverity(value) {
    const parts = String(value).split('.');
    if (parts.length !== 3) return 'medium';

    let header = null;
    let payload = null;
    try {
      header = JSON.parse(decodeBase64Url(parts[0]));
    } catch (_) {
      /* not a decodable header */
    }
    try {
      payload = JSON.parse(decodeBase64Url(parts[1]));
    } catch (_) {
      /* not a decodable payload */
    }

    if (header && String(header.alg || '').toLowerCase() === 'none') return 'critical';
    if (!payload || typeof payload !== 'object') return 'medium';

    const fields = [];
    for (const key of ['role', 'roles', 'admin', 'is_admin', 'isAdmin', 'superuser', 'scope', 'scopes', 'permissions']) {
      if (key in payload) fields.push(JSON.stringify(payload[key]));
    }
    if (
      payload.admin === true ||
      payload.is_admin === true ||
      payload.isAdmin === true ||
      payload.superuser === true
    ) {
      return 'high';
    }
    if (/(?:^|[^a-z])(admin|superuser|root)(?:[^a-z]|$)/.test(fields.join(' ').toLowerCase())) {
      return 'high';
    }
    return 'medium';
  }

  /*
   * Severity is graded by meaning, not just rule id: live keys beat test keys,
   * signing secrets beat random assignments, and admin or unsigned JWTs are
   * worse than an ordinary token.
   */
  function adjustSeverity(rule, value, raw) {
    if (rule.id === 'stripe-secret-key') {
      if (/_live_/i.test(value)) return 'critical';
      if (/_test_/i.test(value)) return 'low';
    }

    if (rule.id === 'jwt') return jwtSeverity(value);

    if (rule.id === 'generic-secret') {
      const name = String(raw).split(/[:=]/)[0].toLowerCase();
      const long = value.length >= 64;
      if (/(secret|private|signing|encryption|hmac|master)/.test(name)) {
        return long ? 'critical' : 'high';
      }
      if (/client[_-]?secret/.test(name) || /admin[_-]?key/.test(name)) {
        return long ? 'critical' : 'high';
      }
      if (/(password|passwd|pwd)/.test(name)) {
        return value.length >= 20 ? 'high' : 'medium';
      }
    }

    return rule.severity;
  }

  function scanText(text, opts) {
    const out = [];
    if (typeof text !== 'string' || text.length === 0) return out;
    const options = opts || {};
    const rules = (self.PSS && self.PSS.rules) || [];
    const entropyOf = self.PSS.shannonEntropy;
    const lower = text.toLowerCase();
    const seenValues = new Set();
    let newlines = null;

    for (const rule of rules) {
      const re = rule.regex;
      re.lastIndex = 0;
      let m;
      let ruleHits = 0;

      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex += 1;
          continue;
        }

        const raw = m[0];
        const value = (rule.group && m[rule.group]) || raw;
        if (!value) continue;

        if (rule.deny && rule.deny.some((d) => d.test(raw) || d.test(value))) continue;

        if (rule.allowPlaceholders !== false) {
          let placeholderValue = value;
          if (rule.placeholderTarget === 'credential') {
            const userinfo = /:\/\/([^@]*)@/.exec(raw);
            if (userinfo) placeholderValue = userinfo[1];
          }
          if (PLACEHOLDER_RE.test(placeholderValue)) continue;
        }

        if (rule.entropy && entropyOf(value) < rule.entropy) continue;

        if (rule.keywords) {
          const from = Math.max(0, m.index - 160);
          const to = Math.min(text.length, m.index + raw.length + 160);
          const windowText = lower.slice(from, to);
          if (!rule.keywords.some((k) => windowText.includes(k))) continue;
        }

        // A bare blob needs letters and digits. This drops long enum names,
        // prose constants, and other word-like strings.
        if (rule.id === 'contextual-blob') {
          if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) continue;
        }

        const key = value;
        if (seenValues.has(key)) continue;
        seenValues.add(key);

        if (!newlines) newlines = newlinePositions(text);

        const start = Math.max(0, m.index - 80);
        const end = Math.min(text.length, m.index + raw.length + 80);
        const redacted = maskMatch(value);
        const snippet = (text.slice(start, m.index) + redacted + text.slice(m.index + raw.length, end))
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 240);

        out.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: adjustSeverity(rule, value, raw),
          match: String(value),
          redacted,
          snippet,
          line: lineOf(newlines, m.index),
          sourceType: options.sourceType || 'html',
          sourceUrl: options.sourceUrl || '',
          pageUrl: options.pageUrl || '',
          host: options.host || '',
        });

        ruleHits++;
        if (ruleHits >= 50 || out.length >= 100) break;
      }
      if (out.length >= 100) break;
    }

    return out;
  }

  self.PSS = self.PSS || {};
  self.PSS.scanText = scanText;
  self.PSS.maskMatch = maskMatch;
})();
