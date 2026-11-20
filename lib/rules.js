/*
 * Secret-detection rule pack.
 *
 * Patterns target publicly documented token formats. Provider-prefixed tokens
 * are anchored exactly; generic rules rely on keyword context plus entropy to
 * keep false positives down. Rule shape:
 *
 *   id, name, severity   identification shown in the UI
 *   regex                global RegExp
 *   group                capture group holding the secret (default: whole match)
 *   entropy              minimum Shannon entropy of the extracted value
 *   keywords             at least one must appear within 160 chars of the match
 *   deny                 regexes whose match/value is ignored
 *   allowPlaceholders    default true; skip values that look like docs examples
 *   placeholderTarget    'credential' checks only the userinfo of a URI
 *
 * Rules are ordered specific → generic; the scanner dedupes the same value
 * across rules, so the first (most precise) rule wins.
 */
(function () {
  const rules = [
    {
      id: 'private-key',
      name: 'Private key block',
      severity: 'critical',
      regex: /-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY)-----/g,
      allowPlaceholders: false,
    },
    {
      id: 'azure-storage-key',
      name: 'Azure Storage account key',
      severity: 'critical',
      regex: /(?:AccountKey|account_key)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
      group: 1,
    },
    {
      id: 'aws-access-key-id',
      name: 'AWS access key ID',
      severity: 'high',
      regex: /\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z0-9]{16}\b/g,
      deny: [/\bAKIAIOSFODNN7EXAMPLE\b/],
    },
    {
      id: 'aws-secret-access-key',
      name: 'AWS secret access key',
      severity: 'critical',
      regex: /(?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key|aws_?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})["']?/gi,
      group: 1,
    },
    {
      id: 'github-token',
      name: 'GitHub token',
      severity: 'high',
      regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
    },
    {
      id: 'gitlab-token',
      name: 'GitLab token',
      severity: 'high',
      regex: /\b(?:glpat|glrt)-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
      id: 'stripe-secret-key',
      name: 'Stripe secret/restricted key',
      severity: 'high',
      regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    },
    {
      id: 'stripe-webhook-secret',
      name: 'Stripe webhook signing secret',
      severity: 'high',
      regex: /\bwhsec_[A-Za-z0-9]{20,}\b/g,
    },
    {
      id: 'slack-token',
      name: 'Slack token',
      severity: 'high',
      regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
    },
    {
      id: 'slack-app-token',
      name: 'Slack app-level token',
      severity: 'high',
      regex: /\bxapp-[0-9]-[A-Z0-9]{6,}-[0-9]{6,}-[a-f0-9]{20,}\b/g,
    },
    {
      id: 'slack-webhook',
      name: 'Slack incoming webhook',
      severity: 'high',
      regex: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g,
    },
    {
      id: 'discord-webhook',
      name: 'Discord webhook',
      severity: 'high',
      regex: /\bhttps:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d{15,25}\/[A-Za-z0-9_-]{40,}/g,
    },
    {
      id: 'google-api-key',
      name: 'Google API key',
      severity: 'low',
      regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    },
    {
      id: 'jwt',
      name: 'JSON Web Token',
      severity: 'medium',
      regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g,
    },
    {
      id: 'npm-token',
      name: 'npm access token',
      severity: 'high',
      regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    },
    {
      id: 'pypi-token',
      name: 'PyPI upload token',
      severity: 'high',
      regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g,
    },
    {
      id: 'sendgrid-key',
      name: 'SendGrid API key',
      severity: 'high',
      regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    },
    {
      id: 'twilio-api-key',
      name: 'Twilio API key',
      severity: 'medium',
      regex: /\bSK[0-9a-f]{32}\b/g,
      keywords: ['twilio'],
    },
    {
      id: 'openai-key',
      name: 'OpenAI API key',
      severity: 'high',
      regex: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g,
    },
    {
      id: 'anthropic-key',
      name: 'Anthropic API key',
      severity: 'high',
      regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
      id: 'huggingface-token',
      name: 'Hugging Face token',
      severity: 'high',
      regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    },
    {
      id: 'mapbox-secret',
      name: 'Mapbox secret token',
      severity: 'high',
      regex: /\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    },
    {
      id: 'digitalocean-token',
      name: 'DigitalOcean token',
      severity: 'high',
      regex: /\bdop_v1_[a-f0-9]{64}\b/g,
    },
    {
      id: 'shopify-token',
      name: 'Shopify access token',
      severity: 'high',
      regex: /\bshpat_[a-fA-F0-9]{32}\b/g,
    },
    {
      id: 'google-oauth-client-secret',
      name: 'Google OAuth client secret',
      severity: 'high',
      regex: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g,
    },
    {
      id: 'telegram-bot-token',
      name: 'Telegram bot token',
      severity: 'high',
      regex: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
    },
    {
      id: 'datadog-key',
      name: 'Datadog API/app key',
      severity: 'medium',
      regex: /\b[0-9a-f]{32}\b/g,
      keywords: ['datadog', 'dd_api_key', 'dd_app_key'],
    },
    {
      id: 'mailgun-key',
      name: 'Mailgun API key',
      severity: 'medium',
      regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
      keywords: ['mailgun'],
    },
    {
      id: 'db-uri',
      name: 'Database URI with credentials',
      severity: 'critical',
      regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/"']+:[^\s@/"']+@[^\s"']+/gi,
      // The hostname often contains "example" in docs; judge only the userinfo.
      placeholderTarget: 'credential',
    },
    {
      id: 'url-basic-auth',
      name: 'Credentials in URL (basic auth)',
      severity: 'high',
      regex: /\bhttps?:\/\/[^\s:@/"'<>]+:[^\s@/"'<>]+@[^\s"'<>]+/gi,
      placeholderTarget: 'credential',
    },
    {
      id: 'azure-sas-token',
      name: 'Azure SAS token URL',
      severity: 'medium',
      regex: /\bhttps?:\/\/[^\s"'<>]+\?[^\s"'<>]*\bsig=[A-Za-z0-9%]{30,}/g,
    },
    {
      id: 'mssql-connection-string',
      name: 'SQL Server connection string with password',
      severity: 'critical',
      regex: /(?:Data Source|Server)\s*=\s*[^"'\n]{0,300}?(?:Password|Pwd)\s*=\s*([^;"'\s]{6,})/gi,
      group: 1,
    },
    {
      id: 'bearer-token',
      name: 'Bearer token',
      severity: 'medium',
      regex: /\b[Bb]earer\s+([A-Za-z0-9\-._~+/]{24,}=*)/g,
      group: 1,
      entropy: 3.2,
    },
    {
      id: 'basic-auth',
      name: 'Basic auth credentials',
      severity: 'medium',
      regex: /\b[Bb]asic\s+([A-Za-z0-9+/]{16,}=*)/g,
      group: 1,
      entropy: 3.0,
    },
    {
      id: 'query-secret',
      name: 'Secret in query string',
      severity: 'medium',
      regex: /[?&](?:password|passwd|pwd|secret|api_key|apikey)=([^&\s"'<>#]{8,128})/gi,
      group: 1,
      entropy: 3.0,
    },
    {
      id: 'generic-secret',
      name: 'Generic secret assignment',
      severity: 'medium',
      regex: /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|access[_-]?key|client[_-]?secret|private[_-]?key|admin[_-]?key|app[_-]?secret|consumer[_-]?secret|jwt[_-]?secret|signing[_-]?key|encryption[_-]?key|session[_-]?secret|webhook[_-]?secret|passwd|password|pwd)["']?(?:\\[nrt]|\s)*[:=](?:\\[nrt]|\s)*["']([A-Za-z0-9_.+\/-]{16,512})["']/gi,
      group: 1,
      entropy: 3.6,
    },
    {
      id: 'contextual-blob',
      name: 'High-entropy string near crypto or auth code',
      severity: 'high',
      regex: /["']([A-Za-z0-9+/=_-]{64,512})["']/g,
      group: 1,
      entropy: 3.8,
      keywords: ['hmac', 'sign', 'secret', 'token', 'encrypt', 'private', 'api_key', 'apikey', 'auth'],
      // Skip common embedded images and bare 32/40 char hashes.
      deny: [/^iVBORw0KGgo/, /^\/9j\//, /^PHN2Zy/, /^R0lGOD/, /^[a-f0-9]{32}$/i, /^[a-f0-9]{40}$/i],
    },
  ];

  self.PSS = self.PSS || {};
  self.PSS.rules = rules;
})();
