#!/usr/bin/env node
/* Offline smoke test for the rule pack and scanner. Run: node tools/test-scan.js */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.join(__dirname, "..");
const context = { self: {}, console, atob, TextDecoder };
vm.createContext(context);
for (const file of ["lib/entropy.js", "lib/rules.js", "lib/scan.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, file), "utf8"), context, { filename: file });
}

const { scanText } = context.self.PSS;

// Long provider secrets exist (CyberSource HMAC keys are 256 hex chars).
const longHex = Array.from({ length: 256 }, (_, i) => (i % 16).toString(16)).join("");
const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const adminJwt = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({
  sub: "1",
  role: "admin",
})}.${"a".repeat(32)}`;
const noneJwt = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "1" })}.`;

const cases = [
  {
    name: "private key header",
    text: "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..." ,
    rule: "private-key",
    expect: true,
  },
  {
    name: "AWS example key is ignored",
    text: 'const id = "AKIAIOSFODNN7EXAMPLE";',
    rule: "aws-access-key-id",
    expect: false,
  },
  {
    name: "AWS access key id",
    text: 'aws_access_key_id = "AKIAZ7Q2XJ5V4R3T2W1Y"',
    rule: "aws-access-key-id",
    expect: true,
  },
  {
    name: "AWS secret access key",
    text: 'aws_secret_access_key = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"',
    rule: "aws-secret-access-key",
    expect: true,
  },
  {
    name: "GitHub token",
    text: 'token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz"',
    rule: "github-token",
    expect: true,
  },
  {
    name: "Stripe publishable key is ignored",
    text: 'const k = "pk_live_1234567890abcdefghijklmn";',
    rule: "stripe-secret-key",
    expect: false,
  },
  {
    name: "Stripe secret key",
    text: 'const k = "sk_live_51H8xQ2eZvKYlo2CxAbCdEfGh";',
    rule: "stripe-secret-key",
    expect: true,
  },
  {
    name: "SendGrid key",
    text: "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
    rule: "sendgrid-key",
    expect: true,
  },
  {
    name: "JWT",
    text: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    rule: "jwt",
    expect: true,
  },
  {
    name: "database URI",
    text: "postgres://admin:hunter2secret@db.example.com:5432/app",
    rule: "db-uri",
    expect: true,
  },
  {
    name: "database URI with placeholder creds is ignored",
    text: "postgres://user:YOUR_PASSWORD@example.com:5432/app",
    rule: "db-uri",
    expect: false,
  },
  {
    name: "placeholder API key is ignored",
    text: 'const apiKey = "YOUR_API_KEY_HERE_1234567890";',
    rule: "generic-secret",
    expect: false,
  },
  {
    name: "generic password assignment",
    text: 'password: "Xk9mQ2vLp7Rt4Wz8"',
    rule: "generic-secret",
    expect: true,
  },
  {
    name: "low-entropy generic value is ignored",
    text: 'password: "aaaaaaaaaaaaaaaaaaaa"',
    rule: "generic-secret",
    expect: false,
  },
  {
    name: "twilio key without context is ignored",
    text: "SK0123456789abcdef0123456789abcdef",
    rule: "twilio-api-key",
    expect: false,
  },
  {
    name: "twilio key with context",
    text: 'twilio_api_key = "SK0123456789abcdef0123456789abcdef"',
    rule: "twilio-api-key",
    expect: true,
  },
  {
    name: "Anthropic key",
    text: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345",
    rule: "anthropic-key",
    expect: true,
  },
  {
    name: "plain JS does not trigger generic rule",
    text: 'const options = { password: null, token: undefined }; function login() { return true; }',
    rule: null,
    expect: false,
  },
  {
    name: "PGP private key block",
    text: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    rule: "private-key",
    expect: true,
  },
  {
    name: "Azure Storage account key",
    text: 'AccountKey=Xk9mQ2vLp7Rt4Wz8AbCdEfGhIjKlMnOpQrStUvWx==',
    rule: "azure-storage-key",
    expect: true,
  },
  {
    name: "Azure SAS token URL",
    text:
      "https://acct.blob.core.windows.net/container/backup.zip?sv=2022-11-02&ss=b&srt=sco&sp=rl&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2Fabc",
    rule: "azure-sas-token",
    expect: true,
  },
  {
    name: "credentials in URL",
    text: "https://admin:hunter2secret@internal.example.test/admin",
    rule: "url-basic-auth",
    expect: true,
  },
  {
    name: "placeholder credentials in URL are ignored",
    text: "https://user:YOUR_PASSWORD@example.test/",
    rule: "url-basic-auth",
    expect: false,
  },
  {
    name: "SQL Server connection string",
    text: "Server=db.internal;Database=app;User Id=sa;Password=Xk9mQ2vLp7Rt4Wz8;",
    rule: "mssql-connection-string",
    expect: true,
  },
  {
    name: "Stripe webhook secret",
    text: "whsec_abcdefghijklmnopqrstuvwx",
    rule: "stripe-webhook-secret",
    expect: true,
  },
  {
    name: "secret in query string",
    text: "https://app.test/login?password=Xk9mQ2vLp7Rt4Wz8",
    rule: "query-secret",
    expect: true,
  },
  {
    name: "long HMAC style secret assignment",
    text: `const SECRET_KEY =\n  '${longHex}';`,
    rule: "generic-secret",
    expect: true,
    severity: "critical",
  },
  {
    name: "secret in JSON-escaped source map",
    text: `"const SECRET_KEY =\\n  '${longHex}';"`,
    rule: "generic-secret",
    expect: true,
    severity: "critical",
  },
  {
    name: "bare secret near HMAC call",
    text: `CryptoJS.HmacSHA256(data, "${longHex}")`,
    rule: "contextual-blob",
    expect: true,
    severity: "high",
  },
  {
    name: "long word-like constant near secret is ignored",
    text: `const note = "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED_${"a".repeat(40)}";`,
    rule: "contextual-blob",
    expect: false,
  },
  {
    name: "short HMAC signature is ignored",
    text: `HmacSHA256(data, "6cF73Kl1yDyHMqXTmhlVx8KqD+dw0YQRoV26C4qr+Bg=")`,
    rule: "contextual-blob",
    expect: false,
  },
  {
    name: "Stripe live key is critical",
    text: 'const k = "sk_live_51H8xQ2eZvKYlo2CxAbCdEfGh";',
    rule: "stripe-secret-key",
    expect: true,
    severity: "critical",
  },
  {
    name: "Stripe test key is low",
    text: 'const k = "sk_test_51H8xQ2eZvKYlo2CxAbCdEfGh";',
    rule: "stripe-secret-key",
    expect: true,
    severity: "low",
  },
  {
    name: "admin JWT is high",
    text: `auth = "${adminJwt}"`,
    rule: "jwt",
    expect: true,
    severity: "high",
  },
  {
    name: "alg none JWT is critical",
    text: `auth = "${noneJwt}"`,
    rule: "jwt",
    expect: true,
    severity: "critical",
  },
];

let failures = 0;

for (const testCase of cases) {
  const findings = scanText(testCase.text, {
    sourceType: "js",
    sourceUrl: "https://example.test/app.js",
    pageUrl: "https://example.test/",
    host: "example.test",
  });
  const target = testCase.rule
    ? findings.find((f) => f.ruleId === testCase.rule)
    : findings[0];
  const hit = Boolean(target);
  const severityOk =
    !testCase.severity || (target && target.severity === testCase.severity);
  const ok = hit === testCase.expect && severityOk;
  if (!ok) failures++;
  const detail = ok
    ? ""
    : `  (expected ${testCase.expect ? "a hit" : "no hit"}${
        testCase.severity ? ` at ${testCase.severity}` : ""
      }, got ${findings.length} finding(s): ${findings
        .map((f) => `${f.ruleId}/${f.severity}`)
        .join(", ") || "none"})`;
  console.log(`${ok ? "PASS" : "FAIL"}  ${testCase.name}${detail}`);
}

// A value matched by a specific rule must not be reported again by the
// generic assignment rule.
const jwtValue =
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const jwtFindings = scanText(`authToken = "${jwtValue}"`, {
  sourceType: "js",
  sourceUrl: "https://example.test/a.js",
  pageUrl: "https://example.test/",
  host: "example.test",
}).filter((f) => f.match === jwtValue);
if (jwtFindings.length === 1) {
  console.log("PASS  a value is reported once across rules");
} else {
  failures++;
  console.log(`FAIL  a value is reported once across rules (got ${jwtFindings.length})`);
}

// Redaction should never expose the full value.
const sample = scanText('api_key = "Zx8Qw2Er5Ty9Ui3Op7As"', {
  sourceType: "js",
  sourceUrl: "https://example.test/a.js",
  pageUrl: "https://example.test/",
  host: "example.test",
});
if (sample.length > 0) {
  const f = sample[0];
  const leaks = f.snippet.includes(f.match) || !f.redacted.includes("*");
  if (leaks) {
    failures++;
    console.log("FAIL  redaction hides the secret in snippets");
  } else {
    console.log("PASS  redaction hides the secret in snippets");
  }
  if (!f.line || typeof f.line !== "number") {
    failures++;
    console.log("FAIL  line number is reported");
  } else {
    console.log("PASS  line number is reported");
  }
} else {
  failures++;
  console.log("FAIL  redaction test could not produce a finding");
}

console.log(failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
