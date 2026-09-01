---
slug: sentry-dsn
name: Sentry DSN and Auth Token Exposure
description: 'Hardcoded Sentry legacy DSNs (with secret key) or Sentry auth tokens in source or config. Legacy DSNs allow reading error events with stack traces; auth tokens grant full API access to issues, releases, and project settings.'
version: 0.1.0
author: agentgg
noiseTier: normal
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: 'https://[a-f0-9]{32}:[a-f0-9]{32}@(?:sentry\.io|[a-z0-9.]+\.ingest\.sentry\.io)/[0-9]+'
      label: Sentry legacy DSN with secret key (public:secret@host/id format)
    - regex: '(?i)(?:SENTRY_AUTH_TOKEN|SENTRY_TOKEN)\s*[=:]\s*[''"]?[A-Za-z0-9]{64}\b'
      label: Sentry auth token (64 chars)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Sentry credentials.

## Credential types

**Modern DSN (public key only — safe in client code):**
```
https://<public_key>@<org>.ingest.sentry.io/<project_id>
```
Only the public key — can send events but not read them. Expected in browser JS and mobile apps.

**Legacy DSN (contains secret key — not safe):**
```
https://<public_key>:<secret_key>@sentry.io/<project_id>
```
The `:<secret_key>@` portion grants read access to events. Sentry deprecated this but old SDKs still use it.

**Auth token (64 alphanumeric chars):** full API access token — much more powerful than a DSN.

## What leaked credentials enable

**Legacy DSN with secret key:** read all error events and stack traces (which often contain local variable values including passwords and tokens), user context (emails, IPs, user IDs).

**Auth token:** full API access — read all issues, delete issues, modify project settings, create releases, access all organization members.

## True positive criteria

Flag at high severity:
1. Legacy DSN with `:<secret_key>@` portion (secret key present)
2. Auth token set to a literal 64-char value

Note only (do not escalate):
3. Modern DSN in client-side JavaScript — expected and intentional

## Examples

True positives:
```env
SENTRY_DSN=https://abc123def456abc123def456abc12345:fed987654321fed987654321fed98765@sentry.io/123456
SENTRY_AUTH_TOKEN=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

Expected (do not flag):
```env
SENTRY_DSN=https://abc123def456abc123def456abc12345@o123456.ingest.sentry.io/789012
```

Report whether the DSN is legacy (with secret key) or modern, and whether an auth token is also present.
