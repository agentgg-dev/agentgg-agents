---
slug: segment-api-key
name: Segment Write Key Exposure
description: 'Hardcoded Segment server-side write keys in source or config. Server-side write keys allow sending arbitrary analytics events as any user, injecting false conversion data that flows to all connected destinations.'
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
    - regex: '(?i)(?:SEGMENT_WRITE_KEY|SEGMENT_API_KEY|analytics\.identify|analytics\.track).{0,40}[=:"''\s]+[A-Za-z0-9]{20,}'
      label: Segment write key in named variable or SDK call
    - regex: '(?i)analytics\.load\s*\(\s*[''"][A-Za-z0-9]{20,}[''"]'
      label: Segment analytics.js load call with write key
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Segment write keys.

## Credential types

**Server-side write key:** used in backend code to send server-side events. Should be kept private — allows sending events as any user ID.

**Browser write key:** used in `analytics.load()` in client JavaScript. Intentionally public — this is normal usage and should NOT be flagged.

## What a leaked server-side key enables

- Send arbitrary events tagged as any user ID (analytics impersonation)
- Inject false conversion or revenue events (distort A/B test results, inflate metrics)
- Send PII-containing events that flow to Segment destinations (CRMs, data warehouses, ad platforms)

## True positive criteria

Flag at higher severity:
1. Write key hardcoded in server-side code (Node.js, Python, Go, Ruby) — string literal, not env var

Flag at lower severity (note, do not escalate):
2. Write key in `analytics.load()` in browser JavaScript — this is expected and intentional

## What to ignore

- Browser write keys in `analytics.load()` — intentionally public
- `SEGMENT_API_TOKEN` for the Config API — different credential, different purpose
- Environment variable references

## Examples

True positive (server-side):
```python
import analytics
analytics.write_key = 'AbCdEfGhIjKlMnOpQrStUvWx'
analytics.track('user_123', 'Order Completed', {'revenue': 100})
```

Expected (browser):
```js
analytics.load('AbCdEfGhIjKlMnOpQrStUvWx')  // OK in browser JS
```

Report whether the key is in server-side or client-side code.
