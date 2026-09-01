---
slug: secret-env-var
name: Secret Env Var Access (Review Handling)
description: 'Direct access to env vars whose names contain SECRET, MASTER_KEY, AWS_SECRET, JWT_SECRET, PRIVATE_KEY — flag for review of how the value is handled (storage, logging, transmission).'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
      - lua
      - go
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - lua
    - go
  preFilter:
    - semgrepRule: exposure/process-env-access
      label: process.env access for a secret-named variable
references:
  - CWE-200
  - CWE-532
  - 'OWASP-A02:2021'
---

You are reviewing source code for access to secret-shaped environment
variables. This is not a vulnerability on its own — most apps need to
read secrets from env — but the access site is the point where review
is needed: where does the value flow, is it logged, is it transmitted
to a third party, is it cached?

## What to look for

**JS/TS:**
```ts
const s = process.env.JWT_SECRET;
const j = process.env.JWE_SECRET;
const k = process.env.COSMOSDB_MASTER_KEY;
const a = process.env.AWS_SECRET_ACCESS_KEY;
```

**Lua (OpenResty):**
```lua
local s = os.getenv("API_SECRET")
local k = os.getenv("DB_MASTER_KEY")
local a = os.getenv("AWS_SECRET_ACCESS_KEY")
local p = os.getenv("RSA_PRIVATE_KEY")
```

**Go:**
```go
s := os.Getenv("API_SECRET")
k := os.Getenv("DB_MASTER_KEY")
```

**Variable-name patterns to flag:**
`*_SECRET`, `*_MASTER_KEY`, `AWS_SECRET_*`, `*_PRIVATE_KEY`,
`JWT_SECRET`, `JWE_SECRET`, `HMAC_SECRET`, `*_API_SECRET`,
`PURGE_API_SECRET`, `COSMOSDB_MASTER_KEY`.

## What to review (downstream of the access)

When you find a secret env-var access, follow the value:

1. **Is it logged?** `console.log(secret)`, `logger.info({ secret })`.
2. **Is it returned in an HTTP response?** `res.json({ ... secret })`.
3. **Is it sent to a third-party service?** OTel span attribute,
   Sentry context, Datadog tag, error monitoring metadata.
4. **Is it cached without protection?** Stored in a global cache or
   plain file.
5. **Does it have a hardcoded fallback?** `process.env.X ?? "default"`
   (see `secret-in-fallback`).
6. **Is the access in client-bundled code?** (see `env-exposure`).

## True positive criteria

Flag every match for review. The access itself is not a finding,
but each access is a review point. Report as a finding when:

- The secret flows into a log/response/trace (use the relevant
  `secret-in-log`, `secrets-plaintext-exposure`, or
  `sensitive-data-in-traces` agent for the actual leak, but this
  agent surfaces the access).
- The access is in a file that ships to the client.
- The access has a hardcoded fallback.

## What to ignore

- Test files / fixtures.
- Centralized config modules that read every secret once, validate
  presence, and re-export typed accessors — these are review points
  for the config module itself, not every consumer.

## Examples

True positives:
```ts
// JWT_SECRET accessed and immediately logged
const secret = process.env.JWT_SECRET;
console.log("Loaded JWT_SECRET:", secret);
```

```lua
-- Lua HMAC secret pulled and used to compute a value sent to a span
local secret = os.getenv("HMAC_SECRET")
ngx.log(ngx.INFO, "secret:", secret)
```

False positives to skip:
```ts
// Used only as input to crypto, no logging
const key = process.env.HMAC_SECRET;
const sig = hmac(key, payload);
```
