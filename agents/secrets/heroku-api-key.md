---
slug: heroku-api-key
name: Heroku API Key / Token Exposure
description: 'Hardcoded Heroku API keys (UUID format near "heroku") or OAuth tokens (HRKU-[60 chars]) in source or config. A leaked key gives full control over all Heroku apps and add-ons in the account, including config vars that store other secrets.'
version: 0.1.0
author: agentgg
noiseTier: precise
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
    - regex: '(?i)heroku.{0,20}key.{0,20}\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b'
      label: Heroku API key (UUID format near "heroku")
    - regex: 'HRKU-[0-9a-zA-Z_\-]{60}'
      label: Heroku OAuth token (HRKU- prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Heroku API credentials.

## Credential formats

**API Key (UUID format):** Heroku API keys are standard UUIDs (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` in lowercase hex) and appear near the word "heroku" in config or code. They authenticate against the Heroku Platform API.

**OAuth Token (`HRKU-[60 alphanumeric chars]`):** Heroku OAuth tokens, issued to apps authorized via OAuth. Also provide full API access scoped to the authorized user.

## Risk

An attacker with a Heroku API key can:
- List, read, and modify all Heroku apps in the account — restart dynos, deploy new releases
- Read all config vars (environment variables) — these commonly store database URLs, third-party API keys, and other secrets for every app in the account
- Modify config vars to inject malicious environment variables into running applications
- Scale dynos up (billing abuse) or to zero (denial of service)
- Access logs, build artifacts, and add-on credentials
- Create, manage, or delete add-ons (Heroku Postgres, Redis, etc.) — including reading database credentials

## Cross-file analysis

When a key is found, look for:
1. The Heroku app name (`HEROKU_APP_NAME`, `heroku apps:config`, `heroku run`) — identifies which apps are at risk
2. CI/CD pipeline steps that deploy to Heroku — if the key is in a CI file, it was used to deploy code
3. Heroku Postgres or Redis add-on references — the API key gives access to add-on credentials

## True positive criteria

Flag when ALL hold:
1. The value matches the UUID format and appears near Heroku-related variables/code, or matches `HRKU-[60 chars]`
2. It is a string literal, not an environment variable reference (`process.env.HEROKU_API_KEY`, `$HEROKU_API_TOKEN`)
3. Not a generic UUID that happens to appear near Heroku configuration — the variable name or context must suggest it is a Heroku credential

## What to ignore

- Environment variable references
- UUIDs in Heroku app IDs or pipeline IDs — those are not API keys (API keys specifically authenticate users to the Platform API)
- Generic UUID values unrelated to Heroku authentication

## Examples

True positives:
```yaml
# In .travis.yml — hardcoded deploy key
deploy:
  provider: heroku
  api_key: <heroku-api-key-uuid>
```
```sh
HEROKU_API_KEY=<heroku-api-key-uuid> heroku apps:info
```
```yaml
HEROKU_TOKEN: HRKU-<60-char-token>
```

False positives to skip:
```yaml
deploy:
  provider: heroku
  api_key: $HEROKU_API_KEY
```

Note which Heroku apps are referenced in the same file/pipeline to understand how many apps and their config vars are exposed.
