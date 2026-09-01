---
slug: newrelic-api-key
name: New Relic API Key Exposure
description: 'Hardcoded New Relic API keys (NRAA-, NRRA-, NRII-, NRIQ-, NRSP-) in source or config. An admin key can delete accounts and manage users; a user key exposes all observability data including production logs and traces.'
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
    - regex: '(?i)NRAA-[a-f0-9]{27}'
      label: New Relic admin API key (NRAA-)
    - regex: '(?i)NRRA-[a-f0-9]{42}'
      label: New Relic REST API key (NRRA-)
    - regex: '(?i)NRI(?:I|Q)-[A-Za-z0-9\-_]{32}'
      label: New Relic Insights insert/query key (NRII-/NRIQ-)
    - regex: '(?i)NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}'
      label: New Relic synthetics location key (NRSP-)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded New Relic API keys.

## Key types and risk

**Admin API Key (`NRAA-[27 hex]`):** Account administration. Can create and delete users, manage account settings, and access billing. Highest severity.

**REST API Key (`NRRA-[42 hex]`):** Full access to the New Relic REST API v2. Can query all APM, browser, mobile, and infrastructure metrics, access alert policies, and read application configuration. Also enables reading deployment markers and log data.

**Insights Insert Key (`NRII-[32 chars]`):** Write-only access to push custom events to New Relic Insights. Attacker can inject fake metric data to mask attacks or cause alert fatigue. Lower direct risk but can undermine the integrity of monitoring data.

**Insights Query Key (`NRIQ-[32 chars]`):** Read access to query all events stored in New Relic Insights/NRDB — potentially includes application logs, transaction traces, and custom events with sensitive data.

**Synthetics Location Key (`NRSP-[country][datacenter][31 hex]`):** Registers a private synthetics minion at a specific location. Attacker can register a rogue location to intercept synthetic test traffic or suppress synthetic monitoring.

## Cross-file analysis

When a key is found, look for:
1. The New Relic account ID (numeric, often nearby) — identifies which account is exposed
2. What data the code queries or ingests — transaction traces and logs often contain PII or secrets
3. Whether the key appears in a backend service or a client-side bundle (NRRA keys should never be in client-side code)

## True positive criteria

Flag when ALL hold:
1. The value matches one of the `NR` prefix patterns with correct length
2. It is a string literal, not an environment variable reference (`process.env.NEW_RELIC_API_KEY`, `ENV['NEW_RELIC_LICENSE_KEY']`)
3. It is not a placeholder: all same characters, New Relic documentation examples

## What to ignore

- New Relic license keys used for agent instrumentation — these are different from API keys and appear as 40-character hex strings; they are write-only and used to send telemetry, not to read account data
- Environment variable references
- Redacted values

## Examples

True positives:
```ts
const nrApi = axios.create({
  baseURL: 'https://api.newrelic.com/v2/',
  headers: { 'X-Api-Key': 'NRRA-<42-hex-chars>' }
});
```
```yaml
NEW_RELIC_API_KEY: NRAA-<27-hex-chars>
```

False positives to skip:
```ts
headers: { 'X-Api-Key': process.env.NEW_RELIC_API_KEY }
```

Rate admin keys as critical, REST/query keys as high (they expose production observability data that often contains sensitive info), insert keys as medium (data integrity risk), and location keys as low.
