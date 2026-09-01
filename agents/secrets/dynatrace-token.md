---
slug: dynatrace-token
name: Dynatrace API Token Exposure
description: 'Hardcoded Dynatrace API tokens (dt0[a-zA-Z]{1}[0-9]{2}.[24 chars].[64 chars]) in source or config. A leaked token can read all APM metrics, traces, and logs — and depending on scopes, modify monitoring configuration.'
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
    - regex: '\b(dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64})\b'
      label: Dynatrace API token (dt0X## format)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Dynatrace API tokens.

## Token format

Dynatrace API tokens follow the format: `dt0[type_char][2 digits].[24 uppercase alphanumeric chars].[64 uppercase alphanumeric chars]`

The type character and digits encode the token type:
- `dt0c01` — API v2 token (most common)
- `dt0s01` — Service token
- `dt0a01` — Agent token (used for OneAgent deployment)
- `dt0e01` — Internal/environment token

## Risk

An attacker with a Dynatrace API token can, depending on granted scopes:
- **Read metrics/traces/logs:** Export all APM metrics, distributed traces, and logs from the Dynatrace environment — production logs often contain PII, session tokens, and error details that reveal application internals
- **Read entities:** Enumerate all monitored hosts, services, processes, and their configurations — provides a full map of the production infrastructure
- **Write configuration:** Modify alerting rules, synthetic monitors, dashboards, and extensions — can suppress alerts during an attack to avoid detection
- **Deploy agents:** Create new OneAgent deployments or modify agent configurations — potential for infrastructure persistence

## Cross-file analysis

When a token is found, look for:
1. The Dynatrace environment URL (`https://xxx.live.dynatrace.com` or `https://xxx.sprint.dynatracelabs.com`) — identifies which tenant is exposed
2. The API endpoints the code calls — determines the token's effective scope
3. Whether the code uses this token in an integration, export script, or monitoring configuration

## True positive criteria

Flag when ALL hold:
1. The value matches `dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}` — this is a highly specific format
2. It is a string literal, not an environment variable reference (`process.env.DT_API_TOKEN`, `os.environ.get('DYNATRACE_TOKEN')`)
3. It is not a placeholder

## What to ignore

- Environment variable references
- Dynatrace PaaS tokens — different format, used only to deploy agents
- Clearly redacted or masked values

## Examples

True positives:
```ts
const dtClient = axios.create({
  baseURL: 'https://abc12345.live.dynatrace.com/api/v2',
  headers: { Authorization: 'Api-Token dt0c01.<24-chars>.<64-chars>' }
});
```
```yaml
DT_API_TOKEN: dt0c01.<24-chars>.<64-chars>
```

False positives to skip:
```ts
headers: { Authorization: `Api-Token ${process.env.DT_API_TOKEN}` }
```

Note the Dynatrace environment URL and which API endpoints are called (metrics, logs, problems, entities, configuration) to describe the scope of the exposure.
