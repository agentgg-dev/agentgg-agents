---
slug: datadog-api-key
name: Datadog API Key Exposure
description: 'Hardcoded Datadog API keys or application keys in source or config. API keys submit metrics and logs; app keys read dashboards, monitors, and user data — together they give full platform access.'
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
    - regex: '(?i)(?:datadog|dd_api|dd_app).{0,30}[=:"''\s]+[a-f0-9]{32}\b'
      label: Datadog API or app key (32 hex chars near datadog)
    - regex: '(?i)(?:DD_API_KEY|DATADOG_API_KEY|DD_APP_KEY|DATADOG_APP_KEY)\s*[=:]\s*[''"]?[a-f0-9]{32}'
      label: Datadog key environment variable with value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Datadog keys. Datadog is a monitoring and observability platform — exposed keys allow submitting fake metrics, reading sensitive infrastructure data, and accessing log contents.

## Key types

**API Key (32 hex chars):**
Authenticates data submission to Datadog:
- Submit metrics (can poison dashboards and alerts)
- Submit logs (can inject false log entries)
- Submit traces, events, and service checks

Used by agents, libraries, and CI pipelines. Set via `DD_API_KEY` environment variable.

**Application Key (40 hex chars):**
Used with the Datadog API to *read and manage* Datadog resources:
- Read all dashboards, monitors, and alerts
- Read log data (may contain secrets, PII, stack traces)
- Modify monitors and notification channels
- Access user information

The combination of API key + app key gives full read/write access to the Datadog account.

## Cross-file analysis

When a key is found:
1. Distinguish whether it is an API key (32 hex) or app key (40 hex)
2. Look for `DD_SITE` or `datadog_site` to identify which Datadog region
3. Check whether the key appears in agent config files (`datadog.yaml`), CI variables, or application code — determines scope of exposure

## True positive criteria

Flag when ALL hold:
1. A 32-hex (API key) or 40-hex (app key) value appears near "datadog", "dd_api", "DD_API_KEY", "DD_APP_KEY", or similar context
2. The value is a string literal, not an environment variable reference
3. The value is not a placeholder (all zeros, all `f`, `your-api-key-here`)

## What to ignore

- Environment variable references: `DD_API_KEY=${DATADOG_API_KEY}`, `dd_api_key: "{{ vault('datadog_api_key') }}"`
- 32-char hex values with no Datadog context nearby (MD5 hashes, UUIDs — too generic)
- Documentation examples with obviously fake keys

## Examples

True positives:
```yaml
# datadog.yaml
api_key: 1234567890abcdef1234567890abcdef
app_key: 1234567890abcdef1234567890abcdef12345678
```
```python
initialize(api_key='1234567890abcdef1234567890abcdef',
           app_key='1234567890abcdef1234567890abcdef12345678')
```

False positives to skip:
```yaml
api_key: ENC[PKCS7,...]
api_key: ${DD_API_KEY}
```

Report whether it is an API key or app key (different impact), what monitoring resources the code accesses, and whether the key appears in infrastructure config vs application source.
