---
slug: doppler-token
name: Doppler Service Token Exposure
description: 'Hardcoded Doppler service tokens (dp.pt. prefix) in source or config. Doppler is a secrets manager — a leaked Doppler token gives access to all other secrets stored for that project/config.'
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
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\bdp\.pt\.[a-zA-Z0-9]{43}\b'
      label: Doppler service token (dp.pt. prefix)
    - regex: '(?i)(?:doppler|DOPPLER_TOKEN).{0,30}[=:"''\s]+dp\.pt\.[a-zA-Z0-9]{43}'
      label: Doppler token in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Doppler service tokens. Doppler is a secrets manager that injects secrets into applications at runtime — leaking a Doppler token is like leaking all the secrets it manages at once.

## Token format

```
dp.pt.<43 alphanumeric characters>
```

Service tokens are scoped to a specific Doppler project and config (e.g., `my-app/production`). They grant read access to all secrets in that scope.

## Why this is high severity

A Doppler service token is a master key. It decrypts and returns all secrets for the environment it's scoped to — database passwords, API keys, TLS certificates — everything. One leaked token exposes the entire secret set for that environment.

## True positive criteria

Flag when ALL hold:
1. Value matches `dp.pt.[a-zA-Z0-9]{43}` exactly
2. String literal, not an env var reference
3. Not a placeholder

## Examples

True positive:
```yaml
# docker-compose.yml
environment:
  DOPPLER_TOKEN: dp.pt.AbCdEfGhIjKlMnOpQrStUvWxYz01234567890Ab
```

Report the Doppler project and config the token is scoped to (if determinable from surrounding config), and what other secrets it would expose.
