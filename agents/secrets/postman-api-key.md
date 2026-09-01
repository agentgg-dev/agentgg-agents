---
slug: postman-api-key
name: Postman API Key Exposure
description: 'Hardcoded Postman API keys (PMAK-[24 chars]-[34 chars]) in source or config. A leaked key exposes all collections, environments (including stored secrets), and workspace data to unauthorized access.'
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
    - regex: '\b(PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34})\b'
      label: Postman API key (PMAK- prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Postman API keys.

## Key format

Postman API keys follow the format `PMAK-[24 alphanumeric chars]-[34 alphanumeric chars]`. The `PMAK` prefix stands for "Postman API Key."

## Risk

An attacker with a Postman API key can:
- Export all collections and environments belonging to the account — Postman environments commonly store API keys, passwords, tokens, and credentials for other services
- Access all workspaces the account belongs to, potentially exposing an entire team's API documentation and test credentials
- Import/export collections to exfiltrate the API structure and any embedded credentials
- Modify or delete collections, breaking team workflows
- Access API network data and mock server configurations

Postman is particularly dangerous as a pivot point: engineers often store production API keys, database credentials, and authentication tokens directly in Postman environment variables. A single Postman key can expose credentials for dozens of other services.

## Cross-file analysis

When a key is found, look for:
1. CI/CD scripts that use Postman's Newman CLI — `newman run collection.json` — often run with this key
2. Scripts that sync or export Postman collections, indicating what workspaces are accessible
3. Comments mentioning Postman workspace names or team names — helps scope the blast radius

## True positive criteria

Flag when ALL hold:
1. The value matches `PMAK-[24 chars]-[34 chars]`
2. It is a string literal, not an environment variable reference (`$POSTMAN_API_KEY`, `process.env.POSTMAN_API_KEY`)
3. It is not a placeholder

## What to ignore

- Environment variable references in CI config: `$POSTMAN_API_KEY`, `${{ secrets.POSTMAN_API_KEY }}`
- Clearly redacted values

## Examples

True positives:
```sh
newman run https://api.getpostman.com/collections/12345?apikey=PMAK-<24-chars>-<34-chars>
```
```yaml
POSTMAN_API_KEY: PMAK-<24-chars>-<34-chars>
```

False positives to skip:
```sh
newman run collection.json --env-var "apiKey=$POSTMAN_API_KEY"
```

Note that Postman API keys are often used to access environments that contain other credentials. Rate as high severity due to the credential-in-credential risk.
