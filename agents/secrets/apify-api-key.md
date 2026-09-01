---
slug: apify-api-key
name: Apify API Key Exposure
description: 'Hardcoded Apify API tokens (apify_api_ prefix) in source or config. Grants access to run web scraping actors, access datasets, manage proxy usage, and incur billing on the Apify platform.'
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
    - regex: '\bapify_api_[a-zA-Z0-9\-]{36}\b'
      label: Apify API token (apify_api_ prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Apify API tokens. Apify is a web scraping and automation platform — a leaked token allows running expensive actors and accessing scraped datasets.

## Token format

```
apify_api_<36 alphanumeric/dash characters>
```

## What a leaked token enables

- Run web scraping actors (can incur significant billing)
- Read all scraped datasets and key-value stores
- Access proxy network credits
- Manage and schedule automated scraping tasks
- Read all actor run results

## True positive criteria

Flag when ALL hold:
1. Value matches `apify_api_[a-zA-Z0-9-]{36}` exactly
2. String literal, not `process.env.APIFY_TOKEN`
3. Not a placeholder

## Examples

True positive:
```js
const client = new ApifyClient({ token: 'apify_api_AbCdEfGhIjKlMnOpQrStUvWxYz123456' });
```

Report what actors or datasets the code accesses.
