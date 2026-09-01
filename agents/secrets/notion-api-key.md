---
slug: notion-api-key
name: Notion API Key Exposure
description: 'Hardcoded Notion integration tokens (secret_ prefix, 43 chars) in source or config. Grants read/write access to all Notion pages, databases, and workspaces the integration was granted access to.'
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
    - regex: '\bsecret_[A-Za-z0-9]{43}\b'
      label: Notion integration token (secret_ prefix, 43 chars)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Notion integration tokens.

## Token format

```
secret_<43 alphanumeric characters>
```
Total length: 50 characters. Created at https://www.notion.so/my-integrations.

## What a leaked token enables

- Read all pages and databases the integration has access to (docs, roadmaps, HR data if shared)
- Create, update, and delete pages and database entries
- Read comments and discussions
- Scope depends on what the workspace owner granted — could be limited or org-wide

## True positive criteria

Flag when ALL hold:
1. Value matches `secret_[A-Za-z0-9]{43}` exactly
2. String literal, not `process.env.NOTION_TOKEN`
3. Not a placeholder

## Examples

True positive:
```python
from notion_client import Client
notion = Client(auth='secret_AbCdEfGhIjKlMnOpQrStUvWxYz01234567890123')
```

Report what Notion operations the code performs and whether the integration likely has broad or narrow page access.
