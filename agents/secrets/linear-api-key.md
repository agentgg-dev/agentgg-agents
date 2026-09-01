---
slug: linear-api-key
name: Linear API Key Exposure
description: 'Hardcoded Linear API keys (lin_api_ prefix, 40 chars) in source or config. Grants read/write access to issues, projects, teams, and workflows in the Linear workspace.'
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
    - regex: '\blin_api_[0-9A-Za-z]{40}\b'
      label: Linear API key (lin_api_ prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Linear API keys. Linear is an issue tracking and project management tool — a leaked key exposes all issues, roadmap data, and internal team communication.

## Token format

```
lin_api_<40 alphanumeric characters>
```

## What a leaked key enables

- Read all issues, projects, and cycles (sprints) across all teams
- Read issue comments and attachments
- Create, update, and delete issues
- Access team member information
- Read roadmap and priority data — may reveal competitive information or security bug details

## True positive criteria

Flag when ALL hold:
1. Value matches `lin_api_[0-9A-Za-z]{40}` exactly
2. String literal, not an env var reference
3. Not a placeholder

## Examples

True positive:
```js
const { LinearClient } = require('@linear/sdk');
const client = new LinearClient({ apiKey: 'lin_api_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890Ab' });
```

Report what teams or projects the code accesses.
