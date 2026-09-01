---
slug: asana-api-key
name: Asana API Client Secret Exposure
description: 'Hardcoded Asana OAuth client secret or personal access token committed to source. Grants access to Asana projects, tasks, and team workspace data.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)asana.{0,30}[=:"''\s]+[a-z0-9]{32}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Asana credential near asana keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{32})(?:[''"\n\r\s`;]|$)'
      label: Asana 32-char client ID or secret
    - regex: '(?i)ASANA_ACCESS_TOKEN|ASANA_PAT|ASANA_PERSONAL_ACCESS_TOKEN'
      label: Asana personal access token variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Asana API credentials.

## Credential types

- **OAuth client secret**: 32-char alphanumeric. Allows OAuth token exchange.
- **Personal access token (PAT)**: opaque token, generated at asana.com/0/my-apps. Acts as the user who created it.

## What leaked credentials enable

- Access all Asana projects, tasks, and comments the user or OAuth app can see
- Read team member lists, project structures, deadlines
- Create/modify/delete tasks if write-scoped
- Access sensitive project data: client names, financial projects, HR tasks

## True positive criteria

Flag when:
1. `ASANA_CLIENT_SECRET` or `ASANA_SECRET` set to a 32-char string literal
2. `ASANA_ACCESS_TOKEN` or `ASANA_PAT` set to a string literal (not env var reference)

## What to ignore

- `process.env.ASANA_ACCESS_TOKEN` — safe env reference
- Asana task GIDs (numeric IDs like `1234567890123456`) — not secrets
- Asana workspace GIDs — not secrets

Report: whether the credential is an OAuth secret or personal access token, and what Asana workspace is accessed (if visible from nearby config).
