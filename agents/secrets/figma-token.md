---
slug: figma-token
name: Figma Personal Access Token Exposure
description: 'Hardcoded Figma personal access tokens (UUID-like format) committed to source. Grants read/write access to Figma files, design assets, team workspaces, and comments.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(?i)figma.{0,20}[0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Figma token in extended UUID format
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)figma.{0,20}\b([0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b'
      label: Figma personal access token (extended UUID format)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Figma personal access tokens.

## Token format

Figma personal access tokens follow an extended UUID format: `XXXX-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (groups of 4-8-4-4-4-12 hex chars). Generated at figma.com/settings.

## What a leaked token enables

- Read all Figma files the token owner can access (team and organization designs)
- Download design assets and export files
- Post comments on designs
- Access team member lists and file metadata
- Modify files if the owner has edit permissions

## True positive criteria

Flag when ALL hold:
1. Extended UUID string appears near `figma`, `FIGMA_TOKEN`, `FIGMA_API_TOKEN`, or as an `X-Figma-Token` HTTP header value
2. It is a string literal, not `process.env.FIGMA_TOKEN`
3. Not a Figma file ID or node ID (those are shorter alphanumeric strings)

## What to ignore

- Figma file URLs: `https://www.figma.com/file/XXXX/...` — the XXXX is a file ID, not an API token
- `process.env.FIGMA_ACCESS_TOKEN` — safe environment reference

Report whether the token is embedded in CI/CD configuration (e.g., a GitHub Actions workflow calling the Figma API).
