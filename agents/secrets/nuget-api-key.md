---
slug: nuget-api-key
name: NuGet API Key Exposure
description: 'Hardcoded NuGet.org API keys (oy2 prefix, 46-char format) committed to source. Grants push/delete access to NuGet packages under the associated account — supply chain risk.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '\boy2[a-z0-9]{43}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: NuGet API key (oy2 prefix)
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '\boy2[a-z0-9]{43}\b'
      label: NuGet API key format (oy2 + 43 chars)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded NuGet.org API keys.

## Token format

NuGet.org API keys: `oy2` followed by 43 lowercase alphanumeric chars — 46 chars total. Generated at nuget.org/account/apikeys.

## What a leaked key enables

- Push new versions of NuGet packages to any package scoped to the key
- Delete or unlist existing package versions
- With a broad key scope: publish packages under any package name the account owns — supply chain attack vector
- Malicious package versions could contain backdoors targeting all downstream .NET projects using that package

## True positive criteria

Flag when:
1. A string starting with `oy2` (46 chars total) appears as a literal value
2. Near `NUGET_API_KEY`, `nuget push`, `.nupkg`, or NuGet publish configuration
3. Especially critical if found in a CI/CD workflow (`.github/workflows/`, `azure-pipelines.yml`, `Jenkinsfile`)

## What to ignore

- `${{ secrets.NUGET_API_KEY }}` — safe secrets reference in GitHub Actions
- `$(NUGET_API_KEY)` — safe pipeline variable reference

Report: the package name scope if visible from nearby config, and whether the key appears in a publish/deploy workflow.
