---
slug: vercel-token
name: Vercel API Token Exposure
description: 'Hardcoded Vercel access tokens in source or config. Grants full control over Vercel deployments, environment variables, domains, and team/project settings.'
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
    - regex: '(?i)(?:vercel|VERCEL_TOKEN|VERCEL_ACCESS_TOKEN).{0,30}[=:"''\s]+[A-Za-z0-9]{24,40}\b'
      label: Vercel token in named variable
    - regex: '\bVercel-Token\s*:\s*[A-Za-z0-9]{24,40}\b'
      label: Vercel-Token HTTP header value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Vercel access tokens.

## Token format

Vercel personal access tokens: alphanumeric, 24-40 chars. Created at vercel.com/account/tokens.

## What a leaked token enables

- Trigger new deployments or promote preview deployments to production
- Read and modify all environment variables for all projects (often contain database URLs, API keys)
- Access deployment logs
- Modify domain and DNS settings
- Enumerate all projects and read source code via the API

## True positive criteria

Flag when ALL hold:
1. Alphanumeric string (24-40 chars) near "vercel", `VERCEL_TOKEN`, or `VERCEL_ACCESS_TOKEN`
2. String literal, not `${{ secrets.VERCEL_TOKEN }}`
3. Not a project ID or team ID (those are UUIDs — these tokens are shorter alphanumeric)

## What to ignore

- `VERCEL_URL`, `VERCEL_ENV` — deployment metadata, not secrets
- `NEXT_PUBLIC_VERCEL_URL` — public metadata

## Examples

True positive:
```yaml
env:
  VERCEL_TOKEN: aBcDeFgHiJkLmNoPqRsTuVwX
```

Report the projects the token has access to and whether it's in a CI/CD pipeline.
