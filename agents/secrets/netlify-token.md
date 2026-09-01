---
slug: netlify-token
name: Netlify API Token Exposure
description: 'Hardcoded Netlify personal access tokens in source or config. Grants full API access to Netlify sites, deployments, environment variables, and DNS settings for the account.'
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
    - regex: '(?i)(?:netlify|NETLIFY_TOKEN|NETLIFY_AUTH_TOKEN|NETLIFY_ACCESS_TOKEN).{0,30}[=:"''\s]+[a-f0-9\-]{30,50}'
      label: Netlify token in named variable
    - regex: '(?i)(?:netlify|NETLIFY).{0,30}[=:"''\s]+[A-Za-z0-9_\-]{36,40}\b'
      label: Netlify personal access token (UUID-like)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Netlify API tokens.

## Token format

Netlify personal access tokens are UUID or long alphanumeric strings (36-48 chars), found in `NETLIFY_AUTH_TOKEN` or `NETLIFY_TOKEN` environment variables.

## What a leaked token enables

- Trigger new deployments or rollbacks
- Read and modify all environment variables for all sites (these often contain database URLs, API keys, etc.)
- Access deployment logs
- Modify DNS records and custom domain configuration
- Add persistent build hooks

## True positive criteria

Flag when ALL hold:
1. UUID or long alphanumeric string near "netlify", `NETLIFY_TOKEN`, or `NETLIFY_AUTH_TOKEN`
2. String literal, not `${{ secrets.NETLIFY_AUTH_TOKEN }}`
3. Not a placeholder or site ID (site IDs are also UUIDs but appear in `NETLIFY_SITE_ID`)

## Examples

True positive:
```yaml
env:
  NETLIFY_AUTH_TOKEN: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Report which sites are managed and whether the token appears in CI/CD.
