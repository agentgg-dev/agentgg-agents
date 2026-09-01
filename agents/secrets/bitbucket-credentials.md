---
slug: bitbucket-credentials
name: Bitbucket OAuth Credentials Exposure
description: 'Hardcoded Bitbucket OAuth client ID or client secret committed to source. Client secrets allow generating access tokens to read/write repositories and manage team settings.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)bitbucket.{0,30}[=:"''\s]+[a-z0-9]{32}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Bitbucket credential near bitbucket keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{32})(?:[''"\n\r\s`;]|$)'
      label: Bitbucket 32-char client ID or secret
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Bitbucket OAuth credentials.

## Credential types

- **OAuth Consumer Key (Client ID)**: 32-char alphanumeric — identifies the OAuth app. Semi-public but should not be committed.
- **OAuth Consumer Secret (Client Secret)**: 32-char alphanumeric — secret that allows generating OAuth tokens. Critical if exposed.

## What a leaked client secret enables

- Generate OAuth access tokens for any user who has authorized the OAuth consumer
- Access private repositories, pipeline configurations, and deployment keys
- Modify repository settings and webhooks if the consumer has write permissions

## True positive criteria

Flag at critical:
1. `BITBUCKET_CLIENT_SECRET`, `BITBUCKET_OAUTH_SECRET`, `BITBUCKET_SECRET` set to a 32-char string literal

Flag at high:
2. `BITBUCKET_CLIENT_ID` or `BITBUCKET_KEY` set to a 32-char string literal (client ID is less sensitive but still should not be committed)

## What to ignore

- `process.env.BITBUCKET_CLIENT_SECRET` — safe env reference
- Bitbucket repository names or URLs — not secrets
- Bitbucket workspace slugs — public identifiers

Report: whether client ID, client secret, or both are present, and whether they appear in CI/CD configs where they could be logged.
