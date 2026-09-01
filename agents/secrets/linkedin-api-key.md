---
slug: linkedin-api-key
name: LinkedIn API Client Secret Exposure
description: 'Hardcoded LinkedIn OAuth client ID or client secret committed to source. Client secrets allow generating OAuth access tokens impersonating the application, enabling access to LinkedIn user profiles, connections, and messaging.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)linkedin.{0,30}(?:secret|client_secret|client_id).{0,30}[=:"''\s]+[a-z0-9]{16}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: LinkedIn OAuth credential near linkedin keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)linkedin.{0,30}(?:api|app|client|consumer|secret|key).{0,15}[=:"''\s]+\b([a-z0-9]{16})\b'
      label: LinkedIn 16-char client ID or secret
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded LinkedIn API credentials.

## Credential types

LinkedIn uses OAuth 2.0 with:
- **Client ID**: 14-16 char alphanumeric — identifies the app. Not secret but should not be committed.
- **Client Secret**: 16 char alphanumeric — used to exchange authorization codes for access tokens. Critical.

## What a leaked client secret enables

- Exchange any valid LinkedIn authorization code for an access token (CSRF on OAuth flow)
- Access LinkedIn user profiles, connections, email addresses, and messages with user permissions
- Post on behalf of users, manage company pages, access LinkedIn Ads data

## True positive criteria

Flag at critical:
1. `LINKEDIN_CLIENT_SECRET` or `LINKEDIN_SECRET` set to a 16-char alphanumeric literal

Flag at high:
2. `LINKEDIN_CLIENT_ID` set to a 16-char literal (less critical but identifies the app)

## What to ignore

- `process.env.LINKEDIN_CLIENT_SECRET` — safe env reference
- LinkedIn profile IDs, organization IDs — not secrets
- LinkedIn access tokens beginning with `AQ` — user-specific, separate from app credentials

Report: whether client ID, client secret, or both are present, and what LinkedIn API scopes the application appears to use (visible from OAuth redirect config or scope parameters).
