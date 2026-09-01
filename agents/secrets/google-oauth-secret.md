---
slug: google-oauth-secret
name: Google OAuth Client Secret Exposure
description: 'Hardcoded Google OAuth 2.0 client secrets committed to source. Allows forging OAuth flows and generating access tokens for Google APIs (Gmail, Drive, Calendar, GCP) on behalf of users who authorized the application.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'GOCSPX-[A-Za-z0-9\-_]{28}'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Google OAuth client secret (GOCSPX- prefix)
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: 'GOCSPX-[A-Za-z0-9\-_]{28}'
      label: Google OAuth client secret (new GOCSPX- format)
    - regex: '(?i)(?:google|goog|oauth).{0,20}client.{0,10}secret.{0,30}[=:"''\s]+[A-Za-z0-9\-_]{24,40}'
      label: Google OAuth client_secret field
    - regex: '"client_secret"\s*:\s*"[A-Za-z0-9\-_]{24,40}"'
      label: client_secret field in Google credentials JSON
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Google OAuth 2.0 client secrets.

## Credential formats

Google OAuth credentials come in two forms:

**New format (post-2021):**
- Client secret: `GOCSPX-` + 28 alphanumeric chars

**Legacy format:**
- Client ID: `XXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com`
- Client secret: 24-40 char alphanumeric string

**`credentials.json` file** (downloaded from Google Cloud Console):
```json
{
  "installed": {
    "client_id": "...",
    "client_secret": "GOCSPX-...",
    "redirect_uris": [...]
  }
}
```

## What a leaked client secret enables

With the client secret AND an authorization code (from a user clicking "Authorize"):
- Generate OAuth access tokens for any Google API the app is authorized for
- Access Gmail, Google Drive, Calendar, Google Cloud Platform APIs as the authorizing user
- For server-to-server flows: generate tokens without user interaction if combined with a service account

## True positive criteria

Flag at critical:
1. `GOCSPX-XXXX` string as a literal value (new format is unambiguous)
2. `credentials.json` file committed to the repository (contains client secret in JSON)
3. `client_secret` field in a JSON/YAML config with a non-placeholder value

## What to ignore

- `client_id` alone — the OAuth client ID is public-facing (embedded in authorization URLs)
- `process.env.GOOGLE_CLIENT_SECRET` — safe env reference
- Google API keys (`AIza...`) — covered by the google-api-key agent

## Special case: credentials.json

If a `credentials.json` or `client_secret_*.json` file is found, read its contents — it contains all OAuth credentials including the client secret and may also contain refresh tokens.

Report: the OAuth application name if visible from the client ID, what Google APIs the application uses (from nearby import statements or config), and whether refresh tokens are also committed.
