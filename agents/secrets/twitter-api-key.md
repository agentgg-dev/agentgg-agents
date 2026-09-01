---
slug: twitter-api-key
name: Twitter/X API Key Exposure
description: 'Hardcoded Twitter/X API keys, bearer tokens (AAAA prefix), or OAuth access tokens in source or config. Full OAuth credentials allow posting, reading DMs, and performing account actions on behalf of users.'
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
    - regex: '\bAAAA[A-Za-z0-9%]{70,}\b'
      label: Twitter bearer token (AAAA prefix, 70+ chars)
    - regex: '(?i)(?:twitter|TWITTER_API_KEY|TWITTER_CONSUMER_KEY|TWITTER_SECRET|TWITTER_BEARER_TOKEN).{0,30}[=:"''\s]+[A-Za-z0-9%_\-]{25,}'
      label: Twitter API key or consumer key in named variable
    - regex: '(?i)(?:TWITTER_ACCESS_TOKEN|TWITTER_ACCESS_TOKEN_SECRET).{0,20}[=:"''\s]+[A-Za-z0-9\-]{25,}'
      label: Twitter access token in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Twitter/X API credentials.

## Credential types

**Bearer Token:** `AAAA...` + 70+ URL-safe base64 chars. App-only read access.

**API Key (Consumer Key):** 25 alphanumeric chars. Identifies the app.

**API Secret (Consumer Secret):** 50 alphanumeric chars. Authenticates the app — do not expose.

**Access Token + Access Token Secret:** per-user OAuth 1.0a tokens for acting on behalf of users.

## What leaked credentials enable

**Bearer Token alone:** read public tweets, user profiles, search (useful for targeted reconnaissance).

**Full OAuth set (API key + secret + access token + access token secret):** post tweets, send/read DMs, follow/unfollow accounts — complete account control for authorized users.

## True positive criteria

Flag at high severity:
1. Full OAuth credential set (API key + API secret + access tokens) hardcoded together

Flag at medium severity:
2. Bearer token hardcoded — read-only but still should not be exposed

## What to ignore

- Environment variable references: `os.environ['TWITTER_API_KEY']`

## Examples

True positive:
```python
auth = tweepy.OAuth1UserHandler(
    consumer_key='AbCdEfGhIjKlMnOpQrStUvWxY',
    consumer_secret='AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStU',
    access_token='1234567890-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn',
    access_token_secret='AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQr'
)
```

Report which credential types are present and what operations the code performs (post tweets, read DMs, etc.).
