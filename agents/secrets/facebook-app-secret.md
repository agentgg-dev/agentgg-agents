---
slug: facebook-app-secret
name: Facebook App Secret Exposure
description: 'Hardcoded Facebook/Meta app secrets (32 hex chars near "facebook" or "fb") in source or config. App secrets generate access tokens for any user who granted the app permissions, and sign webhook payloads.'
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
    - regex: '(?i)(facebook|fb)(.{0,20})?[''"][0-9a-f]{32}[''"]'
      label: Facebook app secret (32 hex chars near "facebook"/"fb")
    - regex: '(?i)(FACEBOOK_SECRET|FACEBOOK_APP_SECRET|FB_APP_SECRET|facebook_app_secret)\s*[=:]\s*[''"]?[0-9a-f]{32}'
      label: Facebook app secret env var with value
    - regex: '(?i)(facebook_client_secret|FB_CLIENT_SECRET)\s*[=:]\s*[''"]?[0-9a-f]{32}'
      label: Facebook OAuth client secret with value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Facebook/Meta app secrets. The app secret is the server-side credential for Facebook's OAuth and Graph API — exposing it allows token forgery and unauthorized data access.

## Credential shapes

**App Secret (32 lowercase hex chars):**
```
FACEBOOK_APP_SECRET=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
```
Used to:
- Generate app access tokens
- Verify webhook signatures
- Exchange short-lived user tokens for long-lived tokens
- Sign server-to-server API requests

**App ID (numeric, 15-16 digits):** this is public — do not flag it alone.

The **pair** of App ID + App Secret is what grants API access. However, the secret alone is sufficient to forge signatures and generate app-level tokens.

## What a leaked app secret enables

1. **Token generation:** generate app access tokens and exchange authorization codes for user access tokens, acting as any user who authorized the app
2. **Webhook spoofing:** forge Facebook webhook payloads — if your server validates `X-Hub-Signature` using the app secret, an attacker can send fake events
3. **Long-lived token exchange:** convert any short-lived user access token (obtained via social engineering) into a 60-day token
4. **Graph API access:** depending on app permissions, access user profile data, posts, messages, or business pages for any user who granted access

## Cross-file analysis

When an app secret is found:
1. Look for the `appId` nearby — with both, an attacker can generate full access tokens
2. Check what Facebook permissions the app requests (`scope` parameter in OAuth) — determines data access
3. Check if webhook signature verification uses the secret — if so, fake events can trigger business logic

## True positive criteria

Flag when ALL hold:
1. A 32 lowercase hex string appears within 20 characters of "facebook", "fb", or a Facebook-related variable name
2. It is a string literal, not an environment variable reference
3. It is not a placeholder (all zeros, `your-app-secret-here`, repeated characters)

## What to ignore

- Facebook App IDs (numeric-only, no hex pattern)
- References like `process.env.FACEBOOK_APP_SECRET`, `os.environ['FB_APP_SECRET']`
- Facebook access tokens (user tokens are much longer, ~180+ chars, often starting with `EAA`)
- 32-char hex values in non-Facebook context (MD5 hashes, other service tokens)

## Examples

True positives:
```python
app = Facebook(
    app_id='123456789012345',
    app_secret='a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
)
```
```env
FACEBOOK_APP_SECRET=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
```

False positives to skip:
```python
app = Facebook(
    app_id=os.environ['FB_APP_ID'],
    app_secret=os.environ['FB_APP_SECRET']
)
```

Report the App ID if present (confirms which app is affected), what Facebook permissions the app uses, and whether the secret is used for webhook verification or OAuth token exchange.
