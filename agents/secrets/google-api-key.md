---
slug: google-api-key
name: Google API Key / OAuth Secret Exposure
description: 'Hardcoded Google API keys (AIza[35 chars]), OAuth client secrets (GOCSPX-[28 chars]), or OAuth access tokens (ya29.*) in source or config. Risk depends on the enabled APIs: Maps billing abuse, Firebase data access, Cloud Storage reads, or full GCP account access.'
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
    - regex: 'AIza[0-9A-Za-z\-_]{35}'
      label: Google API key (AIza prefix)
    - regex: 'GOCSPX-[a-zA-Z0-9_-]{28}'
      label: Google OAuth client secret (GOCSPX-)
    - regex: 'ya29\.[0-9A-Za-z\-_]+'
      label: Google OAuth access token (ya29.)
    - regex: '(?i)\b([0-9]+-[a-z0-9_]{32})\.apps\.googleusercontent\.com'
      label: Google OAuth client ID
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Google API credentials.

## Credential types

**API Key (`AIza[35 chars]`):** Identifies a Google Cloud project and grants access to any API enabled on that project. APIs that carry high risk when key-restricted: Maps JavaScript API (billing abuse via usage inflation), Firebase Realtime Database/Firestore (data read/write if rules are permissive), Cloud Translation, Vision, Natural Language. Some API keys are intentionally public (Maps embed keys); others are server-side secrets.

**OAuth Client Secret (`GOCSPX-[28 chars]`):** Together with the client ID, this is used to exchange authorization codes for access tokens in OAuth 2.0 flows. Leaking the client secret allows an attacker to impersonate the application in OAuth flows, potentially hijacking user sessions.

**OAuth Access Token (`ya29.*`):** Short-lived credential representing a user or service account's current session. If found in code, it may still be valid (typical lifetime 1 hour). Allows the attacker to call any Google API the token has scope for.

**OAuth Client ID (`{project_number}-{32 chars}.apps.googleusercontent.com`):** Identifies the OAuth application. By itself it is semi-public (used in browser-side flows), but its presence alongside the client secret or access token is the real risk.

## Risk assessment by API

- **Maps / Places / Geocoding:** Billing abuse if the key has no HTTP referrer restriction — attacker generates millions of API calls, charging the victim account
- **Firebase / Firestore:** Data exposure and modification if Firestore security rules are weak — key + project ID grants read/write
- **Cloud Storage:** Object download if the key has storage scope
- **Gmail / Drive / Calendar:** OAuth access token with these scopes gives full account-level data access
- **Google Cloud APIs (Compute, IAM, Secret Manager):** Critical — service account keys or tokens with cloud scopes give GCP infrastructure access

## Cross-file analysis

When a key is found, look for:
1. The Google Cloud project ID in the same file or nearby — helps determine which project is exposed
2. The list of APIs enabled (check the code for which Google APIs are called)
3. For OAuth flows, whether the client secret appears alongside a client ID and redirect URI
4. Application restrictions configured on the key (IP allowlist, HTTP referrer restrictions)

## True positive criteria

Flag when ALL hold:
1. The value matches the pattern and is a complete credential
2. It is a string literal, not an environment variable reference (`process.env.GOOGLE_API_KEY`, `os.environ.get('GOOGLE_API_KEY')`)
3. For `AIza` keys: not obviously a public Maps embed key with an HTTP referrer restriction (check the surrounding code — if it calls Maps from a `<script>` tag and the key is meant to be public, note the lower severity)
4. Not a placeholder

Note: Google API keys intended for client-side Maps use are often meant to be "public" but should still have HTTP referrer restrictions — flag them if no restriction is visible.

## What to ignore

- Environment variable references
- Service account JSON key files handled through secret managers or mounted as volumes, not hardcoded
- `ya29.*` tokens in test fixture files that are clearly expired/fake
- Client IDs alone (without secret or access token)

## Examples

True positives:
```ts
const map = new google.maps.Map(document.getElementById('map'), {
  center: { lat: -34.397, lng: 150.644 },
  zoom: 8,
});
// Key visible in the <script> src with no referrer restriction noted
// src="https://maps.googleapis.com/maps/api/js?key=AIza<35-char-api-key>"
```
```python
credentials = {
  "client_id": "<project-number>-<32-chars>.apps.googleusercontent.com",
  "client_secret": "GOCSPX-<28-char-secret>"
}
```

False positives to skip:
```ts
const apiKey = process.env.GOOGLE_API_KEY;
```

Rate the finding based on which APIs the key enables. A Maps key with a strict HTTP referrer restriction is low severity; a server-side key with Cloud Storage or Firebase admin access is critical.
