---
slug: oauth-flow
name: OAuth Flow Issues
description: OAuth authorize / callback handlers — missing state parameter, missing PKCE, open redirect_uri matching, access_token in URL fragment, code in URL query persisted in logs. Walker mode follows OAuth flow across authorize/callback files and shared validators.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/oauth/**/*.{ts,tsx,js,jsx}"
  - "**/auth/**/*.{ts,tsx,js,jsx}"
  - "**/callback/**/*.{ts,tsx,js,jsx}"
  - "**/app/api/**/*.{ts,tsx,js,jsx}"
  - "**/api/**/*.{ts,tsx,js,jsx}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "\\b(authorize|authorization)\\b[\\s\\S]{0,200}\\bclient_id\\b"
    label: "OAuth authorize URL construction"
  - regex: "\\b(code_verifier|code_challenge|code_challenge_method)\\b"
    label: "PKCE parameter"
  - regex: "\\bredirect_uri\\b"
    label: "redirect_uri reference (validate matching)"
  - regex: "[?&#]access_token="
    label: "access_token in URL (likely implicit grant or leak)"
  - regex: "[?&]state\\s*="
    label: "state parameter (validate binding to session)"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-1275
  - OWASP-A02:2021
---

You are reviewing OAuth 2.0 / OIDC flow code for the standard set of
implementation mistakes that allow account takeover or token theft.

**Walker mode advantage:** OAuth flows span at least two files
(authorize initiation and callback). The `state` you generate in
authorize must be the one validated in callback — confirm the binding
by reading both. PKCE check: if the authorize side stores
`code_verifier` in a session/cookie, the callback must read and use
it. `redirect_uri` validation is often a shared helper — open it and
verify it does exact matching against a pre-registered allowlist.

## What to look for

**Missing `state` parameter:**
The authorization request must include a `state` value that the
callback handler verifies, preventing CSRF on the OAuth flow. Flag
authorize-request builders that do not include `state=` and callback
handlers that do not validate it.

```ts
// Missing state
const authUrl = `${idp}/authorize?client_id=${id}&redirect_uri=${cb}&response_type=code`;
```

**Missing PKCE for public clients:**
Mobile apps and single-page apps must use PKCE (`code_challenge` /
`code_verifier`). Flag authorize requests from a SPA or mobile
context that do not include `code_challenge`.

```ts
// SPA — no PKCE
params.set("response_type", "code");
params.set("client_id", clientId);
// Missing code_challenge / code_challenge_method
```

**`redirect_uri` validated loosely:**
Treat `redirect_uri` validation with `includes`, loose regex, or
`startsWith` (without trailing `/`) as bypassable:
```ts
if (!redirectUri.startsWith("https://app.example.com")) throw error;
// Bypass: https://app.example.com.evil.com/callback
```
Safe: exact match against a pre-registered allowlist.

**`access_token` returned via URL fragment in a redirect:**
```ts
res.redirect(`https://app/cb#access_token=${token}`);
```
URL fragments are not sent to the server, so this is the implicit
grant flow — deprecated. Use authorization code + PKCE.

**Authorization `code` in URL query that gets logged:**
```ts
console.log(`Callback received: ${req.url}`);   // contains ?code=...
```
The code is single-use, but if logs aggregate to a third party,
short-lived but real risk.

**State parameter not validated as opaque + bound to the user
session:**
A reused or attacker-supplied `state` allows session fixation on the
OAuth flow. Flag callback handlers that check `state` exists but
not that it matches the value stored in the user's session.

## True positive criteria

Flag for review when:
1. File is in an `/oauth/`, `/auth/`, or `/callback/` path, OR contains
   OAuth keywords (`redirect_uri`, `authorization_code`,
   `code_verifier`, `state=`, `access_token`).
2. One of the misconfigurations above is visible OR the flow is
   built manually (instead of using a vetted library like
   `openid-client`, `next-auth`, `iron-session-auth`).

## What to ignore

- Use of established libraries (NextAuth, Better Auth, openid-client,
  Lucia) configured per their documented best practices.
- Tests / fixtures.
- Server-to-server (client credentials) flows where there is no user
  redirect and `state` is not applicable.

## Examples

True positives:
```ts
// No state parameter
const url = `${idp}/authorize?client_id=${cid}&redirect_uri=${cb}&response_type=code`;
res.redirect(url);

// access_token in fragment (implicit grant)
res.redirect(`${returnUrl}#access_token=${token}`);

// redirect_uri startsWith bypass
if (!redirectUri.startsWith("https://app.example.com")) throw new Error();

// Code logged
logger.info(`OAuth callback: ${req.url}`);
```

False positives to skip:
```ts
// Library handles state / PKCE correctly
import { OAuth2Client } from "google-auth-library";
const client = new OAuth2Client({ ... });
const authUrl = client.generateAuthUrl({ scope: [...], state, code_challenge });
```
