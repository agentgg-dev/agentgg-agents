---
slug: okta-api-token
name: Okta API Token Exposure
description: 'Hardcoded Okta API tokens (00 + 40 alphanumeric chars) in source or config. Okta tokens grant Identity Provider admin access: user enumeration, authentication bypass, app assignment, and policy modification.'
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
    - regex: '(?i)(?:okta|ssws).{0,40}\b(00[a-zA-Z0-9_-]{39}[a-zA-Z0-9_])\b'
      label: Okta API token (00 prefix, 41 chars)
    - regex: '\bSSWS\s+00[a-zA-Z0-9_-]{39}[a-zA-Z0-9_]\b'
      label: Okta SSWS authorization header value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Okta API tokens. Okta is a major Identity Provider (IdP) — a leaked API token grants admin-level access to the organization's identity system.

## Token format

Okta API tokens always begin with `00` followed by 39 more alphanumeric characters (including `-` and `_`), totaling 41 characters. They appear in HTTP headers as:
```
Authorization: SSWS 00Tz3j8...xQ
```

Or in config as:
```yaml
OKTA_API_TOKEN: 00Tz3j8...xQ
```
```json
{ "apiToken": "00Tz3j8...xQ" }
```

## What a leaked token enables

Okta API tokens are tied to the user account that created them and inherit that user's permissions. Admin tokens grant:
- User enumeration and profile access (names, emails, phone numbers)
- User deactivation and password reset
- Viewing and modifying MFA factors for any user
- App assignment and group membership changes
- Modifying authentication policies
- Reading all OAuth clients and their secrets

## Cross-file analysis

When a token is found:
1. Check what Okta API endpoints the code calls — determines blast radius
2. Look for the `oktaDomain` / `orgUrl` to identify which Okta org is affected
3. Check if the token appears in CI/CD config — indicates it may be a service account token with elevated privileges

## True positive criteria

Flag when ALL hold:
1. The value matches `00[a-zA-Z0-9_-]{40}` and appears near "okta", "ssws", or an Okta domain
2. It is a string literal — not `process.env.OKTA_API_TOKEN` or `${OKTA_TOKEN}`
3. The value is not obviously fake (all zeros, `00XXXXX...`, documentation placeholders)

## What to ignore

- Environment variable references: `process.env.OKTA_API_TOKEN`, `os.environ['OKTA_API_TOKEN']`
- Placeholder values: `00YourOktaApiTokenHere`, `00PLACEHOLDER00000...`
- Okta client IDs (alphanumeric, no `00` prefix) — these are public OAuth client identifiers

## Examples

True positives:
```yaml
okta:
  domain: dev-12345678.okta.com
  apiToken: 00Tz3j8aBcDefGh...xQ
```
```ts
const client = new Client({
  orgUrl: 'https://company.okta.com',
  token: '00Tz3j8aBcDefGh...xQ'
});
```

False positives to skip:
```ts
const client = new Client({
  orgUrl: process.env.OKTA_ORG_URL,
  token: process.env.OKTA_API_TOKEN
});
```

Report the Okta org domain if visible, what API operations the token is used for, and whether it appears in CI/CD config (indicates elevated permissions).
