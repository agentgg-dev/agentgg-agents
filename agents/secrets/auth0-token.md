---
slug: auth0-token
name: Auth0 Management API Token Exposure
description: 'Hardcoded Auth0 Management API tokens or client secrets in source or config. Management API tokens grant admin-level access to the Auth0 tenant: users, roles, connections, and application credentials.'
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
    - regex: '(?i)(?:auth0).{0,40}\bey[A-Za-z0-9._-]{20,}\b'
      label: Auth0 Management API JWT near "auth0"
    - regex: '(?i)(?:AUTH0_CLIENT_SECRET|AUTH0_MANAGEMENT_TOKEN|AUTH0_API_TOKEN)\s*[=:]\s*[''"]?[A-Za-z0-9_\-]{20,}'
      label: Auth0 client secret or management token env var with value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Auth0 credentials. Auth0 manages user authentication — leaking these credentials gives admin access to the entire Auth0 tenant.

## Credential types

**Client Secret (32-64 alphanumeric chars):** authenticates the application with Auth0. Enables generating access tokens for any user.

**Management API Token (JWT, `ey...`):** grants full admin access — read/modify all users, roles, connections, and application configs.

## What leaked credentials enable

**Client Secret:** generate access tokens for any user, impersonate users, sign arbitrary tokens.

**Management API Token:** read all users (email, phone, MFA status), update passwords, delete users, read/modify all application configurations.

## True positive criteria

Flag when ALL hold:
1. A JWT (`ey...`) or opaque credential appears within 40 chars of "auth0"
2. Or `AUTH0_CLIENT_SECRET`/`AUTH0_MANAGEMENT_TOKEN` contains a literal value
3. Not an env var reference or placeholder

## What to ignore

- `AUTH0_CLIENT_ID` and `AUTH0_DOMAIN` — public values, not secrets

## Examples

True positives:
```env
AUTH0_CLIENT_SECRET=AbCdEfGhIjKlMnOpQrStUvWxYz123456
AUTH0_MANAGEMENT_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

Report the credential type (client secret vs management token), the Auth0 domain, and what the code does with it.
