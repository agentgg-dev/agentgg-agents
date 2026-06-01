---
slug: secrets-exposure
name: Hardcoded Secrets in Source
description: 'API keys, tokens, passwords, and private keys committed to source files — including split-literal attempts to evade secret scanners.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
      - py
      - rb
      - go
      - rs
      - php
      - java
      - kt
      - cs
      - sh
      - json
      - yaml
      - yml
      - toml
      - ini
      - conf
      - cfg
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - rs
    - php
    - java
    - kt
    - cs
    - sh
    - json
    - yaml
    - yml
    - toml
    - ini
    - conf
    - cfg
  filePatterns:
    - '**/.env*'
references:
  - CWE-798
  - 'OWASP-A07:2021'
---

You are reviewing source code for hardcoded credentials that should
be loaded from a secret manager or environment variable instead.

This agent complements `default/hardcoded-secrets.md` by being more
aggressive about split-literal patterns (a common attempt to hide
secrets from scanners) and config-file variants.

## What to look for

**Contiguous issuer-format secrets:**
- Stripe: `sk_live_...`, `sk_test_...`
- Google API: `AIza...` (39 chars total)
- GitHub: `ghp_...`, `gho_...`, `ghs_...`, `github_pat_...`
- AWS access key: `AKIA...` (20 chars)
- Bearer token: `Bearer <40+ char base64>`
- 32+ char hex strings that look like keys
- PEM blocks: `-----BEGIN ... PRIVATE KEY-----`

**Split-literal evasion:**
```ts
const stripe = "sk_live_" + "REDACTEDxxxxxxxxxxxxxxxx";
const key = "AIza" + "REDACTEDxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const tok = "ghp_" + "REDACTEDxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
```
The pieces don't trip GitHub's secret-scanning push protection, but
the runtime concatenation produces a real credential.

**Hardcoded passwords and tokens in JSON/YAML/env files committed
to the repo:**
```yaml
db_password: "P@ssw0rd!"
```
```env
JWT_SECRET=supersecret
```

**Variable names that signal "secret":**
`*Secret*`, `*Token*`, `*Key*`, `*Password*`, `*Credential*`,
`apiKey`, `privateKey`, `accessKey`.

## True positive criteria

Flag when ANY of the following hold:

1. A contiguous string matching a known issuer format
   (`sk_live_...`, `AIza...`, `AKIA...`, `ghp_...`).
2. A `Bearer <token>` literal with 20+ characters of token body.
3. A 64-char hex string assigned to a `*Secret*` / `*Key*` /
   `*Token*` variable.
4. A split-literal that concatenates an issuer prefix with a body
   of 16+ characters.
5. A `.env`-format file (not gitignored) containing
   `*_SECRET=somevalue` with a non-placeholder value.

## What to ignore

- Test fixtures with synthetic secrets clearly marked as such
  (`"sk_test_4242424242424242"`, `"REDACTED"`, `"test-secret"`).
- Example files (`.env.example`, `config.example.yml`).
- Placeholder values: `"changeme"`, `"your-key-here"`, `"<your-token>"`.
- Hashes that are clearly content digests (e.g., `sha256:abc...` in
  a Dockerfile FROM line).
- Files inside `__tests__`, `__mocks__`, `__fixtures__`.

## Examples

True positives:
```ts
// Issuer-format secret
const stripeKey = "sk_live_<REDACTED_EXAMPLE>";

// Split-literal evasion
const apiKey = "AI" + "za<REDACTED_EXAMPLE>";

// PEM block
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIE...`;

// .env committed
// .env
JWT_SECRET=supersecret-real-prod-value
```

False positives to skip:
```ts
// Test fixture
const TEST_STRIPE_KEY = "sk_test_4242424242424242";

// Placeholder
const apiKey = process.env.API_KEY ?? "your-key-here";
```
