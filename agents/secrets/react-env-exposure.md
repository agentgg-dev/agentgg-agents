---
slug: react-env-exposure
name: React App Environment Credential Exposure
description: 'REACT_APP_* environment variables containing passwords, secrets, or tokens set to literal values in .env files or source — these values are compiled into the JavaScript bundle and served to every browser.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/.env*'
    - '**/*.env'
    - '**/env.js'
    - '**/env.ts'
    - '**/*.config.js'
    - '**/*.config.ts'
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
  preFilter:
    - regex: 'REACT_APP_[A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PWD)[A-Z0-9_]*\s*='
      label: REACT_APP_ credential variable set
    - regex: 'VITE_[A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PWD)[A-Z0-9_]*\s*='
      label: VITE_ credential variable set (Vite bundler equivalent)
    - regex: 'NEXT_PUBLIC_[A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|AUTH)[A-Z0-9_]*\s*='
      label: NEXT_PUBLIC_ credential variable set (Next.js public env)
references:
  - CWE-312
  - CWE-798
  - 'OWASP-A02:2021'
---

You are reviewing `.env` files and config for credential values set in publicly-exposed environment variable prefixes. `REACT_APP_`, `VITE_`, and `NEXT_PUBLIC_` prefixes cause variables to be compiled into the client-side JavaScript bundle — they are visible to every user who opens the browser DevTools.

## Why this matters

Create React App, Vite, and Next.js all expose any env variable with the appropriate prefix directly into the compiled JavaScript bundle. Unlike server-side `process.env`, these values end up in the source of the downloaded JS file and can be extracted by:
- Opening DevTools > Sources and searching the bundle
- Running `strings` on the minified JS
- Using `process.env.REACT_APP_SECRET` in the browser console

**Any secret set here is effectively public.**

## Variable prefixes that are public by design

| Bundler | Public prefix | Scope |
|---|---|---|
| Create React App | `REACT_APP_` | All vars with this prefix |
| Vite | `VITE_` | All vars with this prefix |
| Next.js | `NEXT_PUBLIC_` | Only vars with this prefix (others stay server-side) |

Next.js is less risky because variables without `NEXT_PUBLIC_` stay server-side. But `NEXT_PUBLIC_*_SECRET` or `NEXT_PUBLIC_*_PASSWORD` is still a clear mistake.

## What to look for

A variable set to an actual credential value (not a reference):
```
REACT_APP_API_PASSWORD=hunter2
REACT_APP_STRIPE_SECRET_KEY=sk_live_...
VITE_FIREBASE_API_SECRET=ABcdefghijk...
NEXT_PUBLIC_AUTH_TOKEN=eyJhbGciO...
```

vs. a safe server-side variable (no public prefix, stays in `process.env`):
```
STRIPE_SECRET_KEY=sk_live_...   # server-side only, safe pattern
```

## True positive criteria

Flag when ALL hold:
1. A `REACT_APP_`, `VITE_`, or `NEXT_PUBLIC_` variable contains a word suggesting a secret: `PASS`, `SECRET`, `KEY`, `TOKEN`, `AUTH`, `CREDENTIAL`, `PWD`
2. The value is set to a real literal (not empty, not `your-value-here`, not `${VAR}`)
3. The credential value is non-trivial (not `true`/`false`, not a URL without embedded credentials)

## Special cases

**API keys designed to be public:** some services (Firebase client apiKey, Stripe publishable key `pk_live_...`) are intended to be in the browser. The LLM should check whether the key is a *publishable* or *secret* key:
- `pk_live_...` = Stripe publishable key — safe to expose
- `sk_live_...` = Stripe secret key — never expose client-side

**Firebase client config:** the `apiKey` in a Firebase client config is designed to be public — but `REACT_APP_FIREBASE_ADMIN_SDK_PRIVATE_KEY` or a service account key is not.

## What to ignore

- Variables with appropriate public prefixes that contain only non-secret values (URLs, feature flags, app names, public IDs)
- `.env.example` or `.env.template` files with placeholder values (verify the value looks like a placeholder, not a real credential)
- Server-side variables without a public prefix — those stay in `process.env` and are not bundled

## Examples

True positives:
```
# .env committed to repo
REACT_APP_STRIPE_SECRET_KEY=sk_live_abc123...
REACT_APP_DATABASE_PASSWORD=Pr0dP@ssw0rd
VITE_AUTH_SECRET=supersecretjwtsigningkey
```

False positives to skip:
```
# Stripe publishable key — designed to be public
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_abc123...

# Placeholder in .env.example
REACT_APP_API_PASSWORD=your-password-here

# Server-side only — not bundled
STRIPE_SECRET_KEY=sk_live_abc123...
```

Report the variable name, whether the value appears to be a real credential vs a placeholder, and if identifiable, what service it belongs to (Stripe, Firebase, internal API, etc.).
