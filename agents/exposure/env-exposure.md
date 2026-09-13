---
slug: env-exposure
name: Server Env Vars Exposed to Client Bundle
description: 'Client-bundled env prefixes (NEXT_PUBLIC_, REACT_APP_, VITE_, PUBLIC_) on variables named after secrets (*_SECRET / _KEY / _TOKEN / _PASSWORD), or process.env accessed in ''use client'' files where the value lands in the client bundle.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  filePatterns:
    - '**/.env*'
    - '**/next.config.*'
    - '**/*.env'
    - '**/env.js'
    - '**/env.ts'
    - '**/*.config.js'
    - '**/*.config.ts'
    - '.env.example'
    - '.env.template'
  preFilter:
    - semgrepRule: exposure/process-env-access
      label: process.env access for a secret-named or NEXT_PUBLIC_ variable
    - regex: 'REACT_APP_[A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PWD)[A-Z0-9_]*\s*='
      label: REACT_APP_ credential variable set
    - regex: 'VITE_[A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PWD)[A-Z0-9_]*\s*='
      label: VITE_ credential variable set (Vite bundler equivalent)
    - regex: 'NEXT_PUBLIC_[A-Z0-9_]*(?:PASS|SECRET|KEY|TOKEN|AUTH)[A-Z0-9_]*\s*='
      label: NEXT_PUBLIC_ credential variable set (Next.js public env)
references:
  - CWE-200
  - CWE-312
  - 'OWASP-A05:2021'
---

You are reviewing JavaScript / TypeScript code for environment
variables that leak from server to client. There are two failure
modes:

1. **`NEXT_PUBLIC_*` variables** are inlined into the client bundle
   by Next.js. Naming a secret `NEXT_PUBLIC_API_SECRET` defeats the
   intent — the value ships to every visitor's browser.
2. **`process.env.*` accessed in `"use client"` files** (or in
   Vite/Webpack-bundled client code via `import.meta.env`) is
   substituted at build time and ends up in the browser bundle.

## What to look for

**`NEXT_PUBLIC_*` named for secrets:**
```ts
const k = process.env.NEXT_PUBLIC_API_SECRET;
const t = process.env.NEXT_PUBLIC_AUTH_TOKEN;
const p = process.env.NEXT_PUBLIC_USER_PASSWORD;
const c = process.env.NEXT_PUBLIC_OAUTH_CREDENTIAL;
const k = process.env.NEXT_PUBLIC_STRIPE_KEY;
```
Any `NEXT_PUBLIC_` env var whose name contains `SECRET`, `KEY`,
`TOKEN`, `PASSWORD`, `CREDENTIAL`, `PRIVATE` is suspicious.

**`process.env` accessed in `"use client"` file:**
```ts
"use client";
const s = process.env.API_SECRET;
const k = process.env.PRIVATE_KEY;
```
Even without `NEXT_PUBLIC_`, build-time replacement may inline the
value into the client bundle.

**`import.meta.env` exposed values (Vite/SvelteKit):**
Vite exposes `VITE_*` env vars to the client. The same rule applies:
`VITE_API_SECRET`, `PUBLIC_*` (SvelteKit), etc. with secret-sounding
names are suspicious.

**`REACT_APP_*` variables (Create React App):**
```env
REACT_APP_API_PASSWORD=hunter2
REACT_APP_STRIPE_SECRET_KEY=sk_live_...
REACT_APP_DATABASE_PASSWORD=Pr0dP@ssw0rd
```
Create React App compiles every `REACT_APP_*` variable into the
JavaScript bundle, so the value is readable in DevTools Sources, by
running `strings` on the minified JS, or from the browser console.
Anything set under this prefix is effectively public.

Four prefixes are public by design and carry the same rule:
`REACT_APP_` (Create React App), `VITE_` (Vite), `NEXT_PUBLIC_`
(Next.js), `PUBLIC_` (SvelteKit). Next.js is the narrowest of the
four, since variables without the prefix stay server-side, but
`NEXT_PUBLIC_*_SECRET` is still a mistake. Flag a variable under any
of these prefixes whose name contains `PASS`, `SECRET`, `KEY`,
`TOKEN`, `AUTH`, `CREDENTIAL`, `PRIVATE`, or `PWD` and whose value is
a real literal rather than a reference such as `${VAR}`.

**`.env` files leaking secret-named vars with public prefix:**
```env
NEXT_PUBLIC_STRIPE_SECRET=sk_live_xxx     # secret with public prefix!
```

## True positive criteria

Flag when ANY of the following hold:

1. A `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, or `PUBLIC_*`
   (SvelteKit) env var name contains `SECRET`, `KEY`, `TOKEN`,
   `PASSWORD`, `PASS`, `AUTH`, `PWD`, `CREDENTIAL`, or `PRIVATE`,
   and the value is a real literal.
2. `process.env.*` is accessed in a file that contains `"use client"`
   or under a client-only directory (`src/components/`, `app/**/page.tsx`
   marked client).
3. An `.env*` file declares a `NEXT_PUBLIC_*` variable with a
   secret-shaped name.

Check publishable against secret before flagging a key: `pk_live_...`
is a Stripe publishable key and belongs in the browser, `sk_live_...`
never does. The `apiKey` in a Firebase client config is public by
design, but `REACT_APP_FIREBASE_ADMIN_SDK_PRIVATE_KEY` or a service
account key is not.

## What to ignore

- `NEXT_PUBLIC_*` variables for genuinely public values: feature
  flags, Stripe **publishable** keys (`pk_*`), Google Analytics IDs,
  Sentry DSN client public keys.
- Public-prefix variables holding non-secret values: URLs, feature
  flags, app names, public IDs.
- Server-side variables with no public prefix (`STRIPE_SECRET_KEY=...`)
  since those stay in `process.env` and are not bundled.
- `.env.example` and `.env.template` values that read as placeholders.
  Confirm the value looks like a placeholder and not a real
  credential.
- `process.env.NODE_ENV` and `process.env.VERCEL_ENV` — these are
  build-time constants that don't carry secrets.
- Server components (Next.js App Router files without `"use client"`)
  and `getServerSideProps` — these run on the server.
- Test files.

## Examples

True positives:
```ts
// Secret with NEXT_PUBLIC_ prefix
const apiSecret = process.env.NEXT_PUBLIC_API_SECRET;

// process.env in client component
"use client";
import { useState } from "react";
const dbUrl = process.env.DATABASE_URL;
```

```env
# .env committed to the repo
REACT_APP_STRIPE_SECRET_KEY=sk_live_abc123...
REACT_APP_DATABASE_PASSWORD=Pr0dP@ssw0rd
VITE_AUTH_SECRET=supersecretjwtsigningkey
```

False positives to skip:
```ts
// Publishable key — public by design
const stripe = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;

// Server component — no "use client"
// app/dashboard/page.tsx
const secret = process.env.JWT_SECRET;   // server-only
```

```env
# Publishable key, designed to be public
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_abc123...

# Placeholder in .env.example
REACT_APP_API_PASSWORD=your-password-here

# Server-side only, not bundled
STRIPE_SECRET_KEY=sk_live_abc123...
```

Report the variable name, whether the value reads as a real credential
or a placeholder, and the service it belongs to when that is
identifiable.
