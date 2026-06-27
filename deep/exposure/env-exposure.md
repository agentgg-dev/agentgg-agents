---
slug: env-exposure
name: Server Env Vars Exposed to Client Bundle
description: 'NEXT_PUBLIC_ variables named after secrets (NEXT_PUBLIC_*_SECRET / _KEY / _TOKEN), or process.env accessed in ''use client'' files where the value lands in the client bundle.'
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
references:
  - CWE-200
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

**`.env` files leaking secret-named vars with public prefix:**
```env
NEXT_PUBLIC_STRIPE_SECRET=sk_live_xxx     # secret with public prefix!
```

## True positive criteria

Flag when ANY of the following hold:

1. A `NEXT_PUBLIC_*`, `VITE_*`, or `PUBLIC_*` (SvelteKit) env var
   name contains `SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `CREDENTIAL`,
   or `PRIVATE`.
2. `process.env.*` is accessed in a file that contains `"use client"`
   or under a client-only directory (`src/components/`, `app/**/page.tsx`
   marked client).
3. An `.env*` file declares a `NEXT_PUBLIC_*` variable with a
   secret-shaped name.

## What to ignore

- `NEXT_PUBLIC_*` variables for genuinely public values: feature
  flags, Stripe **publishable** keys (`pk_*`), Google Analytics IDs,
  Sentry DSN client public keys.
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

False positives to skip:
```ts
// Publishable key — public by design
const stripe = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;

// Server component — no "use client"
// app/dashboard/page.tsx
const secret = process.env.JWT_SECRET;   // server-only
```
