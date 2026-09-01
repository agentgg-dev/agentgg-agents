---
slug: process-env-access
name: process.env Access (Review Site)
description: 'Any direct process.env access — review site for hardcoded fallbacks, client-bundle leaks, env-as-bool bugs, and missing-env auth bypass. Noisy by design; pairs with more targeted exposure agents.'
version: 0.1.0
author: agentgg
noiseTier: noisy
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
      - lua
      - go
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - lua
    - go
  preFilter:
    - semgrepRule: exposure/process-env-access
      label: process.env access with secret-shaped name or fallback literal
references:
  - CWE-200
  - CWE-1188
---

You are reviewing source code at every `process.env` access point.
This is a deliberately broad sweep — the access itself is not a bug,
but the access site is the place where many subtle bugs live:

- Hardcoded fallback that disables a security check when env is unset
- Env value read in client-bundled code, leaking the value
- Env string compared as boolean (`'false'` is truthy in JS)
- Missing required env var causing the app to start with no auth

This is the noisiest agent in the exposure category — use it when you
want a full inventory of env touch-points, not when you want only
clear-cut issues. For specific issues, prefer:
- `secret-in-fallback` for `?? "default"` patterns
- `env-exposure` for `NEXT_PUBLIC_*_SECRET` and `"use client"` leaks
- `env-var-as-bool` for `'false'` truthiness bugs

## What to look for

Every line that contains:
```ts
process.env.SOMETHING
process.env["SOMETHING"]
process.env['SOMETHING']
```

For each match, evaluate:

1. **Is there a fallback?** `?? "..."`, `|| "..."` — flag if the
   variable looks like a secret (see `secret-in-fallback`).
2. **Is this file client-bundled?** Look for `"use client"` at the
   top, or a directory path implying client code (`src/components/`,
   `app/**/(client)/`). Flag if the env name is sensitive (see
   `env-exposure`).
3. **Is the value compared truthy?** `if (process.env.FLAG)` will be
   true for `"false"`. Flag if the variable controls security
   behavior (see `env-var-as-bool`).
4. **Is there a null check before use?** `const x = process.env.X;
   db.connect(x);` — if `x` is undefined, the call fails at runtime
   with no clear message. Not a security issue but worth noting.

## True positive criteria

This agent flags every `process.env.*` site. The validity of each
finding depends on what the surrounding code does with the value.
Use it as input to a manual or automated downstream check.

## What to ignore

- Tests, mocks, fixtures.
- `node_modules`, `.next`, `dist`, type definition files.
- Build / deploy scripts.

## Examples

Flagged (all are flagged — relevance depends on context):
```ts
const url = process.env.DATABASE_URL;
const key = process.env.API_KEY ?? "fallback";
if (process.env.NODE_ENV === "development") doStuff();
const cfg = process.env["MY_VAR"];
const secret = process.env['SESSION_SECRET'];
```
