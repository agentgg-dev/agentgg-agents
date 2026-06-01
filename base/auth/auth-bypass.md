---
slug: auth-bypass
name: Authentication Bypass
description: 'Auth checks that can be bypassed — weak boolean comparisons against client data, dev-mode skip flags, truthy session checks that don''t validate the session, missing await on async verifiers. Traces verifier helpers and env-flag definitions.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: (SKIP_AUTH|DISABLE_AUTH|BYPASS_AUTH|NO_AUTH|AUTH_DISABLED|DEV_MODE)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,java,kt,cs,php}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Dev/bypass auth env-var name
      - regex: 'NODE_ENV\s*(!==|===)\s*["'']production["'']'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,java,kt,cs,php}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: NODE_ENV branch gating auth
      - regex: if\s*\(\s*!?\s*(req\.|request\.|ctx\.)?session\s*\)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,java,kt,cs,php}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Truthy session check (no contents validated)
      - regex: '(req|request|ctx)\.(headers|body|query)[^=]*===?\s*["''](admin|true|1)["'']'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,java,kt,cs,php}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Role/auth flag compared against client data
      - regex: if\s*\(\s*(verifyToken|verifyJwt|isAuthenticated|requireUser|assertAuth)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,java,kt,cs,php}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Async verifier potentially called without await
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
    - java
    - kt
    - cs
    - php
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/spec/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: (SKIP_AUTH|DISABLE_AUTH|BYPASS_AUTH|NO_AUTH|AUTH_DISABLED|DEV_MODE)\b
      label: Dev/bypass auth env-var name
    - regex: 'NODE_ENV\s*(!==|===)\s*["'']production["'']'
      label: NODE_ENV branch gating auth
    - regex: if\s*\(\s*!?\s*(req\.|request\.|ctx\.)?session\s*\)
      label: Truthy session check (no contents validated)
    - regex: '(req|request|ctx)\.(headers|body|query)[^=]*===?\s*["''](admin|true|1)["'']'
      label: Role/auth flag compared against client data
    - regex: if\s*\(\s*(verifyToken|verifyJwt|isAuthenticated|requireUser|assertAuth)\s*\(
      label: Async verifier potentially called without await
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-287
  - CWE-305
  - 'OWASP-A07:2021'
---

You are reviewing source code for authentication bypass — patterns
where an auth check exists but is structured in a way that lets an
unauthenticated or unprivileged caller slip through.

**Cross-file analysis:** to judge the "missing await" pattern,
open the verifier definition — if it's `async function verifyToken`
then `if (verifyToken(...))` is always truthy and a bug. For env-var
bypasses, search the repo for where the flag is set (CI configs,
.env.example) to assess whether it can plausibly leak to production.
For "truthy session" patterns, find the session-setup middleware to
see whether the session contains a verified user id or just an
anonymous shell.

## What to look for

**Auth flag compared against client data:**
```ts
if (user.isAdmin === req.body.isAdmin) { grant(); }
if (req.headers["x-role"] === "admin") { ... }
```
The client controls the comparison value.

**Truthy session check without validating session contents:**
```ts
if (req.session) { ... }     // any non-null session passes
if (!session) return null;   // proceeds for ANY session, not just authenticated ones
```
A session object exists even before login; checking only for its
presence does not validate authentication.

**Dev/staging skip flags reachable in production:**
```ts
if (process.env.NODE_ENV !== "production") return next();
if (process.env.SKIP_AUTH === "true") return next();
const bypassAuth = true;     // hardcoded
```
Flags like `SKIP_AUTH`, `DISABLE_AUTH`, `BYPASS_AUTH`, `DEV_MODE`
that disable auth — if the variable can be set in production or the
check is wrong, auth is off.

**Missing `await` on async verifiers:**
```ts
if (verifyToken(req.headers.authorization)) { grant(); }
//   ^^^^^^^^^^^^ returns a Promise, which is truthy — always grants
```

**Early-return on error treated as "auth passed":**
```ts
try {
  const decoded = jwt.verify(token, secret);
  req.user = decoded;
} catch (e) {
  // ignored — falls through to handler with no req.user check
}
// handler runs even if verify threw
```

**Comparison with `==` instead of `===`:**
```ts
if (req.body.role == "admin") { ... }  // type coercion edge cases
```

**Hardcoded auth bypass tokens in source:**
```ts
if (token === "let-me-in") return true;
```

## True positive criteria

Flag when an auth check is present but exhibits one of the patterns
above. The smell is: the check exists, but its effect is weaker than
intended.

## What to ignore

- Proper auth checks: `await verifyToken(...)` whose result is
  required before granting; `session.user?.id` checked, not just
  `session`.
- Dev-mode bypasses gated by a check that genuinely cannot be true
  in production (e.g., NODE_ENV checked AND the deployment process
  guarantees `NODE_ENV=production`).
- Test files / mock servers / fixtures.

## Examples

True positives:
```ts
// Truthy session
if (!session) return new Response("unauthorized", { status: 401 });
// session exists but user.id may not — handler still runs

// Missing await — Promise is truthy
if (verifyJwt(token)) { return handler(req); }

// Env var bypass
if (process.env.SKIP_AUTH) return handler(req);

// Hardcoded bypass token
if (req.headers["x-admin"] === "secret123") return adminPanel();
```

False positives to skip:
```ts
// Proper verification
const user = await verifyToken(token);
if (!user) throw new Error("unauthorized");

// Session content checked, not just presence
if (!session?.user?.id) return new Response("401", { status: 401 });
```
