---
slug: env-var-as-bool
name: Env Var Used as Boolean ("false" is truthy)
description: 'Security flag env vars (DISABLE_AUTH, SKIP_VERIFY, BYPASS_*) compared with if(process.env.X) — the string "false" is truthy in JavaScript, silently disabling the check.'
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
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
references:
  - CWE-1287
  - 'OWASP-A05:2021'
---

You are reviewing JavaScript / TypeScript source code for env vars
used as booleans where the string value `"false"` evaluates to truthy
and silently disables the surrounding behavior.

## The bug

In JavaScript, `if (process.env.X)` checks whether the env var is a
truthy *string*. Any non-empty string is truthy — including the
string `"false"`. So:

```ts
DISABLE_AUTH=false node app.js
// Inside the app:
if (process.env.DISABLE_AUTH) return next();   // entered! auth disabled
```

The operator probably set `DISABLE_AUTH=false` thinking it meant
"don't disable auth". It actually means the opposite.

## What to look for

**Security flag env vars used as truthy checks:**
```ts
if (process.env.SKIP_AUTH_CHECK) doStuff();
if (process.env.BYPASS_AUTH) return next();
if (process.env.NO_AUTH) return next();
if (process.env.DISABLE_VERIFY) bypassed = true;
if (process.env.BYPASS_CHECK) skipFirewall();
if (!process.env.SKIP_VALIDATE) validate();
```

**Variable name patterns:**
`DISABLE_*`, `SKIP_*`, `BYPASS_*`, `NO_*`, `ENABLE_*`, `REQUIRE_*`
(all of these can be misinterpreted).

## Safe patterns

```ts
// Explicit string comparison
if (process.env.DISABLE_AUTH === "true") skipAuth();

// Coerce through a strict parser
const skipAuth = ["1", "true", "yes"].includes(
  (process.env.DISABLE_AUTH ?? "").toLowerCase()
);

// Use a library: zod, env-var, dotenv-flow
const env = z.object({
  DISABLE_AUTH: z.coerce.boolean(),
}).parse(process.env);
```

## True positive criteria

Flag when BOTH of the following hold:

1. `if (process.env.X)` or `if (!process.env.X)` style truthy check.
2. `X` is named with a security-control prefix: `DISABLE_*`,
   `SKIP_*`, `BYPASS_*`, `NO_*`, `ENABLE_*`, `REQUIRE_*`, or
   contains `AUTH`, `VERIFY`, `CHECK`, `VALIDATE`.

## What to ignore

- Comparisons that explicitly check the string value:
  `=== "true"`, `=== "1"`, `=== "false"`.
- Env values parsed by a typed schema (zod `.coerce.boolean()`,
  env-var library).
- Non-security flags (`if (process.env.DEBUG)`).
- Test files.

## Examples

True positives:
```ts
if (process.env.BYPASS_AUTH) return next();   // BYPASS_AUTH=false skips auth!
if (!process.env.SKIP_VALIDATE) validate();   // SKIP_VALIDATE=false truthy
if (process.env.DISABLE_VERIFY) signed = true;
```

False positives to skip:
```ts
if (process.env.DISABLE_AUTH === "true") skipAuth();
if (process.env.SKIP_VALIDATE === "1") return next();

// Parsed via schema
const env = z.object({ DISABLE_AUTH: z.coerce.boolean() }).parse(process.env);
if (env.DISABLE_AUTH) skipAuth();
```
