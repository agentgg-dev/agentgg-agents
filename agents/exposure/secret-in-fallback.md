---
slug: secret-in-fallback
name: Secret Env Var with Hardcoded Fallback
description: 'Env var secret with a hardcoded ?? or || fallback value — production silently uses the fallback if the env is unset, enabling auth bypass or known-secret forgery.'
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
      - lua
      - go
      - py
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
    - py
  preFilter:
    - semgrepRule: exposure/process-env-access
      label: process.env access with a hardcoded string fallback
references:
  - CWE-798
  - CWE-1188
  - 'OWASP-A05:2021'
---

You are reviewing source code for environment variable secrets with
hardcoded fallback values. The pattern is:
```ts
const secret = process.env.JWT_SECRET ?? "dev-secret";
const token = process.env.API_TOKEN || "fallback";
```
If the env var is unset (forgotten in a deployment, lost in a
copy-paste, environment misconfiguration), the application silently
runs with the fallback. The fallback is in source — therefore known
to anyone who can read the code, including an attacker.

## What to look for

**`??` and `||` fallback patterns:**
```ts
const s = process.env.JWT_SECRET ?? "dev-secret";
const t = process.env.API_TOKEN || "fallback";
const k = process.env.STRIPE_KEY ?? "sk_test";
const p = process.env.DB_PASSWORD ?? "changeme";
```

**Lua equivalents:**
```lua
local s = os.getenv("API_SECRET") or "dev"
local t = os.getenv("HMAC_TOKEN") or "fallback"
```

**Python equivalents:**
```python
secret = os.environ.get("JWT_SECRET", "default")
secret = os.getenv("JWT_SECRET") or "fallback"
```

**Go equivalents:**
```go
s := os.Getenv("API_SECRET")
if s == "" { s = "default" }
```

**Variable / env name patterns:**
The env var name contains `SECRET`, `TOKEN`, `KEY`, `PASSWORD`,
`CREDENTIAL`, `AUTH`, `PRIVATE`.

## Why this is a bug

Even if production is "always set", three failure modes:

1. **Misconfiguration:** the env var is missing in a new region,
   new container, or after a deploy. The app starts successfully
   with the fallback — silent failure.
2. **Known secret:** the fallback string is in your public git
   history forever. Any attacker who reads source has it.
3. **HMAC / JWT forgery:** if any production instance ever ran with
   the fallback, an attacker who knows it can sign forged tokens
   that any other instance (running with the real secret) might
   accept across instances that share state.

## Safe pattern

Fail fast at startup:
```ts
const secret = process.env.JWT_SECRET;
if (!secret) throw new Error("JWT_SECRET is required");
```

## True positive criteria

Flag when ALL of the following hold:

1. Code accesses an env var whose name contains a secret-shaped
   substring (`SECRET`, `TOKEN`, `KEY`, `PASSWORD`, `CREDENTIAL`,
   `AUTH`, `PRIVATE`).
2. The access uses `??`, `||`, `or`, or a conditional with a
   non-empty string literal as the fallback.

## What to ignore

- Fallback to `undefined`, `null`, `""`, or an empty value (`?? ""`)
  followed by an explicit validation check.
- Test files, build scripts, local dev tooling clearly gated.
- Fallback values that are themselves placeholders explicitly
  designed to fail downstream (`"MISSING_SECRET"` that gets caught
  by a validator).

## Examples

True positives:
```ts
const jwtSecret = process.env.JWT_SECRET ?? "dev-secret";
const stripe = process.env.STRIPE_SECRET_KEY || "sk_test_fallback";
const dbPass = process.env.DATABASE_PASSWORD ?? "changeme";
```

```lua
local secret = os.getenv("HMAC_SECRET") or "dev"
```

```python
secret = os.environ.get("JWT_SECRET", "default-secret")
```

False positives to skip:
```ts
// Empty fallback + validation
const secret = process.env.JWT_SECRET ?? "";
if (!secret) throw new Error("JWT_SECRET required");

// Fail-fast at startup
const secret = process.env.JWT_SECRET;
if (!secret) throw new Error("JWT_SECRET required");
```
