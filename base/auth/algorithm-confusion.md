---
slug: algorithm-confusion
name: JWT Algorithm Confusion
description: JWT verification without an algorithms allowlist — caller can change the alg header to "none" or to HS256 keyed by the public key, forging tokens. Walker mode follows verifier wrappers to confirm pinning.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs,lua}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "jwt\\.verify\\s*\\("
    label: "jsonwebtoken jwt.verify call"
  - regex: "\\bjwtVerify\\s*\\("
    label: "jose jwtVerify call"
  - regex: "verifyJwt\\s*\\(|verifyJWT\\s*\\("
    label: "custom verifyJwt helper"
  - regex: "jwt_obj\\s*:\\s*verify\\s*\\("
    label: "Lua resty.jwt verify"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-347
  - CVE-2015-9235
---

You are reviewing JWT verification code for algorithm confusion — a
specific vulnerability where the verifier accepts whichever algorithm
the incoming JWT header declares, allowing the attacker to substitute
a weaker algorithm (or `none`) to forge tokens.

**Walker mode advantage:** JWT verification is almost always wrapped
in `auth/jwt.ts` or `lib/verify-token.ts`. If the candidate call
delegates to such a helper, open it and check whether the wrapper
pins `algorithms: [...]`. A finding requires the verify call to lack
algorithm pinning all the way down the chain.

## The vulnerability

JWT verification libraries default to using the algorithm specified
in the token's header. If the code does not pin the algorithm
allowlist, an attacker can:

1. **`alg: none` attack** — strip the signature entirely. Some
   libraries accept this if `none` is in the default allowlist.
2. **RS256 → HS256 confusion** — change the algorithm from asymmetric
   to symmetric. The verifier uses the public key (which is meant for
   asymmetric verification) as an HMAC secret. Since the public key
   is published, the attacker can sign their own tokens.

## What to look for

**`jwt.verify` without `algorithms` option:**
```ts
const decoded = jwt.verify(token, secret);
const decoded = jwt.verify(token, publicKey);   // RS256→HS256 confusion possible
```

**`jose.jwtVerify` without algorithm restriction:**
```ts
const { payload } = await jwtVerify(token, key);
```
jose's defaults are safer than jsonwebtoken's, but explicit pinning
is the recommendation.

**Lua `resty.jwt`:**
```lua
local ok = jwt_obj:verify(secret, token)
-- accepts any algorithm if alg_whitelist is not set
```

## Safe patterns

```ts
jwt.verify(token, secret, { algorithms: ["RS256"] });
await jwtVerify(token, jwks, { algorithms: ["RS256"] });
```
Always pin a single expected algorithm (or a small allowlist of
algorithms you actually use). Never include `none`.

## True positive criteria

Flag when `jwt.verify`, `jwtVerify`, `verifyJwt`, or
`jwt_obj:verify` is called WITHOUT an `algorithms` option (or
`alg_whitelist` for Lua).

## What to ignore

- Calls that include `algorithms: ["RS256"]` (or similar concrete
  list).
- Wrapper functions whose callers supply the algorithm option.
- Test files demonstrating the vulnerability for educational
  purposes.

## Examples

True positives:
```ts
// No algorithms option — accepts whatever the token declares
const claims = jwt.verify(token, secret);

// jose without algorithm pin
const { payload } = await jwtVerify(token, key);

// Lua without alg_whitelist
local ok, err = jwt_obj:verify(secret, token)
```

False positives to skip:
```ts
// Algorithm pinned
const claims = jwt.verify(token, secret, { algorithms: ["RS256"] });

// jose with explicit algorithm
const { payload } = await jwtVerify(token, jwks, { algorithms: ["RS256"] });

// Wrapper that requires the caller to specify
function verify(token, opts: { algorithms: string[] }) {
  return jwt.verify(token, getKey(), opts);
}
```
