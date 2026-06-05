---
slug: test-header-bypass
name: Test / Debug Header Bypasses Security
description: 'Production-reachable code branches on x-automated-test, x-debug, x-bypass, x-internal, x-skip-auth, x-no-rate-limit, x-admin headers to disable security checks.'
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
    - py
    - rb
    - go
    - php
    - java
    - kt
    - cs
  preFilter:
    - regex: '[Hh]eader|x-[A-Za-z]|req(uest)?\.headers|getHeader|HTTP_|\.META\b'
      label: Request header access
references:
  - CWE-287
  - CWE-489
  - 'OWASP-A05:2021'
---

You are reviewing source code for HTTP request headers that bypass
security checks — auth, rate limiting, verification — when present.
If the production reverse proxy doesn't strip these headers, anyone
can set them and disable the check.

## What to look for

**Header read directly inside a security path:**
```ts
if (req.headers["x-automated-test"]) skip();
if (req.headers["x-test-bypass"]) return next();
if (headers.get("x-debug")) bypass();
if (req.headers["x-internal"]) skipAuth();
if (req.headers["x-bypass"]) disable();
if (req.headers["x-skip-auth"]) return next();
if (req.headers["x-no-rate-limit"]) skip();
if (req.headers["x-admin"]) bypass();
```

**Mode toggle via header value:**
```ts
if (headers["x-mode"] === "test") return mockResponse();
if (headers.get("x-environment") === "dev") return skipAuth();
```

**Header names to flag:**
`x-test`, `x-test-*`, `x-debug*`, `x-bypass*`, `x-skip-*`,
`x-no-*`, `x-internal`, `x-admin`, `x-impersonate`, `x-mock`,
`x-automated-test`, `x-environment`, `x-mode`.

## Why this matters

Even if the production setup strips these headers at the edge, this
is one configuration mistake away from public bypass. The robust fix
is to never branch on these headers in production code — keep test
hooks in test-only files that don't ship.

## True positive criteria

Flag when ALL of the following hold:

1. Code reads a request header matching the `x-test*` / `x-debug*` /
   `x-bypass*` / `x-skip-*` / `x-internal` / `x-admin` patterns.
2. The header value gates a security-relevant action: skipping auth,
   skipping rate limit, returning admin data, bypassing CSRF.

## What to ignore

- Standard headers (`x-forwarded-for`, `x-request-id`,
  `x-correlation-id`, `x-amz-*`, `x-vercel-*`) that don't bypass
  security.
- Test files / mock servers that read these headers as part of test
  setup.
- Documentation strings / type definitions.

## Examples

True positives:
```ts
// Skip auth on test header
if (req.headers["x-automated-test"]) {
  return next();
}

// Mode toggle
if (req.headers["x-mode"] === "test") {
  return Response.json({ user: { id: 1, admin: true } });
}

// No rate limit for "internal"
if (req.headers["x-internal"]) {
  return handler(req);   // skips throttle
}
```

False positives to skip:
```ts
// Logging only
if (req.headers["x-debug"]) {
  console.log("debug request", req.url);
}
return handler(req);   // doesn't bypass anything

// Test file
// auth.test.ts
const res = await fetch(url, { headers: { "x-test-mode": "1" } });
```
