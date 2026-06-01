---
slug: cors-wildcard
name: CORS Wildcard / Reflected Origin
description: 'Access-Control-Allow-Origin set to * or to a reflected request Origin header, especially combined with Access-Control-Allow-Credentials — allows arbitrary sites to issue authenticated requests.'
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
      - go
      - py
      - rb
      - conf
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - go
    - py
    - rb
    - conf
references:
  - CWE-942
  - CWE-346
  - 'OWASP-A05:2021'
---

You are reviewing source code for CORS (Cross-Origin Resource Sharing)
misconfigurations that let arbitrary origins read responses or issue
authenticated cross-site requests.

## What to look for

**Wildcard origin with credentials:**
```ts
res.setHeader("Access-Control-Allow-Origin", "*");
res.setHeader("Access-Control-Allow-Credentials", "true");
```
Browsers reject this combination, but some servers send it anyway and
some libraries downgrade gracefully — flag it.

**Reflected origin without validation:**
```ts
res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
res.setHeader("Access-Control-Allow-Credentials", "true");
```
Any origin can issue authenticated requests and read responses. Safe
only if `req.headers.origin` is validated against a strict allowlist
of origins first.

**`cors` middleware with `origin: true`:**
```ts
app.use(cors({ origin: true, credentials: true }));
```
`origin: true` reflects the request origin. Combined with credentials,
this is equivalent to a wildcard.

**Nginx reflection:**
```nginx
add_header Access-Control-Allow-Origin $http_origin;
```

## True positive criteria

Flag when ANY of the following hold:

1. `Access-Control-Allow-Origin: *` appears in a response that also
   serves authenticated data (cookies, bearer tokens accepted).
2. `Access-Control-Allow-Origin` is set to a value that is, directly
   or transitively, the request `Origin` header without an allowlist
   check.
3. `cors({ origin: true, credentials: true })` or equivalent
   middleware config.

## What to ignore

- Public read-only APIs with `Access-Control-Allow-Origin: *` and
  no credentials (no auth, no cookies).
- CORS configurations with a fixed allowlist:
  `cors({ origin: ["https://app.example.com"], credentials: true })`.
- Pre-flight `OPTIONS` handlers that explicitly check origin against
  an allowlist before responding.
- Test files.

## Examples

True positives:
```ts
// Reflected origin + credentials
res.setHeader("Access-Control-Allow-Origin", req.headers.origin ?? "");
res.setHeader("Access-Control-Allow-Credentials", "true");

// cors middleware origin: true + credentials
app.use(cors({ origin: true, credentials: true }));

// Wildcard + credentials
res.setHeader("Access-Control-Allow-Origin", "*");
res.setHeader("Access-Control-Allow-Credentials", "true");
```

False positives to skip:
```ts
// Allowlist
const ALLOWED = ["https://app.example.com", "https://admin.example.com"];
const origin = req.headers.origin;
if (ALLOWED.includes(origin)) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
}

// Public API, no creds
res.setHeader("Access-Control-Allow-Origin", "*");
// no credentials, no cookies
```
