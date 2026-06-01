---
slug: cache-key-poisoning
name: Cache Key Poisoning
description: 'CDN / proxy / application cache keyed using Host, custom headers, or unkeyed parameters — attacker can craft a request that poisons the cache for other users. Follows cache wrappers to verify key construction.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(req|request|ctx)\.headers(\.|\[)host'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,lua,conf}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Cache key reference to request Host header
      - regex: '(req|request|ctx)\.headers(\.|\[)[''"]?x-[a-z-]+'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,lua,conf}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Cache key reference to custom request header
      - regex: ngx\.var\.host|ngx\.var\.request_uri
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,lua,conf}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: OpenResty cache key from Host/URI
      - regex: '(redis|kv|cache)\.(set|setex|hset|mset)\s*\(\s*[`"''][^`"'']*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,lua,conf}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Cache write with template-literal key
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - lua
    - conf
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '(req|request|ctx)\.headers(\.|\[)host'
      label: Cache key reference to request Host header
    - regex: '(req|request|ctx)\.headers(\.|\[)[''"]?x-[a-z-]+'
      label: Cache key reference to custom request header
    - regex: ngx\.var\.host|ngx\.var\.request_uri
      label: OpenResty cache key from Host/URI
    - regex: '(redis|kv|cache)\.(set|setex|hset|mset)\s*\(\s*[`"''][^`"'']*\$\{'
      label: Cache write with template-literal key
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-444
  - 'OWASP-A03:2021'
---

You are reviewing source code for cache-key construction that allows
poisoning — the cache key includes an attacker-controlled value
(custom header, Host, query parameter that should be unkeyed) so
crafting a request stores a malicious response under a key that
serves other users.

**Cross-file analysis:** key construction is often funneled through
a helper (`makeCacheKey`, `cacheKeyFor`, `buildKey`). Open the helper
and verify whether the components are server-derived or client-
controlled. Also check whether the corresponding response handler
varies by the same components — if a query param is in the key but
not used in the response, the key is gratuitously poisonable.

## What to look for

**Cache key built from request Host or custom header:**
```ts
const cache_key = host + ":" + path;
const cacheKey = req.headers["x-tenant"];
const cache_key = req.header("x-trace");
```
`Host` is client-controlled when the upstream allows arbitrary host
values (multi-tenant proxies). Custom headers are always
client-controlled unless the edge strips them.

**Cache key including unkeyed query/body:**
```ts
const cacheKey = url + req.query.foo;
const cache_key = JSON.stringify(query);
```
If the request handler uses these values to render the response,
they should be in the key; if not, the attacker can attach noise
that creates new keys for the same logical response.

**OpenResty / Lua shared-dict caches:**
```lua
ngx.shared.cache:set(ngx.var.host .. path, val)
ngx.shared.dict:set("k:" .. ngx.var.request_uri, val)
```
`ngx.var.host` is the request Host header — client-controlled.

**Redis / KV cache keyed on user input:**
```ts
redis.set("cache:" + req.body.id, value);
redis.hset("cache:host", host, value);
kv.set("cache:" + host, blob);
```

**Missing `Vary` header on responses that depend on a header:**
```ts
res.setHeader("Cache-Control", "public, max-age=3600");
// Response varies by Accept-Language but Vary header not set —
// the cache serves the first language to everyone.
```

## True positive criteria

Flag when ANY of the following hold:

1. A cache key is built from `req.headers.host`, `ngx.var.host`,
   `request.host`, or a custom header.
2. A cache key includes a `req.query.*`, `req.body.*`, or
   `searchParams.*` value that the response handler does not
   consume.
3. A response that varies based on a header (`Authorization`,
   `Cookie`, `Accept-Language`) is cached without a corresponding
   `Vary` header.

## What to ignore

- Cache keyed on internal identifiers: `userId`, session-derived
  values, validated route parameters.
- Test / fixture files.
- Cache writes that always use a constant key.

## Examples

True positives:
```ts
// Host in cache key — multi-tenant poisoning
const key = `${req.headers.host}:${req.url}`;
await redis.set(key, value);

// Custom header in key
await redis.set(`cache:${req.headers["x-tenant"]}`, value);
```

```lua
ngx.shared.cache:set(ngx.var.host .. "/" .. ngx.var.request_uri, response)
```

False positives to skip:
```ts
// User-scoped cache key — safe
const key = `user:${session.userId}:profile`;

// Validated route param
const slug = z.string().regex(/^[a-z0-9-]+$/).parse(req.params.slug);
await redis.set(`product:${slug}`, value);
```
