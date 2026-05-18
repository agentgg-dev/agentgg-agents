---
slug: cache-key-scope
name: Cache Key Missing User / Tenant Scope
description: Per-user or per-tenant cache keys (feature flags, configs, tokens) without a userId / tenantId in the key — one user's value gets served to another. Walker mode follows key-builder helpers.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "(redis|cache|kv)\\.(get|set|setex|hget|hset|mget)\\s*\\(\\s*[`\"'](feature|config|token|flag|user|profile)"
    label: "Cache call with per-user-shaped key prefix"
  - regex: "new\\s+Map\\s*\\(\\s*\\)[\\s\\S]{0,200}\\.set\\s*\\(|\\.get\\s*\\("
    label: "In-memory Map used as cache (verify per-user scope)"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-639
  - CWE-200
  - OWASP-A01:2021
---

You are reviewing source code for cache keys that should be scoped to
a user, team, or tenant but aren't — leading to cross-user data
leakage when one user's cached value is served to another.

**Walker mode advantage:** key construction often happens in a
helper like `getFlagKey(name)` or `cacheKeyFor(...)`. Open it and
verify the userId/tenantId is actually part of the constructed key.
Also trace the cached value's loader function to confirm the value
varies by user — if it does but the key doesn't, that's a finding.

## What to look for

**Per-user feature flag / config cached without user scope:**
```ts
const cached = await redis.get(`feature:${name}`);
await redis.set(`config:${name}`, value);
```
If the feature flag's value depends on the requesting user, the key
must include the user ID.

**Per-tenant token / lookup without tenant scope:**
```ts
await redis.setex(`token:${name}`, 60, value);
await redis.hget(`map:${k}`, field);
```

**Global singleton cache for per-request data:**
```ts
await redis.get("global-counter");
await cache.get("singleton");
```

**Memoization with global cache (`new Map()`) for per-user values:**
```ts
const cache = new Map();
async function getUserFeatures(userId) {
  if (cache.has(name)) return cache.get(name);   // ignores userId!
  const data = await loadFeatures(userId);
  cache.set(name, data);
  return data;
}
```

## True positive criteria

Flag when BOTH of the following hold:

1. A cache key is built that does not include a user, tenant, team,
   or org identifier.
2. The cached value depends on the requesting user (feature flags,
   user preferences, tokens, per-tenant configs).

## What to ignore

- Genuinely global cached data: schema definitions, public product
  list, static catalogs.
- Cache keys that include `userId`, `teamId`, `orgId`, `tenantId`,
  or session-derived IDs.
- Test files.

## Examples

True positives:
```ts
// Feature flag value depends on user, but key doesn't include user
async function getFeatureFlag(name: string, userId: string) {
  const cached = await redis.get(`feature:${name}`);   // wrong — no userId
  if (cached) return cached;
  const value = await flagService.eval(name, userId);
  await redis.set(`feature:${name}`, value);
  return value;
}

// Per-user token cached globally
await redis.setex(`token:${type}`, 60, token);
```

False positives to skip:
```ts
// User-scoped key
const cached = await redis.get(`feature:${name}:${userId}`);

// Global by design — public product catalog
const products = await redis.get("public:products");

// Tenant-scoped
const cfg = await redis.get(`config:${tenantId}:${name}`);
```
