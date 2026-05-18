---
slug: rate-limit-bypass
name: Sensitive Endpoint Missing or Bypassable Rate Limit
description: High-risk endpoints (login, password reset, charge, account delete, token generation, invite) without rate limiting, OR rate limits keyed on spoofable headers like X-Forwarded-For. Walker mode follows middleware and limiter helpers.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/app/api/**/route.{ts,tsx,js,jsx,mjs}"
  - "**/pages/api/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/routes/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/services/**/endpoints/**/*.ts"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "(login|signin|sign-in|signup|sign-up|password-reset|forgot|reset-password|charge|payment|refund|account.*(delete|remove)|token|invite|magic-link|otp|verify)"
    label: "Sensitive endpoint name pattern"
  - regex: "x-forwarded-for|X-Forwarded-For|x-real-ip|cf-connecting-ip"
    label: "Reference to spoofable client-IP header"
  - regex: "(rateLimit|rateLimiter|ratelimit|throttle|consume)\\s*[\\.(]"
    label: "Rate-limit call"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-307
  - CWE-799
  - OWASP-A07:2021
---

You are reviewing HTTP endpoints for missing or bypassable rate
limiting on sensitive operations.

**Walker mode advantage:** rate limiting is usually applied via a
shared middleware/wrapper (`withRateLimit`, `rateLimit({ ... })`).
Open the helper to verify what it keys on — `X-Forwarded-For`
without an edge-strip layer is bypassable. Also check whether the
candidate endpoint is composed with the middleware (Express
`app.use`, Next.js middleware matcher) or whether it's bare.

## High-risk endpoints (always need rate limiting)

- **Authentication:** login, sign-in, sign-up, password reset,
  forgot-password, email verification
- **Account state:** account deletion, email change, password change
- **Money:** charge, payment, refund, transfer
- **Token creation:** API key generation, OAuth code exchange,
  invite generation
- **Bulk operations:** data export, search with high computational
  cost
- **Notification triggers:** invite email, magic link, OTP send

## What to look for

**Endpoint is sensitive but no rate-limit call appears in the file
or in a wrapping middleware:**
```ts
// app/api/auth/login/route.ts — no rate limit
export const POST = async (req: Request) => {
  const { email, password } = await req.json();
  return signIn(email, password);
};
```

**Rate limit keyed on spoofable header:**
```ts
const ip = req.headers["x-forwarded-for"];
await rateLimiter.consume(ip);
```
`X-Forwarded-For` is client-controllable unless your edge strips/sets
it. If the limit is per-IP and the client picks the IP, the limit is
trivially bypassed by rotating the header value.

**Common rate-limit identifiers to look for (presence = good):**
- `rateLimit`, `rateLimiter`, `RateLimiter`, `rate_limit`
- `upstash/ratelimit`, `@upstash/ratelimit`, `express-rate-limit`,
  `next-rate-limit`, `fastify-rate-limit`, `ddosify`
- `limit`, `throttle`, `consume`

## True positive criteria

Flag when ANY of the following hold:

1. An endpoint matches one of the high-risk patterns above and the
   file (and any imported HOF/middleware) contains no rate-limit
   call.
2. A rate-limit call uses `X-Forwarded-For`, `X-Real-IP`, or
   `CF-Connecting-IP` directly without confirming the edge layer
   strips client-supplied values.
3. A rate-limit call is keyed on a user-supplied field
   (`req.body.email`) that the attacker can rotate to defeat the
   limit.

## What to ignore

- Endpoints clearly protected by an upstream WAF / edge layer with
  documented rate limits (Vercel WAF, Cloudflare, AWS API Gateway).
- Files for read-only endpoints that don't fit the high-risk
  patterns.
- Rate limits keyed on session/user ID for authenticated endpoints.
- Test files.

## Examples

True positives:
```ts
// Login with no rate limit
export const POST = async (req) => {
  const { email, password } = await req.json();
  return signIn(email, password);
};

// Rate limit keyed on spoofable IP
const ip = req.headers["x-forwarded-for"];
const { success } = await ratelimit.limit(ip);
```

False positives to skip:
```ts
// Rate limit per email + IP, with edge stripping XFF
const identifier = `${email}:${verifiedClientIp}`;
const { success } = await ratelimit.limit(identifier);
if (!success) return new Response("too many requests", { status: 429 });

// Endpoint behind documented edge rate limiting
// /api/products — read-only, low risk
export const GET = async () => Response.json(products);
```
