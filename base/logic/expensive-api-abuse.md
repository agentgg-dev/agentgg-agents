---
slug: expensive-api-abuse
name: Expensive API Call Without Abuse Protection
description: 'Endpoints that invoke paid APIs (LLM, payment, email send, SMS) without rate limiting, captcha, or other abuse gating — single user can drain budget. Walker mode follows rate-limit middleware across files.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: openai\.chat\.completions|anthropic\.messages|\bgenerateText\s*\(|\bstreamText\s*\(
        in:
          - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/actions/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/server/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: LLM API call
      - regex: resend\.emails\.send|sgMail\.send|twilio\.messages\.create|ses\.sendEmail
        in:
          - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/actions/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/server/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Email/SMS send
      - regex: stripe\.(paymentIntents|charges|customers|subscriptions)\.create
        in:
          - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/actions/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/server/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Stripe billable create
      - regex: (mapbox|googleMaps|geocoder)\.|images?\.generate\s*\(
        in:
          - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/actions/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/server/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Geocoding / image generation API
where:
  filePatterns:
    - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
    - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
    - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/actions/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/server/**/*.{ts,tsx,js,jsx,mjs}'
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: openai\.chat\.completions|anthropic\.messages|\bgenerateText\s*\(|\bstreamText\s*\(
      label: LLM API call
    - regex: resend\.emails\.send|sgMail\.send|twilio\.messages\.create|ses\.sendEmail
      label: Email/SMS send
    - regex: stripe\.(paymentIntents|charges|customers|subscriptions)\.create
      label: Stripe billable create
    - regex: (mapbox|googleMaps|geocoder)\.|images?\.generate\s*\(
      label: Geocoding / image generation API
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-770
  - CWE-307
---

You are reviewing endpoints that invoke paid / metered APIs for
missing abuse protection.

**Walker mode advantage:** abuse protection is typically applied via
shared middleware/wrappers (`withRateLimit`, `requireAuth`,
`assertCaptcha`). If the candidate route doesn't show them inline,
look for HOF wrapping or middleware composition — open the wrapper
to verify it actually enforces a limit before the paid API runs. The risk: a single user (or unauthenticated
caller) can issue thousands of requests, draining your API budget.

## What to look for

**LLM API calls in a public-facing endpoint:**
```ts
const result = await openai.chat.completions.create({...});
const out = await anthropic.messages.create({...});
const r = await generateText({ model, prompt });
```

**Email / SMS / push send:**
```ts
await resend.emails.send({...});
await sgMail.send({...});
await twilio.messages.create({...});
await ses.sendEmail({...});
```

**Payment authorization (not capture — authz alone has costs too):**
```ts
await stripe.paymentIntents.create({...});
await stripe.charges.create({...});
```

**Other paid SaaS:**
- Geocoding (Google Maps, Mapbox)
- Speech-to-text / text-to-speech
- Image generation (DALL-E, Stable Diffusion APIs)
- PDF generation services
- Background check / KYC providers

## What to verify in the file

Abuse-protection signals to look for:
- `rateLimit(...)` / `ratelimit.limit(...)` call before the API call
- Captcha verification: `hcaptcha.verify`, `recaptcha.verify`,
  `turnstile.siteverify`
- Bot detection / Cloudflare Turnstile
- Per-user cap (`if (user.requestsThisMonth > N) return 429`)
- Auth check that limits to a known small set of users

## True positive criteria

Flag when ALL of the following hold:

1. The handler calls an expensive API (LLM, email/SMS send,
   payment, image generation, geocoding).
2. The endpoint is reachable from unauthenticated callers OR
   without rate limiting.

## What to ignore

- Internal admin endpoints clearly behind admin auth.
- Server-to-server endpoints behind a service mesh / VPC / mutual
  TLS / API key with rate limiting at the gateway.
- Test files.

## Examples

True positives:
```ts
// /api/chat — public, no rate limit, calls OpenAI
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = await openai.chat.completions.create({
    model: "gpt-4",
    messages,
  });
  return Response.json(result);
}

// Unauthenticated email send
export async function POST(req: Request) {
  await resend.emails.send({
    to: (await req.json()).to,
    subject: "Notification",
    text: "...",
  });
  return new Response("sent");
}
```

False positives to skip:
```ts
// Rate-limited + authenticated
export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response("401", { status: 401 });
  const { success } = await ratelimit.limit(session.user.id);
  if (!success) return new Response("429", { status: 429 });
  const result = await openai.chat.completions.create({...});
  return Response.json(result);
}

// Captcha protected
const verified = await turnstile.siteverify(token);
if (!verified) return new Response("captcha required", { status: 403 });
await resend.emails.send({...});
```
