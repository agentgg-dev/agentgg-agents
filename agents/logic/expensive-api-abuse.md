---
slug: expensive-api-abuse
name: Expensive API Call Without Abuse Protection
description: 'Endpoints that invoke paid APIs (LLM, streaming or SSE completions, payment, email send, SMS) without rate limiting, captcha, per-request output caps, or other abuse gating — single user can drain budget. Follows rate-limit middleware across files.'
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
      - regex: \b(streamText|streamObject|generateText|generateObject)\s*\(
        in:
          - '**/route.{ts,tsx,js,jsx,mjs}'
          - '**/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Vercel AI SDK streaming/generate call
      - regex: '\.chat\.completions\.create\s*\([^)]*stream\s*:\s*true'
        in:
          - '**/route.{ts,tsx,js,jsx,mjs}'
          - '**/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'OpenAI chat.completions with stream: true'
      - regex: text/event-stream
        in:
          - '**/route.{ts,tsx,js,jsx,mjs}'
          - '**/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: SSE Content-Type response
      - regex: stream\s*=\s*True
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: LLM call with stream=True
      - regex: StreamingResponse\s*\(|text/event-stream
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: SSE / streaming response
      - regex: client\.(messages|chat\.completions)\.(create|stream)\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: LLM streaming call
      - regex: "yield\\s+f?[\\\"']data:"
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: manual SSE data frame
where:
  extensions:
    - py
  filePatterns:
    - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
    - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
    - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/actions/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/server/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/route.{ts,tsx,js,jsx,mjs}'
    - '**/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/app/**/*.{ts,tsx,js,jsx,mjs}'
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/.venv/**'
    - '**/venv/**'
    - '**/site-packages/**'
  preFilter:
    - semgrepRule: shared/http-endpoints
      label: HTTP route handler or endpoint function
    - regex: \b(streamText|streamObject|generateText|generateObject)\s*\(
      label: Vercel AI SDK streaming/generate call
    - regex: '\.chat\.completions\.create\s*\([^)]*stream\s*:\s*true'
      label: 'OpenAI chat.completions with stream: true'
    - regex: text/event-stream
      label: SSE Content-Type response
    - regex: stream\s*=\s*True
      label: stream=True
    - regex: StreamingResponse\s*\(|text/event-stream
      label: SSE / streaming response
    - regex: client\.(messages|chat\.completions)\.(create|stream)\s*\(
      label: LLM streaming call
    - regex: "yield\\s+f?[\\\"']data:"
      label: manual SSE data frame
  maxFilesPerBatch: 5
references:
  - CWE-770
  - CWE-307
  - 'OWASP-A04:2021'
---

You are reviewing endpoints that invoke paid / metered APIs for
missing abuse protection.

**Cross-file analysis:** abuse protection is typically applied via
shared middleware/wrappers (`withRateLimit`, `requireAuth`,
`assertCaptcha`). If the candidate route doesn't show them inline,
look for HOF wrapping or middleware composition — open the wrapper
to verify it actually enforces a limit before the paid API runs. The risk: a single user (or unauthenticated
caller) can issue thousands of requests, draining your API budget.

Streaming handlers need the same checks run stricter. The gate has to
complete before the first byte leaves, because a 401 raised after the
stream opens does not stop the tokens already billed. Python route
files are in scope too: FastAPI and Flask handlers returning
`StreamingResponse` or yielding SSE frames have the same exposure.

## What to look for

**LLM API calls in a public-facing endpoint:**
```ts
const result = await openai.chat.completions.create({...});
const out = await anthropic.messages.create({...});
const r = await generateText({ model, prompt });
```

**Streaming and structured-output LLM calls:**
```ts
const result = streamText({ model, messages });
const stream = streamObject({ model, schema, prompt });
const out = await generateObject({ model, schema, prompt });
const res = await openai.chat.completions.create({ model, stream: true });
```
```py
stream = client.messages.create(model=..., messages=..., stream=True)
return StreamingResponse(gen(), media_type="text/event-stream")
```
`streamObject` and `generateObject` bill the same as their text
counterparts; a schema argument is not a cost bound.

**Raw SSE responses:**
```ts
return new Response(new ReadableStream({ start(c) { ... } }), {
  headers: { "Content-Type": "text/event-stream" },
});
```
```py
yield f"data: {chunk}\n\n"
```
A `text/event-stream` content type, a `StreamingResponse`, or a
hand-written `data:` frame marks a long-lived response. Each open
stream holds a connection and keeps billing for as long as the caller
keeps it open, so an unauthenticated one is both a cost and a
capacity problem.

**Common endpoint paths:**
`/api/chat`, `/api/completion`, `/api/generate`, `/api/agent`,
`/api/assistant`.

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

**Per-request output cap on LLM calls:**
An LLM call with no `maxTokens` / `maxOutputTokens` (`max_tokens` in
Python) is unbounded, so one request can cost far more than the
average. Rate limiting caps the number of calls; an output cap is
what bounds the price of each one. Treat a missing cap as its own
gap even when auth and rate limiting are both present.

Also check that tool schemas handed to the model do not expose
filesystem, shell, or database-write capability the calling user does
not already have, and that server-side context (other users' rows,
secrets) is not pasted into the prompt or system message.

## True positive criteria

Flag when ALL of the following hold:

1. The handler calls an expensive API (LLM, email/SMS send,
   payment, image generation, geocoding), including a streaming or
   structured-output variant.
2. The endpoint is reachable from unauthenticated callers OR
   without rate limiting.

Flag separately when a streaming LLM call runs with no per-request
output cap, or when the auth or rate-limit check runs after the
stream has started.

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

// /api/chat — streams with no auth, no rate limit, no token cap
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({ model: openai("gpt-4o"), messages });
  return result.toDataStreamResponse();
}
```
```py
# FastAPI SSE endpoint with no gate before the stream opens
@app.post("/api/chat")
async def chat(req: ChatRequest):
    stream = client.messages.create(
        model="claude-3-5-sonnet", messages=req.messages, stream=True
    )
    return StreamingResponse(to_sse(stream), media_type="text/event-stream")
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

// Streaming with auth, rate limit, and an output cap, all before the stream
export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response("401", { status: 401 });
  const { success } = await ratelimit.limit(session.user.id);
  if (!success) return new Response("429", { status: 429 });
  const result = streamText({
    model: openai("gpt-4o"),
    messages: (await req.json()).messages,
    maxTokens: 1000,
  });
  return result.toDataStreamResponse();
}
```
