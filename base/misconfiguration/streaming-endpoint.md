---
slug: streaming-endpoint
name: AI Streaming Endpoint Without Auth / Rate Limit
description: 'streamText / streamObject / generateText / OpenAI stream:true / SSE endpoints that lack pre-stream auth and rate limiting — unlimited LLM token billing and prompt injection risk. Walker mode follows auth + rate-limit middleware across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
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
where:
  filePatterns:
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
  preFilter:
    - regex: \b(streamText|streamObject|generateText|generateObject)\s*\(
      label: Vercel AI SDK streaming/generate call
    - regex: '\.chat\.completions\.create\s*\([^)]*stream\s*:\s*true'
      label: 'OpenAI chat.completions with stream: true'
    - regex: text/event-stream
      label: SSE Content-Type response
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-307
  - CWE-770
  - 'OWASP-A04:2021'
---

You are reviewing AI streaming endpoints — handlers that call
`streamText`, `streamObject`, `generateText`, or
`openai.chat.completions.create({ stream: true })` and return a
streaming response.

**Walker mode advantage:** auth and rate-limit may be applied via
middleware (`withAuth`, `withRateLimit`) or imported helpers. Open
the wrapper and verify it runs BEFORE the streaming call (auth that
runs after bytes have started streaming is too late). Also check for
`maxTokens`/`maxOutputTokens` budget caps to bound the per-request
cost. Failure modes:

1. **No auth before stream starts:** caller can hit the endpoint
   anonymously and consume LLM tokens billed to your account.
2. **No rate limit:** even if auth is present, a single user can
   abuse the endpoint to drain budget.
3. **Prompt injection sinks:** the prompt is built from user input
   without scoping (covered separately by
   `agentic-untrusted-prompt-input`).
4. **State leakage:** server-side context (other users' data,
   secrets) is included in the prompt or system message.

## What to look for

**Vercel AI SDK:**
```ts
const result = streamText({ model, messages });
const stream = streamObject({ model, schema, prompt });
const out = await generateText({ model, prompt });
return new StreamingTextResponse(stream);
```

**OpenAI SDK with `stream: true`:**
```ts
const res = await openai.chat.completions.create({ model: "gpt-4", stream: true });
const r = await client.chat.completions.create({ model, messages, stream: true });
```

**Raw SSE / ReadableStream:**
```ts
return new Response(new ReadableStream({ start(c) { ... } }), {
  headers: { "Content-Type": "text/event-stream" },
});
```

**Common endpoint paths:**
`/api/chat`, `/api/completion`, `/api/generate`, `/api/agent`,
`/api/assistant`.

## What to verify in the handler

1. **Auth before stream starts:** `await auth()` / `requireAuth()`
   etc. must run and the result checked before the streaming call.
   If auth fails mid-stream, the bytes are already going to the
   client.
2. **Rate limit before stream starts:** typed by user, IP, or both;
   typically a `ratelimit.limit(identifier)` call.
3. **Budget cap per request:** `maxTokens`, `maxOutputTokens` is
   set; otherwise a single call can be unbounded.
4. **Tool calls scoped:** if the LLM has tool access, the tool
   schemas don't expose filesystem / shell / DB write capabilities
   the calling user shouldn't have.

## True positive criteria

Flag for review when:
1. A streaming-LLM call is made in the handler.
2. Any of the following is missing before the call:
   - Authentication check
   - Rate limit
   - Token/output cap

## What to ignore

- Internal streaming endpoints behind a service mesh / VPC.
- Tests.

## Examples

True positives:
```ts
// /api/chat — no auth, no rate limit
export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({ model: openai("gpt-4o"), messages });
  return result.toDataStreamResponse();
}

// OpenAI streaming with no caps
export async function POST(req: Request) {
  const body = await req.json();
  const stream = await openai.chat.completions.create({
    model: "gpt-4",
    messages: body.messages,
    stream: true,
  });
  return new Response(stream);   // no maxTokens, no auth
}
```

False positives to skip:
```ts
// Auth + rate limit + max tokens
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
