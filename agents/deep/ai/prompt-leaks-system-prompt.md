---
slug: prompt-leaks-system-prompt
name: System Prompt Embeds Secrets / Env Vars
description: 'LLM system prompts (system / instructions / role:system messages) that embed env-var secrets or hardcoded API tokens — values can be extracted via prompt injection or appear in trace logs. Follows prompt builders across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'system\s*:\s*`[^`]*\$\{[^}]*process\.env'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: system prompt interpolating process.env
      - regex: '(role|name)\s*:\s*["'']system["''][\s\S]{0,300}content\s*:\s*`[^`]*\$\{[^}]*process\.env'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'messages role:system with env-var interpolation'
      - regex: 'system\s*:\s*["''][^"'']*\b(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{20,})'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: system prompt with hardcoded secret literal
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'system\s*:\s*`[^`]*\$\{[^}]*process\.env'
      label: system prompt interpolating process.env
    - regex: '(role|name)\s*:\s*["'']system["''][\s\S]{0,300}content\s*:\s*`[^`]*\$\{[^}]*process\.env'
      label: 'messages role:system with env-var interpolation'
      multiline: true
    - regex: 'system\s*:\s*["''][^"'']*\b(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{20,})'
      label: system prompt with hardcoded secret literal
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-200
  - CWE-532
  - OWASP-LLM06
---

You are reviewing LLM call sites where the system prompt or
instructions embed secrets — API keys, tokens, passwords — that
could be extracted by an attacker via prompt injection or leak via
trace logs / model output / LLM-as-a-judge pipelines.

**Cross-file analysis:** the system prompt may be built by a
`buildSystemPrompt(ctx)` helper that interpolates secrets internally.
Follow the call to the prompt builder and check what it stitches in.
Also confirm whether referenced env vars hold actual secrets (e.g.,
`STRIPE_SECRET_KEY`) or innocuous config (e.g., `APP_NAME`).

## Why this is a problem

LLMs are not secret-keeping vaults. Anything in the prompt:
- Can be revealed by a prompt-injection attack asking the model to
  print its prompt.
- Appears in trace logs sent to observability tools (OpenTelemetry,
  LangSmith, LangFuse).
- Can be echoed in the model's completion in some edge cases.
- Is sent to the model provider's servers (where it's also logged).

If the secret is needed for the LLM to call an API, the call should
be made by the application after the LLM emits a tool-call request
— not by embedding the secret in the prompt.

## What to look for

**`system` / `instructions` parameter with env-var secret:**
```ts
await streamText({
  model,
  system: `You are a helpful assistant. Use this API key when needed: ${process.env.API_KEY}`,
});

await generateText({
  model,
  messages: [
    { role: "system", content: `Auth header: Bearer ${process.env.AUTH_TOKEN}` },
    { role: "user", content: userPrompt },
  ],
});
```

**Hardcoded secret patterns in system prompts:**
```ts
system: `Database connection: postgresql://admin:supersecret@db.internal/main`
system: `Internal endpoint key: sk-internal-12345`
```

**Variable names that hint at secrets being added to prompts:**
`api*Key`, `*Token`, `*Secret`, `*Password`, `*Credential`,
`*PrivateKey`, `dbUrl`, `connectionString`.

## Safe pattern

Define tools that the LLM can call. The application handles
authentication when invoking the tool — the secret never enters the
prompt:
```ts
const callApiTool = tool({
  description: "Call the internal API",
  parameters: z.object({ endpoint: z.string(), payload: z.any() }),
  execute: async ({ endpoint, payload }) => {
    return fetch(`https://api.internal${endpoint}`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${process.env.API_KEY}` },  // outside the prompt
      body: JSON.stringify(payload),
    }).then(r => r.json());
  },
});
```

## True positive criteria

Flag when ALL of the following hold:

1. A `system`, `instructions`, or `role: "system"` field in an LLM
   call.
2. The string includes `${process.env.X}` where X is a secret-shaped
   name, OR a hardcoded string matching a known secret format
   (`sk-...`, `ghp_...`, `xoxb-...`, `vck_...`, etc.).

## What to ignore

- System prompts that reference public values: model names, base
  URLs of public APIs, app name.
- System prompts that include env-var references but the referenced
  env var holds non-secret config (`process.env.APP_NAME`).
- Test files.

## Examples

True positives:
```ts
// Env var secret in system prompt
await streamText({
  model,
  system: `You are a billing agent. Use this Stripe key: ${process.env.STRIPE_SECRET_KEY}`,
});

// Hardcoded secret
await generateText({
  model,
  messages: [
    { role: "system", content: "Auth header: sk-real-secret-12345" },
    { role: "user", content: prompt },
  ],
});
```

False positives to skip:
```ts
// No secret in prompt
await streamText({
  model,
  system: "You are a helpful billing assistant.",
  tools: { chargeCustomer },   // tool body uses the secret server-side
});
```
