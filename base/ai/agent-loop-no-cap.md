---
slug: agent-loop-no-cap
name: Agent Loop / LLM Call Without Cap
description: streamText / generateText / Claude Agent SDK query without maxSteps / maxTurns / stopWhen / abortSignal — unbounded tool-use loops can drain budget and never terminate. Walker mode follows shared config and helper wrappers.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
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
  - regex: "\\b(streamText|generateText|streamObject|generateObject)\\s*\\("
    label: "Vercel AI SDK invocation"
  - regex: "@anthropic-ai/claude-agent-sdk|\\bquery\\s*\\(\\s*\\{\\s*prompt"
    label: "Claude Agent SDK query"
  - regex: "while\\s*\\(\\s*true\\s*\\)|for\\s+await\\s*\\(.*\\bagent\\b"
    label: "Unbounded polling/streaming loop"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-770
  - OWASP-LLM10
---

You are reviewing LLM / agent invocations for missing termination
caps.

**Walker mode advantage:** projects often centralize agent config
(`createAgent`, `defaultAgentConfig`, `withDefaults`) in a shared
module. If the candidate call passes `...defaults`, open that helper
to see whether the caps (`maxSteps`, `maxTurns`, `abortSignal`) are
set there. A bare-looking call may already be bounded by the wrapper. Agentic loops where the LLM calls tools and the tool results
feed back into the next turn can run forever in pathological cases:
the model gets stuck in a tool-use loop, an external service returns
empty results that the model keeps retrying, or a malicious prompt
specifically attempts to maximize tool calls. Without a cap, this
burns API tokens (real money) until the process is killed.

## What to look for

**Vercel AI SDK without `maxSteps` / `stopWhen` / `abortSignal`:**
```ts
import { streamText, generateText } from "ai";

const result = streamText({
  model: openai("gpt-4o"),
  prompt: "research this topic",
  tools: { search, scrape, summarize },
  // No maxSteps — unbounded tool calls
});

await generateText({ model, prompt: "hi" });   // no cap
await generateObject({ model, schema, prompt });
```

**Claude Agent SDK `query` without `maxTurns`:**
```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
await query({ prompt: "do thing" });   // no maxTurns
```

**Raw `for await` loop over agent events with no break condition or
counter:**
```ts
for await (const event of agent.stream()) {
  process(event);
  // No iteration cap, no abort
}
```

**OpenAI Assistants polling loop:**
```ts
while (true) {
  const run = await openai.beta.threads.runs.retrieve(threadId, runId);
  if (run.status === "completed") break;
  await sleep(1000);
}
// No max attempts, no wall-clock cap
```

## Safe caps to look for

- `maxSteps: N`, `maxToolRoundtrips: N` (AI SDK)
- `maxTurns: N` (Claude Agent SDK)
- `stopWhen: condition` (AI SDK)
- `abortSignal: AbortSignal.timeout(ms)` or
  `signal: controller.signal`
- An explicit counter / break in `for await` / `while` loops
- `setTimeout(() => controller.abort(), MS)` paired with the
  signal passed to the call

## True positive criteria

Flag when ALL of the following hold:

1. The file makes an LLM call (`streamText`, `generateText`,
   `generateObject`, `streamObject`, Claude Agent `query`, OpenAI
   `chat.completions.create` with `tools`, etc.).
2. The call passes `tools` (enabling agentic loop behavior) OR is
   in a `for await` / `while (true)` loop.
3. None of the cap mechanisms above is present.

## What to ignore

- One-shot LLM calls without `tools` and without a loop wrapper
  (the model returns once and terminates naturally).
- Calls inside a clearly bounded helper (`runWithTimeout(fn, ms)`).
- Test files.

## Examples

True positives:
```ts
// streamText with tools but no cap
const stream = streamText({
  model: openai("gpt-4o"),
  tools: { search, scrape, summarize },
  prompt: userPrompt,
});

// Claude Agent SDK without maxTurns
await query({ prompt: "help me debug" });
```

False positives to skip:
```ts
// streamText with cap
const stream = streamText({
  model: openai("gpt-4o"),
  tools: { ... },
  maxSteps: 10,
  abortSignal: AbortSignal.timeout(60_000),
  prompt: userPrompt,
});

// Claude with maxTurns
await query({ prompt: "...", maxTurns: 20 });
```
