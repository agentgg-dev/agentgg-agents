---
slug: llm-output-to-sink
name: LLM Output Reaches a Dangerous Sink
description: 'Model completions (generateText, streamText, messages.create, chat.completions.create) whose text flows into exec, eval, raw SQL, a file path, an outbound URL, or dangerouslySetInnerHTML with nothing in between to constrain it. Traces the completion variable forward across helpers and files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\b(generateText|streamText|generateObject|streamObject)\s*\('
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Vercel AI SDK completion call
      - regex: 'messages\.create\s*\(|chat\.completions\.create\s*\(|generate_content\s*\('
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.py'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Provider SDK completion call
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,cjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs,cjs}'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '\b(generateText|streamText|generateObject|streamObject)\s*\('
      label: Vercel AI SDK completion call
    - regex: 'messages\.create\s*\(|chat\.completions\.create\s*\(|generate_content\s*\('
      label: Provider SDK completion call
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
validationPrompt: |
  Treat the model completion as attacker-controlled. Do not ask for proof
  that a named attacker can steer it, and do not answer 'uncertain' only
  because the injection source is unclear. An unconstrained completion
  that reaches a sink IS this bug class. Use the cross-file tracing
  instructions above to follow the value. Do not use them to demand an
  attacker-reachable entry point.

  Return 'confirmed' when a value that originates from a model completion
  reaches a sink that executes it, queries with it, resolves a path or a
  URL from it, or renders it as markup, and no step in between narrows it
  to a closed set of safe values. Name the sink call and the variable
  that carries the completion.

  Return 'false-positive' when any of these hold:
    - the completion is parsed into a schema, and every field that
      reaches the sink is an enum, a boolean, a number, or another closed
      set. A free-text string field is NOT a constraint
    - the sink is a parameterized query and the completion is a bound
      parameter, not concatenated SQL
    - the completion is only rendered as escaped text
    - the value reaches no sink of the kinds listed above, for example a
      log line, a metric, or a chat reply
    - the value is a tool-call ARGUMENT inside a tool `execute` body, not
      a completion the caller received back
    - the value at the sink does not come from a completion at all

  Return 'uncertain' when you traced the value and still cannot tell
  whether it came from the model, or whether a step in between
  constrains it.

  If the prompt above includes scope rules and those rules exclude this
  finding, return 'out-of-scope'.
references:
  - CWE-94
  - CWE-78
  - OWASP-LLM05
---

You are reviewing AI/LLM application code for improper output handling:
the text a model returns is treated as trusted data and handed to a sink
that executes, queries, or renders it.

A completion is never trusted input. It is shaped by the system prompt,
by user turns, and by every document, tool result, or web page the model
read. An attacker who controls any of those controls the string that
reaches the sink.

**Cross-file analysis:** the completion and the sink are often in
different files. Start at the LLM call, name the variable that holds the
result (`text`, `content`, `choices[0].message.content`,
`.content[0].text`, `response.text`,
`candidates[0].content.parts[0].text`), then Grep for it: a return
value, an exported helper, a queue payload. Follow it until it reaches a
sink or is constrained.

## What to look for

**Completion into a shell:**
```ts
const { text } = await generateText({ model, prompt });
execSync(text);
```

**Streamed completion, accumulated then executed:**
```ts
const result = streamText({ model, prompt });
let full = "";
for await (const chunk of result.textStream) full += chunk;
execSync(full);
```

**Completion into raw SQL** (common in text-to-SQL features):
```ts
const { text } = await generateText({ model, prompt: askForQuery });
const rows = await prisma.$queryRawUnsafe(text);
```

**Completion into a file path:**
```ts
const { text } = await generateText({ model, prompt });
await writeFile(join(outDir, text), body);
```
`text` can be `../../../.ssh/authorized_keys`.

**Completion into an outbound request** (the model picks the host):
```python
resp = client.messages.create(model=m, messages=msgs)
requests.get(resp.content[0].text)
```

**Completion rendered as markup:**
```tsx
<div dangerouslySetInnerHTML={{ __html: completion }} />
```

**Completion into eval / new Function:**
```ts
const fn = new Function(completion);
```

## True positive criteria

Flag when ALL of the following hold:

1. A value originates from a model completion.
2. That value reaches a sink that executes it, queries with it, resolves
   a path or a URL from it, or renders it as markup.
3. No step in between narrows it to a closed set of safe values.

## What to ignore

- Structured output whose schema really constrains the value: the field
  that reaches the sink is an enum, a boolean, a number, or another
  closed set. A `z.string()` field is not a constraint. Flag that one.
- A completion used as a bound parameter in a parameterized query.
- A completion rendered as escaped text (plain JSX children,
  `textContent`, a template engine that escapes by default).
- A completion used only for logs, metrics, or a chat reply.
- A `messages.create(` call that is not an LLM call. The Twilio SMS
  client uses the same method name in both Node and Python.
- Tool-call ARGUMENTS handled inside a tool `execute` body. That is
  `agent-tool-definition`, not this agent.

## Examples

True positives:
```ts
// shell
const { text } = await generateText({ model, prompt: userAsk });
const out = execSync(`ffmpeg ${text}`);

// raw SQL from a text-to-SQL feature
const sql = (await openai.chat.completions.create({ model, messages }))
  .choices[0].message.content;
const rows = await db.$queryRawUnsafe(sql);

// a schema that does not constrain — cmd is free text
const { object } = await generateObject({
  model,
  schema: z.object({ cmd: z.string() }),
});
execSync(object.cmd);
```

False positives to skip:
```ts
// constrained by a schema — only the enum reaches the sink
const { object } = await generateObject({
  model,
  schema: z.object({ action: z.enum(["archive", "delete"]) }),
});
if (object.action === "delete") await hardDelete(id);

// bound parameter, not concatenated SQL
const { text } = await generateText({ model, prompt });
await db.query("select * from docs where title = $1", [text]);
```
