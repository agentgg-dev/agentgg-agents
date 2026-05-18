---
slug: agent-tool-definition
name: AI Agent Tool Definition Surface
description: AI agent tool / function-calling definitions — review the execute body for shell exec, fs writes, network egress, DB writes, or other high-privilege capabilities exposed to LLM-controlled arguments. Walker mode follows execute helpers into the rest of the codebase.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/tools/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/agent/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/agents/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/*tool*.{ts,tsx,js,jsx,mjs}"
  - "**/*agent*.{ts,tsx,js,jsx,mjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "\\btool\\s*\\(\\s*\\{|\\bcreateTool\\s*\\(|\\bdefineTool\\s*\\("
    label: "Tool definition (tool/createTool/defineTool)"
  - regex: "execute\\s*:\\s*async\\s*\\("
    label: "Tool execute body"
  - regex: "\\btools\\s*:\\s*\\{"
    label: "tools: { ... } object in LLM call"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-94
  - OWASP-LLM06
  - OWASP-LLM07
---

You are reviewing AI agent tool definitions — function-calling
schemas that the LLM can invoke with arguments. Each tool is a
remote-procedure-call exposed to the LLM, so the tool body must
treat the arguments as untrusted (they came from a prompt-injected
or hallucinating model) and limit what the tool can do.

**Walker mode advantage:** tool `execute` bodies frequently delegate
to a helper (`runShell`, `userRepo.update`, `mailer.send`). Open the
helper to assess actual capability — a tool wrapper that looks
narrow may unwrap into raw `child_process.exec` or arbitrary fetch.
Also verify whether the tool validates arguments and performs per-
call authz against the agent's user.

## What to look for

**Tool definitions via Vercel AI SDK / OpenAI / Anthropic:**
```ts
const myTool = tool({
  description: "do thing",
  parameters: z.object({ ... }),
  execute: async (args) => { ... },
});

const t = createTool({ name: "x", execute: async (args) => {...} });
const t = defineTool({ name: "x", parameters, execute });
```

**Dangerous capabilities to flag in `execute` bodies:**

1. **Shell / process execution:**
   ```ts
   import { exec } from "child_process";
   execute: async ({ cmd }) => exec(cmd);   // arbitrary RCE via prompt
   ```
2. **File system write / arbitrary path read:**
   ```ts
   execute: async ({ path, content }) => fs.writeFile(path, content);
   ```
3. **Arbitrary HTTP fetch (SSRF):**
   ```ts
   execute: async ({ url }) => fetch(url).then(r => r.text());
   ```
4. **Database writes:**
   ```ts
   execute: async ({ id, data }) => db.user.update({ where: { id }, data });
   ```
5. **Email / SMS / notification send:**
   ```ts
   execute: async ({ to, subject, body }) => resend.emails.send({ to, subject, html: body });
   ```
6. **Payment authorization:**
   ```ts
   execute: async ({ amount }) => stripe.charges.create({ amount });
   ```
7. **Code evaluation:** `eval`, `vm.run*`, `new Function`.

## Required mitigations to look for

- Per-tool authz: the tool checks that the agent's user has
  permission for this specific action.
- Argument validation: Zod schemas with strict format / value
  allowlists.
- Scoped capabilities: a `read_file` tool that's limited to a
  specific directory tree, an HTTP tool with a domain allowlist, a
  DB tool that scopes by `userId` from the session.
- Human-in-the-loop confirmation for high-stakes actions
  (payments, deletes, sends).

## True positive criteria

Flag every tool definition for review when:
1. The `execute` body invokes shell / fs write / arbitrary fetch /
   DB write / email send / payment / code eval, AND
2. The tool does not validate its arguments against a strict
   allowlist or check per-call authorization, AND
3. The agent that invokes this tool is fed untrusted content
   (covered by `agentic-untrusted-prompt-input`).

## What to ignore

- Read-only tools that don't expose write capabilities (a `get_weather`
  tool calling a weather API).
- Tools with strict argument allowlists and per-call auth checks.
- Test fixtures.

## Examples

True positives:
```ts
const runShellTool = tool({
  description: "Run a shell command",
  parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }) => {
    const { exec } = require("child_process");
    return new Promise(r => exec(cmd, (e, out) => r(out)));
  },
});

const fetchUrlTool = tool({
  description: "Fetch any URL",
  parameters: z.object({ url: z.string() }),
  execute: async ({ url }) => fetch(url).then(r => r.text()),
});
```

False positives to skip:
```ts
const readDocTool = tool({
  description: "Read a doc from the user's library",
  parameters: z.object({ docId: z.string().uuid() }),
  execute: async ({ docId }) => {
    const doc = await db.docs.findFirst({
      where: { id: docId, ownerId: session.userId },
    });
    if (!doc) throw new Error("not found");
    return { content: doc.content };
  },
});
```
