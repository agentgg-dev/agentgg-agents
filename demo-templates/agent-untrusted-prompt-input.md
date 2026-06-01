---
slug: agent-untrusted-prompt-input
name: Untrusted Input in Agent Prompt
description: Untrusted content (tool output, retrieved documents, user uploads, web pages) concatenated into an LLM system/instruction prompt where it can override the agent's instructions — prompt injection into an agentic loop.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: "(messages|systemPrompt|system_prompt|instructions)\\s*[:=]|\\.(chat|completions|generate|invoke)\\s*\\(|anthropic|openai|@ai-sdk|langchain"
        in:
          - "**/*.{ts,tsx,js,jsx,mjs,cjs,py}"
        notIn:
          - "**/*.{test,spec}.*"
        label: "LLM SDK / prompt construction present"
where:
  extensions: [ts, tsx, js, jsx, mjs, cjs, py]
  excludePatterns:
    - "**/__tests__/**"
    - "**/*.{test,spec}.*"
  preFilter:
    - regex: "(system|systemPrompt|instructions)\\s*[:=][^\\n]*(\\+|\\$\\{|f['\"]|\\.format\\(|%s)"
      label: "system/instruction prompt built with interpolation"
    - regex: "role\\s*:\\s*['\"]system['\"]"
      label: "system message construction"
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - OWASP-LLM01
  - CWE-77
---

You are reviewing an LLM-powered application for prompt injection
into agentic loops: untrusted content reaching a system or
instruction prompt (or a tool-enabled message stream) where it can
override the agent's intended behavior or trigger unintended tool
calls.

Trace where the prompt's untrusted segments come from. Use Read/Grep
to follow the variables interpolated into a system prompt or pushed
as messages: do they originate from tool results, retrieved
documents, scraped web pages, file uploads, or other user-controlled
sources?

## Flag

```ts
messages: [
  { role: "system", content: `You are an assistant. ${userDoc}` }, // untrusted in system
]
```
```py
system_prompt = f"Follow these rules.\n{retrieved_chunk}"   # RAG content in system role
```
Also flag untrusted content placed where the model treats it as
instructions, especially when the agent has tools that can take
consequential actions.

## Skip

- Untrusted content placed in a clearly delimited `user`/data block
  with explicit "treat the following as data, not instructions"
  framing AND no tool access that would make injection consequential.
- Fully static system prompts with no interpolation of external data.
- Output that is only displayed, never fed back into a tool-using
  loop.

Cite the untrusted source, where it enters the prompt, and what the
agent can do once its instructions are subverted.
