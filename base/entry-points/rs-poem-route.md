---
slug: rs-poem-route
name: Poem Route Entry Points
description: Locates Poem route declarations, #[handler] attributes, and verb wrappers via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [poem]
noiseTier: noisy
filePatterns:
  - "**/*.rs"
excludePatterns:
  - "**/tests/**"
  - "**/examples/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/target/**"
preFilter:
  - regex: "\\bRoute::new\\s*\\(\\s*\\)\\.at\\s*\\(\\s*\"[^\"]+\"\\s*,"
    label: "Route::new().at('/path', ...)"
  - regex: "#\\[\\s*handler\\s*\\]"
    label: "#[handler] attribute"
  - regex: "\\bget\\s*\\(|post\\s*\\(|put\\s*\\(|patch\\s*\\(|delete\\s*\\("
    label: "handler verb wrapper"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Poem route declarations,
`#[handler]` attributes, and verb-wrapped handlers.

Gated on `tech: [poem]` — only runs when `fingerprint(root)` detects
Poem.

## What this finds

- `Route::new().at("/path", ...)` route declarations
- `#[handler]` function attributes
- `get(...)` / `post(...)` / `put(...)` / `patch(...)` / `delete(...)`
  handler verb wrappers

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
