---
slug: js-bun-serve
name: Bun.serve Fetch Handler Entry Points
description: Locates Bun.serve fetch handlers and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [bun]
noiseTier: noisy
filePatterns:
  - "**/*.{ts,js,mjs}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bBun\\.serve\\s*\\(\\s*\\{"
    label: "Bun.serve({ fetch(req) ... })"
  - regex: "(?:async\\s+)?fetch\\s*\\(\\s*req(?:uest)?\\s*[,)]"
    label: "fetch(req) handler body"
  - regex: "\\brequest\\.(?:url|headers|method)\\b"
    label: "request.* accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Bun.serve fetch handlers and
`request.*` accessors.

Gated on `tech: [bun]` — only runs when `fingerprint(root)` detects
Bun.

## What this finds

- `Bun.serve({ fetch(req) ... })` declarations
- `(async) fetch(req, server)` handler bodies
- `request.url` / `headers` / `method` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
