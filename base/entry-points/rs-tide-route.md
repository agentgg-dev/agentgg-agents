---
slug: rs-tide-route
name: Tide Route Entry Points
description: Locates Tide route handlers and Middleware declarations via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [tide]
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
  - regex: "\\bapp\\.at\\s*\\(\\s*\"[^\"]+\"\\s*\\)\\.(?:get|post|put|patch|delete|all)\\s*\\("
    label: "app.at('/path').<verb>(handler)"
  - regex: "\\btide::new\\s*\\(\\s*\\)"
    label: "tide::new() factory"
  - regex: "\\bMiddleware\\b"
    label: "Middleware trait — auth wiring"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Tide route handlers, app factory,
and Middleware declarations.

Gated on `tech: [tide]` — only runs when `fingerprint(root)` detects
Tide.

## What this finds

- `app.at("/path").<verb>(handler)` route bindings
- `tide::new()` factory
- `Middleware` trait references (auth wiring)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
