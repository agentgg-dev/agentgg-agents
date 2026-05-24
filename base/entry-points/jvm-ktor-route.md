---
slug: jvm-ktor-route
name: Ktor Route Entry Points
description: Locates Ktor routing DSL blocks, verb declarations, authenticate scopes, and call.receive sites via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [ktor]
noiseTier: noisy
filePatterns:
  - "**/*.kt"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/src/test/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/target/**"
preFilter:
  - regex: "\\brouting\\s*\\{"
    label: "routing { ... } block"
  - regex: "\\b(?:get|post|put|patch|delete)\\s*\\(\\s*\"[^\"]+\"\\s*\\)\\s*\\{"
    label: "<verb>('/path') { ... }"
  - regex: "\\bauthenticate\\s*\\(\\s*\"[^\"]+\"\\s*\\)\\s*\\{"
    label: "authenticate('jwt') { ... } scope"
  - regex: "\\bcall\\.receive\\b"
    label: "call.receive (untrusted body)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Ktor `routing { ... }` blocks,
verb-bound routes, `authenticate(...)` scopes, and `call.receive`
sites.

Gated on `tech: [ktor]` — only runs when `fingerprint(root)` detects
Ktor.

## What this finds

- `routing { ... }` top-level block
- `get/post/put/patch/delete("/path") { ... }` route DSL
- `authenticate("scheme") { ... }` auth scope
- `call.receive<T>()` — untrusted body deserialization

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
