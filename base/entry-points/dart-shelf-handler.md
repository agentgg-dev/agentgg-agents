---
slug: dart-shelf-handler
name: Dart Shelf Handler Entry Points
description: Locates Dart Shelf Router factories, route bindings, handler signatures, and Pipeline middleware via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [shelf]
noiseTier: noisy
filePatterns:
  - "**/*.dart"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bRouter\\s*\\(\\s*\\)"
    label: "shelf_router Router() factory"
  - regex: "\\.(?:get|post|put|patch|delete|head|options|all)\\s*\\(\\s*'[^']+'\\s*,"
    label: "router.<verb>('/path', handler)"
  - regex: "\\bRequest\\s+\\w+\\s*\\)"
    label: "Handler signature taking shelf Request"
  - regex: "\\bPipeline\\s*\\(\\s*\\)\\.addMiddleware\\b"
    label: "Pipeline().addMiddleware"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Dart Shelf Router factories,
verb-bound routes, Request handler signatures, and Pipeline
middleware.

Gated on `tech: [shelf]` — only runs when `fingerprint(root)`
detects Shelf.

## What this finds

- `Router()` factory
- `.get/post/put/patch/delete/head/options/all('/path', handler)`
- Handler signatures taking `Request`
- `Pipeline().addMiddleware(...)` middleware chains

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
