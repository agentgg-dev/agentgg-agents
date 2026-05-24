---
slug: py-aiohttp-route
name: aiohttp Route Entry Points
description: Locates aiohttp route registrations and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [aiohttp]
noiseTier: noisy
filePatterns:
  - "**/*.py"
excludePatterns:
  - "**/tests/**"
  - "**/test/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "**/migrations/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bapp\\.router\\.add_(?:get|post|put|patch|delete|route)\\s*\\("
    label: "app.router.add_*"
  - regex: "^\\s*@routes\\.(?:get|post|put|patch|delete|view)\\s*\\("
    label: "@routes.* decorator"
  - regex: "\\bweb\\.Application\\s*\\("
    label: "web.Application() init"
  - regex: "\\brequest\\.(?:query|match_info|json|post|read)\\b"
    label: "request accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates aiohttp route registrations,
application init, and request accessors.

Gated on `tech: [aiohttp]` — only runs when `fingerprint(root)`
detects aiohttp.

## What this finds

- `app.router.add_get/post/put/patch/delete/route(...)`
- `@routes.get/post/put/patch/delete/view(...)` decorators
- `web.Application(...)` initializer
- `request.query` / `match_info` / `json` / `post` / `read` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
