---
slug: js-deno-route
name: Deno HTTP / Oak Route Entry Points
description: Locates Deno.serve handlers and Oak router methods via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [deno]
noiseTier: noisy
filePatterns:
  - "**/*.{ts,tsx}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bDeno\\.serve\\s*\\("
    label: "Deno.serve() entry point"
  - regex: "\\brouter\\.(?:get|post|put|patch|delete|all|use)\\s*\\("
    label: "Oak router method"
  - regex: "import\\s*\\{[^}]*\\bApplication\\b[^}]*\\}\\s*from\\s*['\"]https?://deno\\.land/x/oak"
    label: "Oak Application import"
  - regex: "\\bctx\\.request\\.(?:url|body|headers)\\b"
    label: "Oak ctx.request accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Deno HTTP server / Oak router
handlers and `ctx.request.*` accessors.

Gated on `tech: [deno]` — only runs when `fingerprint(root)` detects
Deno.

## What this finds

- `Deno.serve(...)` entry points
- `router.get/post/put/patch/delete/all/use(...)` — Oak methods
- Oak `Application` import from `deno.land/x/oak`
- `ctx.request.url` / `body` / `headers` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
