---
slug: js-hono-route
name: Hono Route Entry Points
description: Locates Hono route registrations, app instances, and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [hono]
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
  - regex: "\\b(?:app|router|hono)\\.(?:get|post|put|patch|delete|options|all|use)\\s*\\("
    label: "Hono method/use registration"
  - regex: "new\\s+Hono\\s*\\("
    label: "new Hono() instantiation"
  - regex: "\\bc\\.req\\.(?:query|param|json|formData|text|valid)\\b"
    label: "Request data accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Hono route registrations, app
instances, and `c.req.*` request accessors.

Gated on `tech: [hono]` — only runs when `fingerprint(root)` detects
Hono.

## What this finds

- `app/router/hono.get/post/put/patch/delete/options/all/use(...)`
- `new Hono(...)` instantiation
- `c.req.query` / `param` / `json` / `formData` / `text` / `valid` —
  untrusted input

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
