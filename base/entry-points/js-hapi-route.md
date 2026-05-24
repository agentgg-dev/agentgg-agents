---
slug: js-hapi-route
name: Hapi Route Entry Points
description: Locates Hapi server.route declarations and auth strategy/options via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [hapi]
noiseTier: noisy
filePatterns:
  - "**/*.{ts,js,mjs,cjs}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bserver\\.route\\s*\\(\\s*\\{"
    label: "server.route({ method, path, handler })"
  - regex: "Hapi\\.server\\s*\\("
    label: "Hapi.server() init"
  - regex: "options:\\s*\\{\\s*auth:"
    label: "route auth option (verify scope)"
  - regex: "strategy\\s*:\\s*['\"][^'\"]+['\"]"
    label: "auth strategy declaration"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Hapi route declarations, server
init, and route-level auth options/strategies.

Gated on `tech: [hapi]` — only runs when `fingerprint(root)` detects
Hapi.

## What this finds

- `server.route({ method, path, handler })` declarations
- `Hapi.server(...)` initializer
- `options: { auth: ... }` route-level auth options
- `strategy: '...'` auth strategy declarations

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
