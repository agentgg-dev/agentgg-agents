---
slug: js-nuxt-route
name: Nuxt Server Route Entry Points
description: Locates Nuxt server routes / event handlers and h3 request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [nuxt]
noiseTier: noisy
filePatterns:
  - "**/server/api/**/*.{ts,js}"
  - "**/server/routes/**/*.{ts,js}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bdefineEventHandler\\s*\\("
    label: "defineEventHandler — Nuxt server entry point"
  - regex: "\\beventHandler\\s*\\("
    label: "h3 eventHandler factory"
  - regex: "\\bgetRouterParam(?:s)?\\s*\\(|\\bgetQuery\\s*\\(|\\breadBody\\s*\\("
    label: "h3 request accessor (untrusted input)"
  - regex: "\\bcreateError\\s*\\("
    label: "createError() throw site"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Nuxt server routes /
h3 event handlers, request accessors, and error throw sites.

Gated on `tech: [nuxt]` — only runs when `fingerprint(root)` detects
Nuxt.

## What this finds

- `defineEventHandler(...)` — Nuxt server entry point
- `eventHandler(...)` — h3 factory
- `getRouterParam(s)(...)` / `getQuery(...)` / `readBody(...)`
- `createError(...)` throw sites

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
