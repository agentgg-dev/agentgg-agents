---
slug: js-solidstart-action
name: SolidStart Server Action Entry Points
description: Locates SolidStart server actions, cached server functions, and 'use server' directives via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [solidstart]
noiseTier: noisy
filePatterns:
  - "**/*.{ts,tsx,js,jsx}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\b(?:action|cache|query)\\s*\\(\\s*async\\s*\\("
    label: "action/cache/query factory"
  - regex: "\\b['\"]use server['\"]\\s*;?"
    label: "'use server' directive (publicly callable)"
  - regex: "\\baction\\$\\s*\\(|\\bserver\\$\\s*\\("
    label: "action$ / server$ helper"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates SolidStart server actions, cached
server functions, `'use server'` directives, and `action$`/`server$`
helpers.

Gated on `tech: [solidstart]` — only runs when `fingerprint(root)`
detects SolidStart.

## What this finds

- `action(async ...)` / `cache(async ...)` / `query(async ...)`
- `'use server'` directives — publicly callable
- `action$(...)` / `server$(...)` helpers

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
