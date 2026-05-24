---
slug: js-sveltekit-route
name: SvelteKit Route Entry Points
description: Locates SvelteKit +server method handlers, load functions, and actions exports via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [sveltekit]
noiseTier: noisy
filePatterns:
  - "**/+page.server.{ts,js}"
  - "**/+server.{ts,js}"
  - "**/+layout.server.{ts,js}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "export\\s+(?:async\\s+)?(?:const|function)\\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\\b"
    label: "+server method handler"
  - regex: "export\\s+(?:async\\s+)?(?:const|function)\\s+load\\b"
    label: "+page.server.ts / +layout.server.ts load function"
  - regex: "export\\s+const\\s+actions\\s*[:=]"
    label: "+page.server.ts actions export (form actions)"
  - regex: "\\b(?:fail|redirect|error)\\s*\\("
    label: "SvelteKit response helper"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates SvelteKit `+server.ts` method
handlers, `load` functions, `actions` exports, and response
helpers.

Gated on `tech: [sveltekit]` — only runs when `fingerprint(root)`
detects SvelteKit.

## What this finds

- `export const/function GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD`
- `export const/function load` (`+page.server.ts` /
  `+layout.server.ts`)
- `export const actions` (form actions)
- `fail/redirect/error(...)` response helpers

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
