---
slug: js-remix-route
name: Remix Route Entry Points
description: Locates Remix loader/action exports, default route components, and auth helpers via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [remix]
noiseTier: noisy
filePatterns:
  - "**/app/routes/**/*.{ts,tsx,js,jsx}"
  - "**/routes/**/*.{ts,tsx,js,jsx}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "export\\s+(?:async\\s+)?(?:const|function)\\s+(?:loader|action)\\b"
    label: "Remix loader/action export"
  - regex: "export\\s+default\\s+function\\s+\\w+"
    label: "Remix default export route component"
  - regex: "\\bjson\\s*\\(\\s*\\{[^}]*\\}\\s*,\\s*\\{\\s*headers"
    label: "json() with custom headers (auth response)"
  - regex: "\\brequireUser(?:Id)?\\s*\\("
    label: "common Remix auth helper"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Remix loader/action exports,
default route components, and `requireUser`/`requireUserId` auth
helpers.

Gated on `tech: [remix]` — only runs when `fingerprint(root)`
detects Remix.

## What this finds

- `export const/function loader(...)` and `action(...)`
- `export default function Component(...)`
- `json({...}, { headers: { ... } })` with auth-related headers
- `requireUser(...)` / `requireUserId(...)` helpers

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
