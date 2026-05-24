---
slug: js-astro-endpoint
name: Astro Endpoint Entry Points
description: Locates Astro API endpoints, SSR routes, Astro.* accessors, and cookie writes via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [astro]
noiseTier: noisy
filePatterns:
  - "**/pages/**/*.{ts,js}"
  - "**/pages/api/**/*.{ts,js}"
  - "**/src/pages/**/*.astro"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "export\\s+(?:async\\s+)?(?:const|function)\\s+(GET|POST|PUT|PATCH|DELETE|ALL)\\b"
    label: "Astro endpoint method export"
  - regex: "\\bAstro\\.(?:request|cookies|params|url)\\b"
    label: "Astro.* request accessor"
  - regex: "\\bexport\\s+const\\s+prerender\\s*="
    label: "prerender flag (SSR / SSG split)"
  - regex: "\\bSetCookie\\s*\\(|cookies\\.set\\s*\\("
    label: "cookie write — auth surface"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Astro endpoint method exports,
`Astro.*` request accessors, `prerender` flags, and cookie writes.

Gated on `tech: [astro]` — only runs when `fingerprint(root)`
detects Astro.

## What this finds

- `export const/function GET/POST/PUT/PATCH/DELETE/ALL`
- `Astro.request` / `cookies` / `params` / `url` accessors
- `export const prerender = ...` (SSR / SSG split)
- `cookies.set(...)` / `SetCookie(...)` cookie writes — auth surface

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
