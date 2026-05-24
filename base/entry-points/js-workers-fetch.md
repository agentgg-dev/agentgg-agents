---
slug: js-workers-fetch
name: Cloudflare Workers Fetch Handler Entry Points
description: Locates Cloudflare Workers / edge runtime default-export fetch handlers, env.* bindings, and cache API via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [workers]
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
  - regex: "export\\s+default\\s*\\{\\s*(?:async\\s+)?fetch\\s*\\("
    label: "Workers default export { fetch(req, env, ctx) }"
  - regex: "addEventListener\\s*\\(\\s*['\"]fetch['\"]"
    label: "addEventListener('fetch', ...) — service worker"
  - regex: "\\benv\\.[A-Z][A-Z0-9_]+"
    label: "env.* binding access (KV, R2, secrets)"
  - regex: "\\bcaches\\.default\\b|\\bcaches\\.open\\s*\\("
    label: "Workers cache API — review key composition"
references:
  - CWE-862
  - CWE-200
---

Regex-only rule (no LLM). Locates Cloudflare Workers / edge runtime
fetch handlers, `env.*` bindings, and cache API usage.

Gated on `tech: [workers]` — only runs when `fingerprint(root)`
detects a Workers project.

## What this finds

- `export default { fetch(req, env, ctx) }` module-syntax handler
- `addEventListener('fetch', ...)` service-worker syntax
- `env.SOMETHING` binding access (KV, R2, secrets)
- `caches.default` / `caches.open(...)` cache API

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
