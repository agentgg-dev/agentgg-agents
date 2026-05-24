---
slug: js-fastify-route
name: Fastify Route Entry Points
description: Locates Fastify route registrations, route-object form, and lifecycle hooks via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [fastify]
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
  - regex: "\\b(?:fastify|instance|app|server)\\.(?:get|post|put|patch|delete|head|options|route|register)\\s*\\("
    label: "fastify method/route/register call"
  - regex: "\\.route\\s*\\(\\s*\\{[\\s\\S]*?method\\s*:"
    label: "fastify .route({ method, ... }) form"
  - regex: "addHook\\s*\\(\\s*['\"](?:onRequest|preHandler|preValidation)['\"]"
    label: "auth-relevant lifecycle hook"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Fastify route registrations, the
route-object form, and `addHook` calls for auth-relevant lifecycle
phases.

Gated on `tech: [fastify]` — only runs when `fingerprint(root)`
detects Fastify.

## What this finds

- `fastify/instance/app/server.<verb>(...)` registrations
- `.route({ method, url, handler })` object form
- `.register(...)` plugin loaders
- `.addHook('onRequest'|'preHandler'|'preValidation', ...)` —
  auth-relevant lifecycle hooks

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
