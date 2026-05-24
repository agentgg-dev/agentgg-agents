---
slug: js-koa-route
name: Koa Route Entry Points
description: Locates Koa router method registrations, Koa instances, and ctx accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [koa]
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
  - regex: "\\b(?:router|app)\\.(?:get|post|put|patch|del|delete|all|use)\\s*\\("
    label: "Koa router method registration"
  - regex: "new\\s+Koa\\s*\\("
    label: "new Koa() instantiation"
  - regex: "\\bKoaRouter\\s*\\(|@koa/router"
    label: "@koa/router import or factory"
  - regex: "async\\s*\\(\\s*ctx\\s*[,)]"
    label: "Koa middleware (ctx) signature"
  - regex: "\\bctx\\.(?:request|query|params|state|throw)\\b"
    label: "ctx.* accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Koa router/app method
registrations, app instances, middleware signatures, and `ctx.*`
accessors.

Gated on `tech: [koa]` — only runs when `fingerprint(root)` detects
Koa.

## What this finds

- `router/app.get/post/put/patch/del/delete/all/use(...)`
- `new Koa(...)` instantiation
- `@koa/router` import / `KoaRouter(...)` factory
- `async (ctx, next) => ...` middleware signature
- `ctx.request` / `query` / `params` / `state` / `throw` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
