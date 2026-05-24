---
slug: go-gin-route
name: Gin Route Entry Points
description: Locates Gin route registrations, group middleware, and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [gin]
noiseTier: noisy
filePatterns:
  - "**/*.go"
excludePatterns:
  - "**/*_test.go"
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\b(?:r|router|engine|api|v\\d+)\\.(?:GET|POST|PUT|PATCH|DELETE|Any|Handle)\\s*\\("
    label: "Gin method registration"
  - regex: "\\.Group\\s*\\("
    label: "Gin .Group (middleware scope)"
  - regex: "gin\\.Default\\s*\\(\\s*\\)|gin\\.New\\s*\\(\\s*\\)"
    label: "Gin engine init"
  - regex: "\\bc\\.(?:Query|Param|PostForm|GetHeader|ShouldBind\\w*)\\b"
    label: "Request data accessor (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Gin route registrations, route
groups, engine initializers, and untrusted-input accessors so
downstream walker/hunt/file agents see them as anchor points.

Gated on `tech: [gin]` — only runs when `fingerprint(root)` detects
Gin.

## What this finds

- Method registrations (`r.GET`, `router.POST`, `engine.PUT`,
  `api.PATCH`, `v1.DELETE`, `r.Any`, `r.Handle`)
- `.Group(...)` route groups (middleware scope)
- `gin.Default()` / `gin.New()` engine initializers
- Request data accessors (`c.Query`, `c.Param`, `c.PostForm`,
  `c.GetHeader`, `c.ShouldBind*`) — untrusted input

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
