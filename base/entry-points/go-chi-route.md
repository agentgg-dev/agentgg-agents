---
slug: go-chi-route
name: Chi Route Entry Points
description: Locates Chi router registrations, subroute groups, and URL param accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [chi]
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
  - regex: "\\b(?:r|router|api)\\.(?:Get|Post|Put|Patch|Delete|Method|Handle|HandleFunc)\\s*\\("
    label: "Chi method registration"
  - regex: "\\bchi\\.NewRouter\\s*\\(\\s*\\)"
    label: "chi.NewRouter() init"
  - regex: "\\.Route\\s*\\("
    label: "Chi .Route (subroute scope)"
  - regex: "\\.Group\\s*\\("
    label: "Chi .Group (middleware scope)"
  - regex: "\\.Mount\\s*\\("
    label: "Chi .Mount (subrouter — middleware inheritance gotcha)"
  - regex: "\\bchi\\.URLParam\\s*\\("
    label: "chi.URLParam (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Chi router registrations, scoped
subroutes, mounted subrouters, and URL param accessors so downstream
walker/hunt/file agents see them as anchor points.

Gated on `tech: [chi]` — only runs when `fingerprint(root)` detects
Chi.

## What this finds

- Method registrations (`r.Get`, `router.Post`, `api.Put`, `r.Patch`,
  `r.Delete`, `r.Method`, `r.Handle`, `r.HandleFunc`)
- `chi.NewRouter()` initializer
- `.Route(...)` subroute scopes
- `.Group(...)` middleware scopes
- `.Mount(...)` subrouter mounts (middleware inheritance gotcha)
- `chi.URLParam(...)` accessors — untrusted input

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
