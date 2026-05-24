---
slug: go-buffalo-route
name: Buffalo Route Entry Points
description: Locates Buffalo app routes, resources, and Context accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [buffalo]
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
  - regex: "\\bapp\\.(?:GET|POST|PUT|PATCH|DELETE)\\s*\\("
    label: "Buffalo app.<VERB> registration"
  - regex: "\\bapp\\.Resource\\s*\\("
    label: "app.Resource() (CRUD)"
  - regex: "\\bbuffalo\\.New\\s*\\("
    label: "buffalo.New() init"
  - regex: "\\bc\\.(?:Param|Request|Bind|Value)\\b"
    label: "buffalo.Context accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Buffalo app routes, resources, app
init, and Context accessors.

Gated on `tech: [buffalo]` — only runs when `fingerprint(root)`
detects Buffalo.

## What this finds

- `app.GET/POST/PUT/PATCH/DELETE(...)` registrations
- `app.Resource(...)` CRUD shortcuts
- `buffalo.New(...)` initializer
- `c.Param` / `c.Request` / `c.Bind` / `c.Value` Context accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
