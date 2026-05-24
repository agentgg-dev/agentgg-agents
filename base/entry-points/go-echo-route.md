---
slug: go-echo-route
name: Echo Route Entry Points
description: Locates Echo (labstack) route registrations and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [echo]
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
  - regex: "\\b(?:e|app|server|g)\\.(?:GET|POST|PUT|PATCH|DELETE|Any|Match)\\s*\\("
    label: "Echo method registration"
  - regex: "\\b(?:e|app|server)\\.Group\\s*\\("
    label: "Echo .Group (auth scope)"
  - regex: "\\becho\\.New\\s*\\(\\s*\\)"
    label: "echo.New() init"
  - regex: "\\bc\\.(?:Param|QueryParam|FormValue|Bind|Request)\\b"
    label: "Request accessor (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Echo (labstack) route
registrations, route groups, and untrusted-input accessors so
downstream walker/hunt/file agents see them as anchor points.

Gated on `tech: [echo]` — only runs when `fingerprint(root)`
detects Echo.

## What this finds

- Method registrations (`e.GET`, `app.POST`, `server.PUT`, `g.PATCH`,
  `e.Any`, `e.Match`)
- `.Group(...)` route groups (auth scope)
- `echo.New()` engine initializer
- Request accessors (`c.Param`, `c.QueryParam`, `c.FormValue`,
  `c.Bind`, `c.Request`) — untrusted input

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
