---
slug: go-fiber-route
name: Fiber Route Entry Points
description: Locates Fiber route registrations, groups, and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [fiber]
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
  - regex: "\\b(?:app|api|router|g)\\.(?:Get|Post|Put|Patch|Delete|All)\\s*\\("
    label: "Fiber method registration"
  - regex: "\\bfiber\\.New\\s*\\("
    label: "fiber.New() init"
  - regex: "\\.Group\\s*\\("
    label: "Fiber .Group (auth scope)"
  - regex: "\\bc\\.(?:Query|Params|Body(?:Parser)?|Get|FormValue|Cookies)\\b"
    label: "Request accessor (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Fiber route registrations, route
groups, app init, and untrusted-input accessors.

Gated on `tech: [fiber]` — only runs when `fingerprint(root)` detects
Fiber.

## What this finds

- Method registrations (`app.Get`, `api.Post`, `router.Put`,
  `g.Patch`, `app.All`)
- `fiber.New(...)` initializer
- `.Group(...)` route groups (auth scope)
- Request accessors (`c.Query`, `c.Params`, `c.Body`, `c.BodyParser`,
  `c.Get`, `c.FormValue`, `c.Cookies`) — untrusted input

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
