---
slug: py-bottle-route
name: Bottle Route Entry Points
description: Locates Bottle route decorators and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [bottle]
noiseTier: noisy
filePatterns:
  - "**/*.py"
excludePatterns:
  - "**/tests/**"
  - "**/test/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "**/migrations/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^\\s*@(?:route|get|post|put|patch|delete)\\s*\\(\\s*['\"][^'\"]+['\"]"
    label: "Bottle @route/@method decorator"
  - regex: "\\bBottle\\s*\\(\\s*\\)"
    label: "Bottle() instance"
  - regex: "\\brequest\\.(?:query|forms|json|cookies)\\b"
    label: "request accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Bottle route decorators, app
instances, and request accessors.

Gated on `tech: [bottle]` — only runs when `fingerprint(root)`
detects Bottle.

## What this finds

- `@route` / `@get` / `@post` / `@put` / `@patch` / `@delete`
  decorators
- `Bottle()` instance
- `request.query` / `forms` / `json` / `cookies` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
