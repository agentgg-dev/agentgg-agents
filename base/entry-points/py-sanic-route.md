---
slug: py-sanic-route
name: Sanic Route Entry Points
description: Locates Sanic route handlers, Blueprints, and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [sanic]
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
  - regex: "^\\s*@(?:app|bp|blueprint)\\.route\\s*\\("
    label: "Sanic @app.route / @bp.route"
  - regex: "^\\s*@(?:app|bp)\\.(?:get|post|put|patch|delete|head|options|websocket)\\s*\\("
    label: "Sanic method-shortcut decorator"
  - regex: "\\bSanic\\s*\\(\\s*['\"][^'\"]*['\"]\\s*\\)"
    label: "Sanic() instance"
  - regex: "\\brequest\\.(?:args|json|form|files|headers)\\b"
    label: "request accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Sanic route handlers, Blueprints,
app initialization, and request accessors.

Gated on `tech: [sanic]` — only runs when `fingerprint(root)`
detects Sanic.

## What this finds

- `@app.route` / `@bp.route` / `@blueprint.route` decorators
- Method-shortcut decorators (`@app.get`, `@bp.post`, etc.,
  including `@app.websocket`)
- `Sanic('app-name')` initializer
- `request.args` / `json` / `form` / `files` / `headers` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
