---
slug: py-fastapi-route
name: FastAPI Route Entry Points
description: Locates FastAPI route handlers and dependency injection markers via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [fastapi]
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
  - regex: "^\\s*@(?:app|router|api)\\.(?:get|post|put|patch|delete|options|head|websocket)\\s*\\("
    label: "FastAPI route decorator"
  - regex: "\\bAPIRouter\\s*\\("
    label: "APIRouter() factory"
  - regex: "=\\s*Depends\\s*\\("
    label: "Depends(...) dependency (auth gate when wired up)"
  - regex: "\\bSecurity\\s*\\("
    label: "Security(...) — auth dependency"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates FastAPI route handlers,
`APIRouter` factories, and `Depends`/`Security` dependency markers
so downstream walker/hunt/file agents see them as anchor points.

Gated on `tech: [fastapi]` — only runs when `fingerprint(root)`
detects FastAPI.

## What this finds

- Route decorators (`@app.get`, `@router.post`, `@api.put`, etc.,
  including `@app.websocket`)
- `APIRouter(...)` factory calls
- `Depends(...)` dependency injection (often the auth gate)
- `Security(...)` auth-scoped dependencies

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
