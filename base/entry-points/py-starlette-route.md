---
slug: py-starlette-route
name: Starlette Route Entry Points
description: Locates Starlette Route/Mount/WebSocketRoute declarations via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [starlette]
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
  - regex: "\\bRoute\\s*\\(\\s*['\"][^'\"]+['\"]\\s*,"
    label: "Route('/path', endpoint)"
  - regex: "\\bMount\\s*\\(\\s*['\"][^'\"]+['\"]\\s*,"
    label: "Mount('/sub', app)"
  - regex: "\\bWebSocketRoute\\s*\\("
    label: "WebSocketRoute declaration"
  - regex: "\\bAuthenticationMiddleware\\b"
    label: "AuthenticationMiddleware wiring"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Starlette route declarations,
sub-app mounts, websocket routes, and authentication middleware
wiring.

Gated on `tech: [starlette]` — only runs when `fingerprint(root)`
detects Starlette.

## What this finds

- `Route('/path', endpoint=...)` declarations
- `Mount('/sub', app=...)` sub-app mounts
- `WebSocketRoute(...)` websocket endpoints
- `AuthenticationMiddleware` wiring

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
