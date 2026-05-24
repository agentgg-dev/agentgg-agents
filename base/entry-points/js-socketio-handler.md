---
slug: js-socketio-handler
name: Socket.IO Handler Entry Points
description: Locates Socket.IO connection/event handlers, middleware, and handshake accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [socketio]
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
  - regex: "\\bio\\.on\\s*\\(\\s*['\"]connection['\"]"
    label: "io.on('connection', ...) — connection entry"
  - regex: "\\bsocket\\.on\\s*\\(\\s*['\"][^'\"]+['\"]"
    label: "socket.on('event', handler)"
  - regex: "\\bio\\.use\\s*\\("
    label: "io.use(authMiddleware) — auth gate"
  - regex: "\\bsocket\\.handshake\\.(?:auth|headers|query)\\b"
    label: "handshake.auth/headers/query (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Socket.IO connection and event
handlers, `io.use` auth middleware, and `socket.handshake.*`
accessors.

Gated on `tech: [socketio]` — only runs when `fingerprint(root)`
detects Socket.IO.

## What this finds

- `io.on('connection', ...)` connection entry
- `socket.on('event', handler)` event handlers
- `io.use(...)` auth middleware
- `socket.handshake.auth` / `headers` / `query` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
