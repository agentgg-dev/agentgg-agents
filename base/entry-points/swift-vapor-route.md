---
slug: swift-vapor-route
name: Swift Vapor Route Entry Points
description: Locates Swift Vapor route registrations, middleware groups, RouteCollection conformance, and req accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [vapor]
noiseTier: noisy
filePatterns:
  - "**/*.swift"
excludePatterns:
  - "**/Tests/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/.build/**"
preFilter:
  - regex: "\\bapp\\.(?:get|post|put|patch|delete|on)\\s*\\("
    label: "app.<verb>('/path') registration"
  - regex: "\\bgrouped\\s*\\(\\s*\\w+\\.[A-Za-z]+\\(\\)\\s*\\)"
    label: ".grouped(Middleware()) auth scope"
  - regex: "\\breq\\.(?:parameters|query|content|auth|headers)\\b"
    label: "req.* accessor"
  - regex: "\\bclass\\s+\\w+Controller\\s*:\\s*RouteCollection\\b"
    label: "RouteCollection conformance"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Swift Vapor route registrations,
middleware groups, request accessors, and `RouteCollection`
conformance.

Gated on `tech: [vapor]` — only runs when `fingerprint(root)`
detects Vapor.

## What this finds

- `app.get/post/put/patch/delete/on(...)` route registrations
- `.grouped(Middleware())` auth-scope middleware groups
- `req.parameters` / `query` / `content` / `auth` / `headers`
- `class FooController: RouteCollection` conformance

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
