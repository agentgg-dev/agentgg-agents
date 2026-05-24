---
slug: py-tornado-handler
name: Tornado Handler Entry Points
description: Locates Tornado RequestHandler subclasses, method handlers, and Application routing via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [tornado]
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
  - regex: "^class\\s+\\w+\\s*\\(\\s*(?:tornado\\.web\\.)?RequestHandler\\s*\\)"
    label: "RequestHandler subclass"
  - regex: "^\\s*def\\s+(get|post|put|patch|delete|head|options)\\s*\\(\\s*self\\b"
    label: "method handler"
  - regex: "Application\\s*\\(\\s*\\["
    label: "Application([(...handler...)])"
  - regex: "@tornado\\.web\\.authenticated\\b"
    label: "@authenticated decorator"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Tornado handler classes, method
handlers, application routing, and `@authenticated` markers.

Gated on `tech: [tornado]` — only runs when `fingerprint(root)`
detects Tornado.

## What this finds

- `class FooHandler(RequestHandler)` / `(tornado.web.RequestHandler)`
- `def get/post/put/patch/delete/head/options(self, ...)` method handlers
- `Application([(r"/path", Handler), ...])` route table
- `@tornado.web.authenticated` decorators

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
