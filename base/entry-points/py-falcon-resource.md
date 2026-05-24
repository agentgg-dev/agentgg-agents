---
slug: py-falcon-resource
name: Falcon Resource Entry Points
description: Locates Falcon resource classes with on_<method> handlers and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [falcon]
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
  - regex: "^\\s*def\\s+on_(get|post|put|patch|delete|head|options)\\s*\\(\\s*self\\b"
    label: "on_<method>(self, req, resp) handler"
  - regex: "\\bfalcon\\.App\\s*\\(|\\bfalcon\\.API\\s*\\("
    label: "falcon.App/API instance"
  - regex: "\\.add_route\\s*\\(\\s*['\"][^'\"]+['\"]"
    label: "app.add_route() registration"
  - regex: "\\breq\\.(?:params|media|context|get_param)\\b"
    label: "req.* accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Falcon resource classes with
`on_<method>` handlers, app instances, route registrations, and
request accessors.

Gated on `tech: [falcon]` — only runs when `fingerprint(root)`
detects Falcon.

## What this finds

- `def on_get/post/put/patch/delete/head/options(self, req, resp)`
- `falcon.App()` / `falcon.API()` instances
- `app.add_route('/path', resource)` registrations
- `req.params` / `media` / `context` / `get_param` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
