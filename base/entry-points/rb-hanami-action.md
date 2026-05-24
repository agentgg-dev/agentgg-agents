---
slug: rb-hanami-action
name: Hanami Action Entry Points
description: Locates Hanami action subclasses and handle(request, response) entries via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [hanami]
noiseTier: noisy
filePatterns:
  - "**/app/actions/**/*.rb"
  - "**/actions/**/*.rb"
excludePatterns:
  - "**/test/**"
  - "**/spec/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^class\\s+\\w+\\s*<\\s*(?:Hanami::Action|App::Action)\\b"
    label: "Hanami action subclass"
  - regex: "^\\s*def\\s+handle\\s*\\(\\s*request\\s*,\\s*response\\s*\\)"
    label: "handle(request, response) entry"
  - regex: "^\\s*include\\s+Deps\\[\\s*['\"][^'\"]+['\"]\\s*\\]"
    label: "Deps[] DI accessor"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Hanami action subclasses, request
handlers, and `Deps[]` DI accessors.

Gated on `tech: [hanami]` — only runs when `fingerprint(root)`
detects Hanami.

## What this finds

- Action subclasses (`class Foo < Hanami::Action` or `< App::Action`)
- `def handle(request, response)` entry methods
- `include Deps["..."]` DI accessor declarations

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
