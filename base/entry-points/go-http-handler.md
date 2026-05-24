---
slug: go-http-handler
name: Go net/http Handler Entry Points
description: Locates Go net/http handler registrations and handler function signatures via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [go]
noiseTier: normal
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
  - regex: "http\\.HandleFunc\\s*\\("
    label: "http.HandleFunc registration"
  - regex: "http\\.Handle\\s*\\("
    label: "http.Handle registration"
  - regex: "mux\\.Handle(Func)?\\s*\\("
    label: "mux handler registration"
  - regex: "\\.GET\\s*\\(|\\.POST\\s*\\(|\\.PUT\\s*\\(|\\.DELETE\\s*\\("
    label: "HTTP method handler"
  - regex: "func\\s+\\w+\\s*\\(\\s*w\\s+http\\.ResponseWriter.*r\\s+\\*http\\.Request"
    label: "HTTP handler function signature"
  - regex: "ServeHTTP\\s*\\("
    label: "ServeHTTP implementation"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Go net/http handler registrations,
function signatures, and `ServeHTTP` implementations. Generic Go
entry-point sweep — fires on any Go project (not framework-gated).

Gated on `tech: [go]` — only runs when `fingerprint(root)` detects
Go.

## What this finds

- `http.HandleFunc(...)` and `http.Handle(...)` registrations
- `mux.Handle(...)` / `mux.HandleFunc(...)` registrations
- Generic verb methods (`.GET`, `.POST`, `.PUT`, `.DELETE`)
- HTTP handler function signatures
  (`func name(w http.ResponseWriter, r *http.Request)`)
- `ServeHTTP(...)` implementations

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
