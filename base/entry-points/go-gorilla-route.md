---
slug: go-gorilla-route
name: Gorilla Mux Route Entry Points
description: Locates Gorilla mux router registrations, method bindings, and Vars accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [gorilla]
noiseTier: noisy
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
  - regex: "\\bmux\\.NewRouter\\s*\\(\\s*\\)"
    label: "mux.NewRouter() init"
  - regex: "\\.HandleFunc\\s*\\(\\s*\"[^\"]+\"\\s*,"
    label: "router.HandleFunc('/path', handler)"
  - regex: "\\.Methods\\s*\\(\\s*\"(?:GET|POST|PUT|PATCH|DELETE)\""
    label: ".Methods('VERB')"
  - regex: "\\.PathPrefix\\s*\\("
    label: ".PathPrefix() subroute scope"
  - regex: "\\bmux\\.Vars\\s*\\(\\s*r\\s*\\)"
    label: "mux.Vars(r) (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Gorilla mux router registrations,
method bindings, subroute scopes, and Vars accessors.

Gated on `tech: [gorilla]` — only runs when `fingerprint(root)`
detects Gorilla.

## What this finds

- `mux.NewRouter()` initializer
- `.HandleFunc("/path", handler)` registrations
- `.Methods("GET"|"POST"|...)` chained verb bindings
- `.PathPrefix(...).Subrouter()` subroute scopes
- `mux.Vars(r)` accessors (untrusted input)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
