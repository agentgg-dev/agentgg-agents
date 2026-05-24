---
slug: rs-axum-route
name: Axum Route Entry Points
description: Locates Axum router declarations, route compositions, and extractors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [axum]
noiseTier: noisy
filePatterns:
  - "**/*.rs"
excludePatterns:
  - "**/tests/**"
  - "**/examples/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/target/**"
preFilter:
  - regex: "\\bRouter::new\\s*\\(\\s*\\)"
    label: "Router::new() factory"
  - regex: "\\.route\\s*\\(\\s*\"[^\"]+\"\\s*,\\s*(?:get|post|put|patch|delete|any|on)\\s*\\("
    label: ".route('/path', get(handler))"
  - regex: "\\.nest\\s*\\(\\s*\"[^\"]+\""
    label: ".nest() subroute"
  - regex: "\\.merge\\s*\\("
    label: ".merge() router composition"
  - regex: "\\bExtension<[^>]+>|\\bState<[^>]+>"
    label: "Extension/State extractor (auth identity)"
  - regex: "Path<[^>]+>|Query<[^>]+>|Json<[^>]+>"
    label: "request extractor (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Axum router declarations, route
compositions, and request/state extractors.

Gated on `tech: [axum]` — only runs when `fingerprint(root)`
detects Axum.

## What this finds

- `Router::new()` factory
- `.route("/path", get(handler))` registrations
- `.nest("/sub", router)` subroutes
- `.merge(router)` router compositions
- `Extension<T>` / `State<T>` extractors (auth identity)
- `Path<T>` / `Query<T>` / `Json<T>` request extractors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
