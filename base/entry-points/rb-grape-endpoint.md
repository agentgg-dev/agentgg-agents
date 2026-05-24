---
slug: rb-grape-endpoint
name: Grape Endpoint Entry Points
description: Locates Grape API endpoints, resource blocks, and before filters via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [grape]
noiseTier: noisy
filePatterns:
  - "**/*.rb"
excludePatterns:
  - "**/test/**"
  - "**/spec/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^\\s*(?:get|post|put|patch|delete)\\s+:\\w+"
    label: "Grape <verb> :name do"
  - regex: "^\\s*resource\\s+:\\w+"
    label: "resource :name do block"
  - regex: "^\\s*before\\s+do\\b"
    label: "before do — auth filter"
  - regex: "\\bdeclared\\s*\\(\\s*params\\s*\\)"
    label: "declared(params) — strong-params equivalent"
references:
  - CWE-862
  - CWE-915
---

Regex-only rule (no LLM). Locates Grape endpoints, resource blocks,
before filters, and `declared(params)` parameter accessors.

Gated on `tech: [grape]` — only runs when `fingerprint(root)`
detects Grape.

## What this finds

- `get/post/put/patch/delete :name do` endpoint declarations
- `resource :name do` resource blocks
- `before do` filters (auth pipeline)
- `declared(params)` — strong-params equivalent

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
