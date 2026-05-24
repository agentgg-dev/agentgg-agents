---
slug: rs-warp-filter
name: Warp Filter Entry Points
description: Locates Warp filter compositions and route declarations via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [warp]
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
  - regex: "\\bwarp::path!\\s*\\("
    label: "warp::path!() filter"
  - regex: "\\bwarp::(?:get|post|put|patch|delete)\\s*\\(\\s*\\)"
    label: "warp::<verb>()"
  - regex: "\\.and_then\\s*\\("
    label: ".and_then(handler)"
  - regex: "\\bwarp::filters::body::json\\s*\\("
    label: "json body extractor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Warp filter compositions, verb
filters, handler bindings, and body extractors.

Gated on `tech: [warp]` — only runs when `fingerprint(root)` detects
Warp.

## What this finds

- `warp::path!(...)` filters
- `warp::get/post/put/patch/delete()` verb filters
- `.and_then(handler)` handler bindings
- `warp::filters::body::json()` body extractor

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
