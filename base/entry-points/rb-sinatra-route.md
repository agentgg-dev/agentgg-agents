---
slug: rb-sinatra-route
name: Sinatra Route Entry Points
description: Locates Sinatra route blocks, before filters, and halt calls via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [sinatra]
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
  - regex: "^\\s*(?:get|post|put|patch|delete|options|head)\\s+['\"][^'\"]+['\"]\\s+do\\b"
    label: "Sinatra <verb> '/path' do ... end"
  - regex: "^\\s*before\\s+do\\b"
    label: "before do — auth filter"
  - regex: "^\\s*halt\\s+\\d+"
    label: "halt — auth response"
  - regex: "\\bparams\\["
    label: "params[:x] (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Sinatra route blocks, `before do`
filters, `halt` calls, and `params[]` accessors.

Gated on `tech: [sinatra]` — only runs when `fingerprint(root)`
detects Sinatra.

## What this finds

- `get`/`post`/`put`/`patch`/`delete`/`options`/`head '/path' do` blocks
- `before do` filters (auth pipeline)
- `halt N` short-circuit responses
- `params[:x]` accessors (untrusted input)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
