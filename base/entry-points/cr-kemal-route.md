---
slug: cr-kemal-route
name: Kemal Route Entry Points
description: Locates Crystal Kemal route handlers, before_* filters, and env.params accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [kemal]
noiseTier: noisy
filePatterns:
  - "**/*.cr"
excludePatterns:
  - "**/spec/**"
  - "**/test/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^\\s*(?:get|post|put|patch|delete|options|ws)\\s+\"[^\"]+\"\\s+do\\b"
    label: "Kemal <verb> '/path' do"
  - regex: "^\\s*before_(?:all|get|post|put|delete)\\s+do\\b"
    label: "before_* do — auth filter"
  - regex: "\\benv\\.params\\.(?:url|query|json|body|files)\\b"
    label: "env.params accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Crystal Kemal route handlers,
`before_*` filters, and `env.params.*` accessors.

Gated on `tech: [kemal]` — only runs when `fingerprint(root)`
detects Kemal.

## What this finds

- `get/post/put/patch/delete/options/ws "/path" do` route handlers
- `before_all/get/post/put/delete do` filters (auth pipeline)
- `env.params.url` / `query` / `json` / `body` / `files` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
