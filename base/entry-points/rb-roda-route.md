---
slug: rb-roda-route
name: Roda Route Entry Points
description: Locates Roda app classes, route tree nodes, and plugin declarations via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [roda]
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
  - regex: "^class\\s+\\w+\\s*<\\s*Roda\\b"
    label: "class < Roda app"
  - regex: "\\br\\.(?:get|post|put|patch|delete|on|is|root)\\b"
    label: "r.<verb>/r.on/r.is route node"
  - regex: "\\bplugin\\s+:[\\w_]+"
    label: "Roda plugin (auth/security/render)"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Roda app classes, route tree
nodes, and plugin declarations.

Gated on `tech: [roda]` — only runs when `fingerprint(root)`
detects Roda.

## What this finds

- App classes (`class App < Roda`)
- Route tree nodes (`r.get`, `r.post`, `r.put`, `r.patch`,
  `r.delete`, `r.on`, `r.is`, `r.root`)
- `plugin :name` declarations (auth/security/render)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
