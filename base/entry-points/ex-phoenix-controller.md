---
slug: ex-phoenix-controller
name: Phoenix Controller Entry Points
description: Locates Phoenix controllers, LiveView modules, router pipelines, and Repo.query surfaces via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [phoenix]
noiseTier: noisy
filePatterns:
  - "**/*.ex"
  - "**/*.exs"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/_build/**"
  - "**/deps/**"
preFilter:
  - regex: "^\\s*use\\s+\\w+,\\s+:controller\\b"
    label: "use ..., :controller — Phoenix controller"
  - regex: "^\\s*use\\s+\\w+,\\s+:live_view\\b"
    label: "use ..., :live_view"
  - regex: "^\\s*(?:get|post|put|patch|delete|live)\\s+\"[^\"]+\"\\s*,"
    label: "router pipeline verb"
  - regex: "^\\s*pipeline\\s+:\\w+\\s+do\\b"
    label: "pipeline :name do — auth scope"
  - regex: "\\bplug\\s+:\\w+"
    label: "plug :name (auth/middleware wiring)"
  - regex: "\\bRepo\\.query!?\\s*\\("
    label: "Repo.query — raw SQL surface"
references:
  - CWE-862
  - CWE-89
---

Regex-only rule (no LLM). Locates Phoenix controllers, LiveView
modules, router declarations, pipelines, plug wiring, and raw-SQL
surfaces.

Gated on `tech: [phoenix]` — only runs when `fingerprint(root)`
detects Phoenix.

## What this finds

- `use MyAppWeb, :controller` — controller declarations
- `use MyAppWeb, :live_view` — LiveView modules
- `get/post/put/patch/delete/live "/path", ...` router declarations
- `pipeline :name do` — auth scope
- `plug :name` middleware wiring
- `Repo.query` / `Repo.query!` raw SQL

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
