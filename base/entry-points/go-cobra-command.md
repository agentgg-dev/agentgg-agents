---
slug: go-cobra-command
name: Cobra CLI Command Entry Points
description: Locates Cobra CLI command declarations and Run handlers — privileged-CLI surface — via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [cobra]
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
  - regex: "&cobra\\.Command\\s*\\{"
    label: "cobra.Command{} declaration"
  - regex: "\\b(?:Run|RunE|PreRun|PostRun)\\s*:\\s*func\\b"
    label: "Run/RunE handler — privileged action body"
  - regex: "\\.PersistentFlags\\s*\\(\\s*\\)\\.(?:String|Bool|Int)Var"
    label: "PersistentFlags()"
  - regex: "\\.AddCommand\\s*\\("
    label: "AddCommand registration"
references:
  - CWE-78
  - CWE-77
---

Regex-only rule (no LLM). Locates Cobra CLI command declarations,
`Run`/`RunE` handler bodies, persistent flag declarations, and
subcommand registrations — privileged-CLI surface.

Gated on `tech: [cobra]` — only runs when `fingerprint(root)`
detects Cobra.

## What this finds

- `&cobra.Command{...}` declarations
- `Run`/`RunE`/`PreRun`/`PostRun` handler bodies
- `.PersistentFlags().StringVar/BoolVar/IntVar(...)` flag declarations
- `.AddCommand(...)` subcommand registrations

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
