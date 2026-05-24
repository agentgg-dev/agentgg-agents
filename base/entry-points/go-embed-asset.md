---
slug: go-embed-asset
name: Go //go:embed Asset Directives
description: Locates Go //go:embed directives that bundle external assets into the binary — supply-chain surface — via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [go]
noiseTier: precise
filePatterns:
  - "**/*.go"
excludePatterns:
  - "**/*_test.go"
  - "**/test/**"
  - "**/tests/**"
  - "**/gen/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^\\s*//go:embed\\s+"
    label: "//go:embed directive (asset bundled into binary)"
references:
  - CWE-1357
---

Regex-only rule (no LLM). Locates Go `//go:embed` directives that
bundle external assets (kernels, rootfs payloads, templates,
configs) into the binary at build time — supply-chain surface where
an attacker who can swap the asset gets bytes shipping to production.

Gated on `tech: [go]` — only runs when `fingerprint(root)` detects
Go.

## What this finds

- `//go:embed <path>` directives at the start of a line

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether the embedded asset is
checked into the repo, whether the path glob is too wide, and
whether the embed pulls runtime-mutable data or secrets.
