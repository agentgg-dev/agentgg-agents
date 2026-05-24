---
slug: dotnet-razor-pages
name: Razor Pages Entry Points
description: Locates Razor Pages PageModel handlers and request-binding attributes via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [dotnet]
noiseTier: noisy
filePatterns:
  - "**/Pages/**/*.cshtml.cs"
  - "**/*.cshtml.cs"
excludePatterns:
  - "**/Tests/**"
  - "**/UnitTests/**"
  - "**/IntegrationTests/**"
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/bin/**"
  - "**/obj/**"
preFilter:
  - regex: "\\bclass\\s+\\w+\\s*:\\s*PageModel\\b"
    label: "PageModel subclass"
  - regex: "\\bpublic\\s+(?:async\\s+)?(?:Task<?[^>]*>?\\s+)?On(?:Get|Post|Put|Delete)(?:Async)?\\s*\\("
    label: "OnGet/OnPost handler"
  - regex: "\\[\\s*BindProperty\\b"
    label: "[BindProperty] (request-bound input)"
  - regex: "\\[\\s*ValidateAntiForgeryToken\\s*\\]"
    label: "[ValidateAntiForgeryToken] CSRF guard"
references:
  - CWE-862
  - CWE-352
---

Regex-only rule (no LLM). Locates Razor Pages PageModel subclasses,
handler methods, and request-binding attributes.

Gated on `tech: [dotnet]` — only runs when `fingerprint(root)`
detects a .NET project.

## What this finds

- `class Foo : PageModel` subclasses
- `OnGet` / `OnPost` / `OnPut` / `OnDelete` (and `*Async`) handlers
- `[BindProperty]` request-bound input attributes
- `[ValidateAntiForgeryToken]` CSRF guards

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
