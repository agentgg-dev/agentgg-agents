---
slug: js-nestjs-controller
name: NestJS Controller Entry Points
description: Locates NestJS controllers, route decorators, and Guards/Public markers via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [nestjs]
noiseTier: normal
filePatterns:
  - "**/*.{ts,js}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "@Controller\\s*\\("
    label: "@Controller decorator"
  - regex: "@(?:Get|Post|Put|Patch|Delete|Options|Head|All)\\s*\\("
    label: "HTTP method decorator"
  - regex: "@UseGuards\\s*\\("
    label: "@UseGuards (auth gate)"
  - regex: "@Public\\s*\\(\\s*\\)"
    label: "@Public() decorator (skips global auth)"
  - regex: "@Body\\s*\\(\\s*\\)"
    label: "@Body() (request body sink)"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates NestJS controllers, route method
decorators, `@UseGuards`/`@Public` auth markers, and `@Body()` body
extractors.

Gated on `tech: [nestjs]` — only runs when `fingerprint(root)`
detects NestJS.

## What this finds

- `@Controller(...)` decorators
- `@Get` / `@Post` / `@Put` / `@Patch` / `@Delete` / `@Options` /
  `@Head` / `@All` method decorators
- `@UseGuards(...)` — auth gate
- `@Public()` — opts out of global auth (verify intent)
- `@Body()` — request body sink

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
