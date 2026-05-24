---
slug: jvm-micronaut-controller
name: Micronaut Controller Entry Points
description: Locates Micronaut controllers, method annotations, and auth attributes via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [micronaut]
noiseTier: noisy
filePatterns:
  - "**/*.java"
  - "**/*.kt"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/src/test/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/target/**"
preFilter:
  - regex: "@Controller\\s*\\("
    label: "@Controller(...) declaration"
  - regex: "@(?:Get|Post|Put|Patch|Delete|Head|Options)\\s*\\("
    label: "Micronaut HTTP method annotation"
  - regex: "@Secured\\s*\\("
    label: "@Secured(...) auth annotation"
  - regex: "@PermitAll\\b"
    label: "@PermitAll — public access"
  - regex: "\\bAuthentication\\s+\\w+"
    label: "Authentication arg in handler"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Micronaut controllers, route
methods, and auth annotations.

Gated on `tech: [micronaut]` — only runs when `fingerprint(root)`
detects Micronaut.

## What this finds

- `@Controller(...)` class declarations
- `@Get` / `@Post` / `@Put` / `@Patch` / `@Delete` / `@Head` /
  `@Options` method annotations
- `@Secured(...)` auth annotations
- `@PermitAll` — opens public access (verify intent)
- `Authentication` parameter in handler signatures

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
