---
slug: jvm-spring-controller
name: Spring Controller Entry Points
description: Locates Spring controllers, mapping annotations, and security config via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [spring]
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
  - regex: "@(?:Rest)?Controller\\b"
    label: "@Controller / @RestController"
  - regex: "@(?:Get|Post|Put|Patch|Delete|Request)Mapping\\b"
    label: "@<Verb>Mapping"
  - regex: "@PreAuthorize\\s*\\("
    label: "@PreAuthorize SpEL expression"
  - regex: "\\.permitAll\\s*\\(\\s*\\)"
    label: ".permitAll() — opens public access"
  - regex: "\\bantMatchers?\\s*\\("
    label: "antMatcher(...) auth scope"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Spring controllers, request
mappings, and Spring Security configuration so downstream
walker/hunt/file agents see them as anchor points.

Gated on `tech: [spring]` — only runs when `fingerprint(root)`
detects Spring.

## What this finds

- `@Controller` / `@RestController` class annotations
- Mapping annotations (`@GetMapping`, `@PostMapping`,
  `@RequestMapping`, etc.)
- `@PreAuthorize(...)` SpEL expressions (method-level auth gate)
- `.permitAll()` — opens public access (verify intent)
- `antMatcher(...)` / `antMatchers(...)` security-scope expressions

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
