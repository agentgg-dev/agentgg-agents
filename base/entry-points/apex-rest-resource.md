---
slug: apex-rest-resource
name: Salesforce Apex REST Resource Entry Points
description: Locates Salesforce Apex @RestResource classes, @HttpVerb methods, sharing modifiers, and AuraEnabled methods via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [apex]
noiseTier: noisy
filePatterns:
  - "**/*.cls"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "@RestResource\\s*\\(\\s*urlMapping\\s*=\\s*'[^']+'\\s*\\)"
    label: "@RestResource declaration"
  - regex: "@Http(?:Get|Post|Put|Patch|Delete|Head)\\b"
    label: "@HttpVerb method"
  - regex: "\\bwithout\\s+sharing\\b"
    label: "without sharing — bypasses record-level security (REVIEW)"
  - regex: "\\bwith\\s+sharing\\b"
    label: "with sharing — record security applied"
  - regex: "\\bAuraEnabled\\s*\\("
    label: "@AuraEnabled — exposed to Lightning"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Salesforce Apex `@RestResource`
classes, `@HttpVerb` methods, sharing modifiers, and `@AuraEnabled`
methods.

Gated on `tech: [apex]` — only runs when `fingerprint(root)` detects
Apex.

## What this finds

- `@RestResource(urlMapping='...')` class declarations
- `@HttpGet` / `@HttpPost` / `@HttpPut` / `@HttpPatch` /
  `@HttpDelete` / `@HttpHead` methods
- `without sharing` — bypasses record-level security (verify intent)
- `with sharing` — record security applied
- `@AuraEnabled(...)` — exposed to Lightning

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
