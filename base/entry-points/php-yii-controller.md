---
slug: php-yii-controller
name: Yii Controller Entry Points
description: Locates Yii2 controllers, actionXxx methods, and behaviors() filters via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [yii]
noiseTier: noisy
filePatterns:
  - "**/controllers/**/*.php"
  - "**/src/controllers/**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "class\\s+\\w+Controller\\s+extends\\s+(?:Controller|ActiveController|RestController)\\b"
    label: "Yii Controller class"
  - regex: "public\\s+function\\s+action[A-Z]\\w*\\s*\\("
    label: "actionXxx() — Yii public action"
  - regex: "\\bbehaviors\\s*\\(\\s*\\)\\s*[:{]"
    label: "behaviors() — verify auth filter"
  - regex: "AccessControl::class|ContentNegotiator::class"
    label: "auth/behavior class wired up"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Yii2 controllers, public action
methods, and `behaviors()` filter declarations.

Gated on `tech: [yii]` — only runs when `fingerprint(root)` detects
Yii.

## What this finds

- Controller subclasses (`extends Controller`, `ActiveController`,
  `RestController`)
- `actionXxx()` public action methods
- `behaviors()` declarations (verify auth filter scope)
- `AccessControl::class` / `ContentNegotiator::class` references

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
