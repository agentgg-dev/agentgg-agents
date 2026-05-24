---
slug: php-symfony-controller
name: Symfony Controller Entry Points
description: Locates Symfony controllers, #[Route] attributes, and auth markers via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [symfony]
noiseTier: noisy
filePatterns:
  - "**/src/**/*.php"
  - "**/src/Controller/**/*.php"
  - "**/Controller/**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "#\\[\\s*Route\\s*\\("
    label: "#[Route] attribute"
  - regex: "class\\s+\\w+Controller\\s+extends\\s+AbstractController\\b"
    label: "Symfony controller class"
  - regex: "#\\[\\s*IsGranted\\s*\\("
    label: "#[IsGranted] auth gate"
  - regex: "#\\[\\s*AsEventListener\\s*\\("
    label: "Event listener entry point"
  - regex: "#\\[\\s*AsMessageHandler\\s*\\("
    label: "Messenger handler entry point"
  - regex: "\\$this->getUser\\s*\\(\\s*\\)"
    label: "auth identity accessor"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Symfony controllers, `#[Route]`
attributes, and `#[IsGranted]` / `getUser()` auth markers.

Gated on `tech: [symfony]` — only runs when `fingerprint(root)`
detects Symfony.

## What this finds

- `#[Route(...)]` attribute declarations
- Controller subclasses (`extends AbstractController`)
- `#[IsGranted(...)]` auth gates
- `#[AsEventListener(...)]` event-handler entry points
- `#[AsMessageHandler(...)]` Messenger handlers
- `$this->getUser()` auth-identity accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents (`missing-auth-php`, etc.) decide whether
they represent a real vulnerability.
