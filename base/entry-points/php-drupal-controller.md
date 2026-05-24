---
slug: php-drupal-controller
name: Drupal Controller Entry Points
description: Locates Drupal controllers, routing permissions, and form callbacks via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [drupal]
noiseTier: noisy
filePatterns:
  - "**/src/Controller/**/*.php"
  - "**/modules/**/*.php"
  - "**/modules/**/*.routing.yml"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/core/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "class\\s+\\w+\\s+extends\\s+ControllerBase\\b"
    label: "Drupal ControllerBase subclass"
  - regex: "_permission\\s*:\\s*['\"]access\\s+content['\"]"
    label: "permission: access content (public-ish route)"
  - regex: "buildForm\\s*\\(\\s*array\\s+\\$form"
    label: "FormBase::buildForm() entry"
  - regex: "\\\\Drupal::request\\s*\\(\\s*\\)"
    label: "request() service accessor"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Drupal controllers, routing
permission declarations, and form callbacks.

Gated on `tech: [drupal]` — only runs when `fingerprint(root)`
detects Drupal.

## What this finds

- Controller subclasses (`extends ControllerBase`)
- `_permission: 'access content'` route declarations (public-ish)
- `FormBase::buildForm(array $form, ...)` entry methods
- `\Drupal::request()` service accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
