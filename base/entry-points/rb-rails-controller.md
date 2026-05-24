---
slug: rb-rails-controller
name: Rails Controller Entry Points
description: Locates Rails controllers, route registrations, and before_action callbacks via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [rails]
noiseTier: noisy
filePatterns:
  - "**/app/controllers/**/*.rb"
  - "**/config/routes.rb"
  - "**/app/jobs/**/*.rb"
  - "**/app/mailers/**/*.rb"
excludePatterns:
  - "**/test/**"
  - "**/spec/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^\\s*class\\s+\\w+Controller\\s*<\\s*\\w*Controller\\b"
    label: "Rails controller class"
  - regex: "^\\s*before_action\\s+"
    label: "before_action callback"
  - regex: "^\\s*skip_before_action\\s+"
    label: "skip_before_action (auth bypass — confirm intent)"
  - regex: "^\\s*resources\\s+:\\w+"
    label: "routes.rb resources :foo (CRUD)"
  - regex: "^\\s*(?:get|post|put|patch|delete|match)\\s+['\"][^'\"]+['\"]\\s*,"
    label: "routes.rb verb registration"
  - regex: "params\\.require\\s*\\("
    label: "strong params boundary"
references:
  - CWE-862
  - CWE-915
---

Regex-only rule (no LLM). Locates Rails controllers, routes, and
strong-params boundaries so downstream walker/hunt/file agents see
them as anchor points.

Gated on `tech: [rails]` — only runs when `fingerprint(root)`
detects Rails.

## What this finds

- Controller class declarations (`class FooController < ApplicationController`)
- `before_action` callbacks (auth pipeline)
- `skip_before_action` (potential auth bypass — confirm intent)
- `resources :foo` CRUD route registrations
- `routes.rb` verb registrations (`get`, `post`, `put`, `patch`,
  `delete`, `match`)
- `params.require(...)` strong-params boundaries

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
