---
slug: rs-actix-route
name: Actix-web Route Entry Points
description: Locates Actix-web route attributes, service registrations, and extractors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [actix]
noiseTier: noisy
filePatterns:
  - "**/*.rs"
excludePatterns:
  - "**/tests/**"
  - "**/examples/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/target/**"
preFilter:
  - regex: "#\\[\\s*(?:get|post|put|patch|delete|head|options)\\s*\\(\\s*\"[^\"]+\"\\s*\\)"
    label: "Actix route attribute"
  - regex: "App::new\\s*\\(\\s*\\)"
    label: "App::new() factory"
  - regex: "\\.service\\s*\\("
    label: ".service(...) registration"
  - regex: "\\bweb::scope\\s*\\("
    label: "web::scope() group"
  - regex: "web::(?:Path|Query|Json|Form|Data)<[^>]+>"
    label: "extractor (untrusted input)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Actix-web route attributes, app
factories, service registrations, scope groups, and extractors.

Gated on `tech: [actix]` — only runs when `fingerprint(root)`
detects Actix.

## What this finds

- Route attributes (`#[get("/...")]`, `#[post("/...")]`, etc.)
- `App::new()` factory
- `.service(...)` registrations
- `web::scope(...)` route groups
- `web::Path` / `Query` / `Json` / `Form` / `Data` extractors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
