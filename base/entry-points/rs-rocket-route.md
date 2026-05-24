---
slug: rs-rocket-route
name: Rocket Route Entry Points
description: Locates Rocket route attributes, routes! macro, and mount calls via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [rocket]
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
    label: "Rocket route attribute"
  - regex: "\\brocket::routes!\\s*\\["
    label: "routes![...] macro"
  - regex: "\\.mount\\s*\\(\\s*\"[^\"]+\""
    label: ".mount() registration"
  - regex: "Json<[^>]+>|Form<[^>]+>|Query<[^>]+>"
    label: "guard / extractor (untrusted)"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Rocket route attributes,
`routes![...]` declarations, `.mount(...)` registrations, and
guards/extractors.

Gated on `tech: [rocket]` — only runs when `fingerprint(root)`
detects Rocket.

## What this finds

- Route attributes (`#[get("/...")]`, `#[post("/...")]`, etc.)
- `rocket::routes![...]` macro
- `.mount("/api", routes![...])` registrations
- `Json<T>` / `Form<T>` / `Query<T>` guards and extractors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
