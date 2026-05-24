---
slug: erl-cowboy-handler
name: Erlang Cowboy Handler Entry Points
description: Locates Erlang Cowboy init/2 entries, cowboy_router:compile, and cowboy_req accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [erlang]
noiseTier: noisy
filePatterns:
  - "**/*.erl"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/_build/**"
preFilter:
  - regex: "\\binit\\s*\\(\\s*Req\\s*,\\s*State\\s*\\)\\s*->"
    label: "init(Req, State) — cowboy handler entry"
  - regex: "\\bcowboy_router:compile\\b"
    label: "cowboy_router:compile([...])"
  - regex: "\\bcowboy_req:(?:binding|qs|read_body|header)\\b"
    label: "cowboy_req accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Erlang Cowboy `init/2` handler
entries, router compile sites, and `cowboy_req` accessors.

Gated on `tech: [erlang]` — only runs when `fingerprint(root)`
detects Erlang.

## What this finds

- `init(Req, State) -> ...` cowboy handler entry
- `cowboy_router:compile([...])` route table
- `cowboy_req:binding` / `qs` / `read_body` / `header` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
