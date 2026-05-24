---
slug: js-graphql-resolver
name: GraphQL Resolver Entry Points
description: Locates GraphQL resolvers (Apollo, Yoga, Mercurius), type-graphql/Nest decorators, and context accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [graphql]
noiseTier: noisy
filePatterns:
  - "**/*.{ts,js,mjs,cjs}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bresolvers?\\s*[:=]\\s*\\{\\s*Query\\s*:"
    label: "resolvers Query map"
  - regex: "\\bMutation\\s*:\\s*\\{"
    label: "Mutation resolver map"
  - regex: "\\bSubscription\\s*:\\s*\\{"
    label: "Subscription resolver"
  - regex: "@(?:Query|Mutation|Resolver)\\s*\\("
    label: "type-graphql / Nest GraphQL decorator"
  - regex: "\\bcontext\\.\\w+"
    label: "context.* (auth identity carrier — confirm wiring)"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates GraphQL resolvers (Apollo, Yoga,
Mercurius), type-graphql / Nest GraphQL decorators, and `context.*`
accessors.

Gated on `tech: [graphql]` — only runs when `fingerprint(root)`
detects GraphQL.

## What this finds

- `resolvers: { Query: {...} }` maps
- `Mutation: { ... }` resolver maps
- `Subscription: { ... }` resolver maps
- `@Query` / `@Mutation` / `@Resolver` decorators
- `context.*` accessors (auth identity carrier)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
