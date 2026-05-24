---
slug: dotnet-minimal-api
name: ASP.NET Core Minimal API Entry Points
description: Locates ASP.NET Core minimal-API endpoint mappings and auth chained methods via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [dotnet]
noiseTier: noisy
filePatterns:
  - "**/*.cs"
excludePatterns:
  - "**/Tests/**"
  - "**/UnitTests/**"
  - "**/IntegrationTests/**"
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/bin/**"
  - "**/obj/**"
preFilter:
  - regex: "\\bapp\\.Map(?:Get|Post|Put|Patch|Delete|Methods)\\s*\\("
    label: "app.Map<Verb> registration"
  - regex: "\\.RequireAuthorization\\s*\\("
    label: ".RequireAuthorization() — auth gate"
  - regex: "\\.AllowAnonymous\\s*\\(\\s*\\)"
    label: ".AllowAnonymous() — public route"
  - regex: "\\bWebApplication\\.CreateBuilder\\s*\\("
    label: "WebApplication.CreateBuilder() init"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates ASP.NET Core minimal-API endpoint
mappings, auth chains, and WebApplication initialization.

Gated on `tech: [dotnet]` — only runs when `fingerprint(root)`
detects a .NET project.

## What this finds

- `app.MapGet/MapPost/MapPut/MapPatch/MapDelete/MapMethods(...)`
- `.RequireAuthorization(...)` chained auth gate
- `.AllowAnonymous()` — opens public access (verify intent)
- `WebApplication.CreateBuilder(...)` initializer

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
