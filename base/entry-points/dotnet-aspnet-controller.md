---
slug: dotnet-aspnet-controller
name: ASP.NET Core Controller Entry Points
description: Locates ASP.NET Core controllers, route attributes, and authorization attributes via regex — no LLM cost.
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
  - regex: "\\bclass\\s+\\w+\\s*:\\s*(?:Controller|ControllerBase)\\b"
    label: "ControllerBase / Controller subclass"
  - regex: "\\[\\s*ApiController\\s*\\]"
    label: "[ApiController] attribute"
  - regex: "\\[\\s*Route\\s*\\("
    label: "[Route] attribute"
  - regex: "\\[\\s*Http(?:Get|Post|Put|Patch|Delete|Head|Options)\\s*\\(?"
    label: "[HttpMethod] attribute"
  - regex: "\\[\\s*AllowAnonymous\\s*\\]"
    label: "[AllowAnonymous] — opens public access"
  - regex: "\\[\\s*Authorize(?:\\s*\\([^)]*\\))?\\s*\\]"
    label: "[Authorize] auth gate"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates ASP.NET Core controllers, route
and HTTP-method attributes, and `[AllowAnonymous]` / `[Authorize]`
auth markers so downstream walker/hunt/file agents see them as
anchor points.

Gated on `tech: [dotnet]` — only runs when `fingerprint(root)`
detects a .NET project.

## What this finds

- Controller subclasses (`class Foo : Controller`, `class Bar : ControllerBase`)
- `[ApiController]` attribute
- `[Route(...)]` attribute
- `[HttpGet]` / `[HttpPost]` / `[HttpPut]` / `[HttpPatch]` /
  `[HttpDelete]` / `[HttpHead]` / `[HttpOptions]`
- `[AllowAnonymous]` — opens public access (verify intent)
- `[Authorize]` (with optional roles/policy arguments) auth gates

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
