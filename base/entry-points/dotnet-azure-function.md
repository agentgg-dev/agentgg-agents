---
slug: dotnet-azure-function
name: Azure Functions C# Entry Points
description: Locates Azure Functions C# attributes (FunctionName, HttpTrigger, queue triggers) and authorization levels via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [azure-functions, dotnet]
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
  - regex: "\\[\\s*FunctionName\\s*\\(\\s*\"[^\"]+\"\\s*\\)\\s*\\]"
    label: "[FunctionName(...)] attribute"
  - regex: "\\[\\s*Function\\s*\\(\\s*\"[^\"]+\"\\s*\\)\\s*\\]"
    label: "[Function(...)] attribute"
  - regex: "\\[\\s*HttpTrigger\\s*\\(\\s*AuthorizationLevel\\.(Anonymous|Function|Admin)\\b"
    label: "[HttpTrigger(AuthorizationLevel.X)] — verify Anonymous is intentional"
  - regex: "\\[\\s*ServiceBusTrigger\\b|\\[\\s*QueueTrigger\\b"
    label: "queue trigger entry"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Azure Functions C# entry points:
`FunctionName`/`Function` attributes, `HttpTrigger` authorization
levels, and queue-trigger entries.

Gated on `tech: [azure-functions, dotnet]` — only runs when
`fingerprint(root)` detects Azure Functions in a .NET project.

## What this finds

- `[FunctionName("Name")]` attributes (classic model)
- `[Function("Name")]` attributes (isolated worker)
- `[HttpTrigger(AuthorizationLevel.Anonymous|Function|Admin, ...)]`
  — verify `Anonymous` is intentional
- `[ServiceBusTrigger]` / `[QueueTrigger]` queue-trigger entries

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
