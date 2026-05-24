---
slug: php-slim-route
name: Slim Route Entry Points
description: Locates Slim Framework route registrations, groups, and middleware attachments via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [slim]
noiseTier: noisy
filePatterns:
  - "**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\$app->(?:get|post|put|patch|delete|map|any)\\s*\\("
    label: "$app->method route registration"
  - regex: "\\$app->group\\s*\\("
    label: "$app->group(...) middleware scope"
  - regex: "->add\\s*\\(\\s*new\\s+\\w+Middleware"
    label: "->add(new ...Middleware) attach"
  - regex: "\\$request->(?:getQueryParams|getParsedBody|getAttribute)\\s*\\("
    label: "PSR-7 request accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Slim Framework route registrations,
route groups, middleware attachments, and PSR-7 request accessors.

Gated on `tech: [slim]` — only runs when `fingerprint(root)` detects
Slim.

## What this finds

- `$app->get/post/put/patch/delete/map/any(...)` registrations
- `$app->group(...)` route groups (middleware scope)
- `->add(new ...Middleware)` middleware attachments
- PSR-7 request accessors (`getQueryParams`, `getParsedBody`,
  `getAttribute`) — untrusted input

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
