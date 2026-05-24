---
slug: php-codeigniter-controller
name: CodeIgniter Controller Entry Points
description: Locates CodeIgniter 4 controllers, $routes registrations, and request accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [codeigniter]
noiseTier: noisy
filePatterns:
  - "**/app/Controllers/**/*.php"
  - "**/Controllers/**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "class\\s+\\w+\\s+extends\\s+(?:BaseController|ResourceController|Controller)\\b"
    label: "CI Controller class"
  - regex: "\\$this->request->getVar\\s*\\(|\\$this->request->getPost\\s*\\("
    label: "request var accessor"
  - regex: "\\$routes->(?:get|post|put|patch|delete|add)\\s*\\("
    label: "$routes-> registration"
  - regex: "helper\\s*\\(\\s*['\"][^'\"]+['\"]\\s*\\)"
    label: "helper() — review for unsafe loaders"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates CodeIgniter 4 controllers, route
registrations, and request-data accessors.

Gated on `tech: [codeigniter]` — only runs when `fingerprint(root)`
detects CodeIgniter.

## What this finds

- Controller subclasses (`extends BaseController`, `ResourceController`,
  `Controller`)
- `$this->request->getVar(...)` / `getPost(...)` accessors
- `$routes->get/post/put/patch/delete/add(...)` registrations
- `helper(...)` calls (review for unsafe loaders)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
