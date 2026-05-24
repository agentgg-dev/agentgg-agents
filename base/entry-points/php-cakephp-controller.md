---
slug: php-cakephp-controller
name: CakePHP Controller Entry Points
description: Locates CakePHP controllers and Auth component callbacks via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [cakephp]
noiseTier: noisy
filePatterns:
  - "**/src/Controller/**/*.php"
  - "**/Controller/**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "class\\s+\\w+Controller\\s+extends\\s+AppController\\b"
    label: "CakePHP controller class"
  - regex: "\\$this->Auth->allow\\s*\\("
    label: "Auth->allow() — opens public access"
  - regex: "\\$this->loadComponent\\s*\\(\\s*['\"]Auth['\"]"
    label: "Auth component wiring"
  - regex: "\\$this->request->getData\\s*\\("
    label: "request data accessor"
  - regex: "\\$this->Flash->"
    label: "flash response (post-redirect-get)"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates CakePHP controllers, Auth-component
wiring, and request-data accessors.

Gated on `tech: [cakephp]` — only runs when `fingerprint(root)`
detects CakePHP.

## What this finds

- Controller subclasses (`extends AppController`)
- `$this->Auth->allow(...)` — opens public access (verify intent)
- `$this->loadComponent('Auth', ...)` wiring
- `$this->request->getData(...)` request-data accessors
- `$this->Flash->*` flash-response calls

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
