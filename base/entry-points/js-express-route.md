---
slug: js-express-route
name: Express Route Entry Points
description: Locates Express.js route registrations, router factories, and handler signatures via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [express]
noiseTier: noisy
filePatterns:
  - "**/*.{ts,js,mjs,cjs,tsx}"
excludePatterns:
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/__tests__/**"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\b(?:app|router)\\.(?:get|post|put|patch|delete|all|use)\\s*\\("
    label: "app/router method registration"
  - regex: "express\\.Router\\s*\\("
    label: "express.Router() factory"
  - regex: "\\(\\s*req\\s*,\\s*res(?:\\s*,\\s*next)?\\s*\\)\\s*=>"
    label: "(req, res) handler signature"
  - regex: "function\\s+\\w+\\s*\\(\\s*req\\s*,\\s*res(?:\\s*,\\s*next)?\\s*\\)"
    label: "function (req, res) handler"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Express.js route registrations,
router factories, and `(req, res)` handler signatures.

Gated on `tech: [express]` — only runs when `fingerprint(root)`
detects Express.

## What this finds

- `app.get/post/put/patch/delete/all/use(...)` registrations
- `router.<verb>(...)` registrations
- `express.Router()` factory calls
- `(req, res, next) => ...` arrow handlers
- `function name(req, res, next)` handler declarations

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
