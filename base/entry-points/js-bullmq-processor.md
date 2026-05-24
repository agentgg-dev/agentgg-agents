---
slug: js-bullmq-processor
name: BullMQ Worker/Queue Entry Points
description: Locates BullMQ workers, queue declarations, and job.data accessors — background-job auth-gap surface — via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [bullmq]
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
  - regex: "new\\s+Worker\\s*\\(\\s*['\"][^'\"]+['\"]\\s*,"
    label: "new Worker('queue', handler)"
  - regex: "new\\s+Queue\\s*\\(\\s*['\"][^'\"]+['\"]"
    label: "new Queue() declaration"
  - regex: "\\.process\\s*\\(\\s*async\\s*\\(\\s*job\\b"
    label: "queue.process(async job => ...) handler body"
  - regex: "\\bjob\\.data\\b"
    label: "job.data — payload trust boundary"
references:
  - CWE-862
  - CWE-915
---

Regex-only rule (no LLM). Locates BullMQ `Worker` and `Queue`
declarations, processor handler bodies, and `job.data` accessors.

Gated on `tech: [bullmq]` — only runs when `fingerprint(root)`
detects BullMQ.

## What this finds

- `new Worker('queue-name', handler)` declarations
- `new Queue('queue-name', ...)` declarations
- `.process(async job => ...)` handler bodies
- `job.data` — payload trust boundary

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
