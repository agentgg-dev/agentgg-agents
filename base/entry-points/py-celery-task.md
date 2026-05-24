---
slug: py-celery-task
name: Celery Task Entry Points
description: Locates Celery task definitions and dispatch sites — background-job auth surface — via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [celery]
noiseTier: noisy
filePatterns:
  - "**/*.py"
excludePatterns:
  - "**/tests/**"
  - "**/test/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "**/migrations/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "^\\s*@(?:app|celery|shared_task)\\.task\\b"
    label: "@app.task / @celery.task"
  - regex: "^\\s*@shared_task\\b"
    label: "@shared_task decorator"
  - regex: "\\.delay\\s*\\(|\\.apply_async\\s*\\("
    label: "task.delay/apply_async dispatch site"
  - regex: "\\bCelery\\s*\\(\\s*['\"]"
    label: "Celery('app') init"
references:
  - CWE-862
  - CWE-915
---

Regex-only rule (no LLM). Locates Celery task definitions and
dispatch sites — a common auth-gap surface where background jobs
operate without the request-level auth context.

Gated on `tech: [celery]` — only runs when `fingerprint(root)`
detects Celery.

## What this finds

- `@app.task` / `@celery.task` / `@shared_task.task` decorators
- `@shared_task` decorator
- `.delay(...)` / `.apply_async(...)` dispatch sites
- `Celery('app-name', ...)` initializer

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
