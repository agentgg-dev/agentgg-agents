---
slug: py-flask-route
name: Flask Route Entry Points
description: Locates Flask route registrations and blueprint declarations via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [flask]
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
  - regex: "^\\s*@(?:app|bp|blueprint|api)\\.route\\s*\\("
    label: "Flask @app.route / blueprint.route"
  - regex: "^\\s*@(?:app|bp)\\.(?:get|post|put|patch|delete)\\s*\\("
    label: "Flask method-shortcut decorator"
  - regex: "\\bBlueprint\\s*\\("
    label: "Blueprint(...) registration"
  - regex: "\\brender_template_string\\s*\\("
    label: "render_template_string (SSTI sink)"
references:
  - CWE-862
  - CWE-1336
---

Regex-only rule (no LLM). Locates Flask route registrations,
blueprint declarations, and a template-injection sink so downstream
walker/hunt/file agents see them as anchor points.

Gated on `tech: [flask]` — only runs when `fingerprint(root)`
detects Flask.

## What this finds

- `@app.route` / `@bp.route` / `@blueprint.route` / `@api.route`
- Method-shortcut decorators (`@app.get`, `@bp.post`, etc.)
- `Blueprint(...)` registrations
- `render_template_string(...)` — server-side template injection sink
  when fed user input

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
