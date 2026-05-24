---
slug: py-django-view
name: Django View Entry Points
description: Locates Django views, urlpatterns, and class-based views via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [django, djangorestframework]
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
  - regex: "^\\s*path\\s*\\("
    label: "urlpatterns path()"
  - regex: "^\\s*re_path\\s*\\("
    label: "urlpatterns re_path()"
  - regex: "^class\\s+\\w+\\s*\\([^)]*\\b(?:View|TemplateView|ListView|DetailView|FormView|APIView|ViewSet|ModelViewSet|GenericAPIView|CreateView|UpdateView|DeleteView)\\b"
    label: "class-based view"
  - regex: "^def\\s+\\w+\\s*\\(\\s*request\\b"
    label: "function-based view (def view(request))"
  - regex: "@csrf_exempt\\b"
    label: "@csrf_exempt — confirm alternate auth"
  - regex: "@api_view\\s*\\("
    label: "DRF @api_view decorator"
references:
  - CWE-862
  - CWE-352
---

Regex-only rule (no LLM). Locates Django function-based views,
class-based views, and `urlpatterns` entries so downstream
walker/hunt/file agents see them as anchor points.

Gated on `tech: [django, djangorestframework]` — only runs when
`fingerprint(root)` detects Django or Django REST Framework.

## What this finds

- `urlpatterns` entries: `path(...)` and `re_path(...)`
- Class-based views (`View`, `ListView`, `APIView`, `ModelViewSet`, etc.)
- Function-based views (`def view(request)`)
- `@csrf_exempt` decorators (alternate auth must exist)
- DRF `@api_view` decorators

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents take these candidates
and decide whether they constitute a real vulnerability.
