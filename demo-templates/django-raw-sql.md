---
slug: django-raw-sql
name: Django Raw SQL Injection
description: Django ORM raw()/extra()/RawSQL or cursor.execute calls built with untrusted input instead of parameterized params — SQL injection in a Django app.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    files:
      - "**/manage.py"
    extensions:
      - ".py"
    patterns:
      - regex: "\\.(raw|extra)\\s*\\(|RawSQL\\s*\\(|cursor\\.execute\\s*\\("
        in:
          - "**/*.py"
        label: "Django raw SQL call"
where:
  extensions: [py]
  excludePatterns:
    - "**/migrations/**"
    - "**/tests/**"
  preFilter:
    - regex: "\\.raw\\s*\\(\\s*f['\"]|\\.extra\\s*\\(|RawSQL\\s*\\("
      label: "raw/extra/RawSQL call"
    - regex: "cursor\\.execute\\s*\\(\\s*f['\"]|cursor\\.execute\\s*\\([^)]*%\\s*\\("
      label: "cursor.execute with f-string / %-format"
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing a Django application for SQL injection through the ORM's raw
escape hatches: `Model.objects.raw()`, `QuerySet.extra()`, `RawSQL()`, and
direct `cursor.execute()` calls where untrusted input is interpolated into the
SQL string instead of passed as parameters.

When a flagged call builds SQL with an f-string, `%`-formatting, or `+`
concatenation of request data, confirm whether the value reaches the database
unparameterized. Use Read/Grep to follow helpers and view functions.

## Flag

```python
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
qs.extra(where=[f"age > {request.GET['age']}"])
cursor.execute("SELECT * FROM t WHERE id = %s" % request.GET["id"])
```

## Skip

- `raw("... %s", [param])` / `cursor.execute("...", [param])` — params passed
  separately (parameterized).
- `.filter(...)` / `.get(...)` and other ORM query-builder calls (already safe).

Report only calls where untrusted input reaches the SQL string unparameterized.
