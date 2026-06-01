---
slug: laravel-mass-assignment
name: Laravel Mass Assignment
description: Eloquent models filled from request input without guarding sensitive attributes, letting a caller set fields (is_admin, role, balance) they shouldn't control.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    files:
      - "**/artisan"
      - "**/composer.json"
    directories:
      - "**/app/**"
    patterns:
      - regex: "->(fill|forceFill)\\s*\\(|::create\\s*\\(|::update\\s*\\(|->update\\s*\\("
        in:
          - "**/app/**/*.php"
        label: "Eloquent mass-assignment call"
  prompt: |
    Run only if this is a Laravel application — look for artisan, an
    app/Http directory, routes/, and illuminate/laravel in composer.json.
where:
  filePatterns:
    - "**/app/**/*.php"
  excludePatterns:
    - "**/tests/**"
  preFilter:
    - regex: "->(fill|forceFill)\\s*\\(\\s*\\$request"
      label: "fill() directly from request"
    - regex: "::create\\s*\\(\\s*\\$request->all\\s*\\(\\)"
      label: "create() from request->all()"
    - regex: "->update\\s*\\(\\s*\\$request->all\\s*\\(\\)"
      label: "update() from request->all()"
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-915
  - OWASP-A08:2021
---

You are reviewing a Laravel application for mass-assignment
vulnerabilities: Eloquent models populated directly from request
input where the model does not restrict which attributes can be set.

When you find a `fill()` / `create()` / `update()` fed from
`$request->all()` (or the whole request), use Read to open the model
class and check its `$fillable` / `$guarded` declarations. The bug
exists when the model leaves sensitive attributes assignable.

## Flag

```php
User::create($request->all());          // model has no $guarded
$user->update($request->all());
$model->forceFill($request->input());   // forceFill bypasses guarding entirely
```
combined with a model exposing privileged columns (`is_admin`,
`role`, `account_balance`) and a permissive or absent `$fillable`/
`$guarded`.

## Skip

- `$request->validate([...])` / `$request->only([...])` / form-request
  classes that whitelist fields before the model call.
- Models with a tight `$fillable` that excludes the sensitive columns.
- Internal/admin flows where the privileged column is intended to be
  set and is access-controlled.

Cite both the mass-assignment call and the model's guarding (or lack
of it) — a finding needs both halves.
