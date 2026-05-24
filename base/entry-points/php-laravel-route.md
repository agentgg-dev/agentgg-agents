---
slug: php-laravel-route
name: Laravel Route Entry Points
description: Locates Laravel route registrations, controller actions, and SQL surface markers via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [laravel]
noiseTier: noisy
filePatterns:
  - "**/routes/**/*.php"
  - "**/app/Http/Controllers/**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "Route::(get|post|put|patch|delete|any|match)\\s*\\("
    label: "Route::* registration"
  - regex: "Route::resource\\s*\\("
    label: "Route::resource (CRUD)"
  - regex: "Route::group\\s*\\("
    label: "Route::group (middleware scope)"
  - regex: "class\\s+\\w+Controller\\s+extends\\s+\\w*Controller\\b"
    label: "Controller class"
  - regex: "->middleware\\s*\\(\\s*['\"]auth"
    label: "Auth middleware (verify scope)"
  - regex: "\\$request->all\\s*\\(\\s*\\)"
    label: "$request->all() — mass-assignment surface"
  - regex: "DB::raw\\s*\\("
    label: "DB::raw (SQL injection if interpolated)"
  - regex: "\\b(?:whereRaw|selectRaw|orderByRaw)\\s*\\("
    label: "*Raw query helper"
references:
  - CWE-89
  - CWE-862
---

Regex-only rule (no LLM). Locates Laravel route registrations,
controller actions, and SQL surface markers so downstream
walker/hunt/file agents see them as anchor points.

Gated on `tech: [laravel]` — only runs when `fingerprint(root)`
detects a Laravel project (composer.json with `laravel/*` or an
`artisan` script at the repo root).

## What this finds

- `Route::get/post/put/patch/delete/any/match` registrations
- `Route::resource` CRUD shortcuts
- `Route::group` middleware scopes
- Controller class declarations
- Auth middleware bindings (`->middleware('auth')`)
- `$request->all()` mass-assignment surfaces
- `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw` SQL surface markers

## What this does NOT do

This rule does not classify findings or determine severity — it only
locates candidates. Downstream walker agents (`missing-auth`,
`sql-injection`, etc.) take these candidates and decide whether they
constitute a real vulnerability.
