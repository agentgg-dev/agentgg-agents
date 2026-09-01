---
slug: launchdarkly-sdk-key
name: LaunchDarkly SDK Key Exposure
description: 'Hardcoded LaunchDarkly SDK keys (sdk- prefix) or API tokens (api- prefix) in source or config. Server-side SDK keys grant read access to all feature flag rules; API tokens allow full flag and project management.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\bsdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
      label: LaunchDarkly server-side SDK key (sdk-UUID)
    - regex: '\bapi-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
      label: LaunchDarkly API access token (api-UUID)
    - regex: '(?i)(?:launchdarkly|LAUNCHDARKLY_SDK_KEY|LD_SDK_KEY).{0,30}[=:"''\s]+(?:sdk-|api-)[a-f0-9\-]{36}'
      label: LaunchDarkly key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded LaunchDarkly credentials. LaunchDarkly controls feature flags — leaked keys expose all flag targeting rules and enable flag manipulation.

## Credential types

**Server-side SDK key:** `sdk-<UUID>` — read all flag rules and evaluations. Never expose client-side.

**API access token:** `api-<UUID>` — create/modify/delete flags and projects.

**Client-side ID:** plain UUID (no prefix) — intentionally public, not a secret.

**Mobile key:** `mob-<UUID>` — intentionally public for mobile apps, not a secret.

## What leaked credentials enable

**SDK key:** read all feature flag rules and targeting logic (reveals internal business logic, user segments, percentage rollouts), impersonate the SDK for any user context.

**API token:** create/delete flags, change targeting rules (e.g., enable a feature for all users immediately), read all project environments.

## True positive criteria

Flag when ALL hold:
1. Value starts with `sdk-` or `api-` followed by a UUID format
2. String literal, not an env var reference
3. For `sdk-` keys: file is server-side code (not intentionally public)

## What to ignore

- Client-side IDs (plain UUID without `sdk-`/`api-` prefix)
- Mobile keys (`mob-` prefix)

Report the key type (sdk vs api), whether it appears in server-side or client-side code, and what flag names are visible.
