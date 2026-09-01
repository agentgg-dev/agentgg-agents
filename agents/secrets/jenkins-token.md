---
slug: jenkins-token
name: Jenkins API Token or Crumb Exposure
description: 'Hardcoded Jenkins API tokens or CSRF crumbs committed to source. API tokens authenticate to the Jenkins API as a specific user; crumbs are short-lived CSRF protection tokens that can be replayed if exposed.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)jenkins.{0,20}[=:"''\s]+[0-9a-f]{32,36}\b'
        in:
          - '**/*'
          - '**/*.{env,conf,config,yaml,yml,json,properties}'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Jenkins token/crumb pattern
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)jenkins.{0,10}(?:crumb|token|api_key|api_token).{0,10}\b([0-9a-f]{32,36})\b'
      label: Jenkins API token or crumb (32-36 hex chars)
    - regex: '(?i)JENKINS_TOKEN|JENKINS_API_TOKEN|jenkins_crumb'
      label: Jenkins token environment variable assignment
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Jenkins API tokens or CSRF crumbs.

## Token formats

- **Jenkins API tokens**: 32-char hex string. Generated per user at `/user/<name>/configure`. Authenticate to the Jenkins REST API.
- **Jenkins crumbs**: 32-36 char hex string. CSRF protection tokens. Short-lived but if exposed in source alongside the session cookie, can be replayed.

## What a leaked token enables

- Trigger Jenkins builds, including parameterized builds with arbitrary parameter injection
- Access build artifacts, logs, and environment variables (which often contain other secrets)
- Create/delete jobs if the associated user has admin privileges
- Read workspace contents which may include source code and secrets

## True positive criteria

Flag when ALL hold:
1. A 32-36 char hex string appears near `jenkins`, `JENKINS_TOKEN`, `JENKINS_API_TOKEN`, or `crumb`
2. It is a string literal, not `$JENKINS_TOKEN` or `process.env.JENKINS_API_TOKEN`
3. Not a build number or other Jenkins numeric identifier (those are short decimal numbers)

## What to ignore

- Jenkins URLs without credentials: `https://jenkins.company.com/job/...` — not a secret
- Jenkins job IDs or build numbers — not tokens
- `withCredentials([string(credentialsId: ...)` — safe credentials binding

Report: the Jenkins instance URL if visible nearby, and whether the token is associated with a named user account.
