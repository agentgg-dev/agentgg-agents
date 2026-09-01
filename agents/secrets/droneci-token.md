---
slug: droneci-token
name: Drone CI API Token Exposure
description: 'Hardcoded Drone CI personal API tokens committed to source. Grants access to CI pipeline management, build logs, and repository secrets stored in Drone — enabling pipeline manipulation and secret exfiltration.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)(?:DRONE_TOKEN|drone.{0,20}token).{0,30}[=:"''\s]+[a-zA-Z0-9]{32,64}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Drone CI API token variable
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:DRONE_TOKEN|DRONE_SERVER_TOKEN|drone_api_key|drone.{0,10}access.{0,10}token)\s*=\s*[''"]?[a-zA-Z0-9]{32,64}'
      label: Drone CI token assignment
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Drone CI API tokens.

## Token format

Drone CI personal API tokens: alphanumeric strings, typically 32-64 chars. Generated in the Drone user account settings or configured as server tokens via `DRONE_TOKEN` environment variable.

## What a leaked token enables

- Read pipeline definitions (`.drone.yml`) and build logs
- Access secrets stored in Drone's secret store (often database URLs, API keys for deployments)
- Trigger new pipeline builds or restart existing builds
- Modify repository activation settings

## True positive criteria

Flag when:
1. `DRONE_TOKEN` or `DRONE_SERVER_TOKEN` is set to an alphanumeric literal (not `${DRONE_TOKEN}` or a placeholder)
2. The token length matches Drone's format (32-64 alphanumeric chars)

## What to ignore

- `${DRONE_TOKEN}` — environment variable substitution
- `$DRONE_TOKEN` in shell scripts — safe env reference
- Placeholder values like `YOUR_DRONE_TOKEN_HERE`

Report: whether the token appears in a `.drone.yml`, a deployment script, or application config, and what Drone server URL is nearby (if any).
