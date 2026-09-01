---
slug: codecov-token
name: Codecov Upload Token Exposure
description: 'Hardcoded Codecov repository upload tokens committed to source. Enables injecting arbitrary coverage data into Codecov reports — primarily notable as the token abused in the Codecov supply chain attack (2021) to steal CI environment variables.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(?i)codecov.{0,30}[=:"''\s]+[a-z0-9]{32}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Codecov token near codecov keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:codecov)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{32})(?:[''"\n\r\s`;]|$)'
      label: Codecov 32-char upload token
    - regex: '(?i)CODECOV_TOKEN\s*=\s*[a-z0-9]{32}'
      label: CODECOV_TOKEN variable assignment
references:
  - CWE-798
  - CVE-2021-1000
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Codecov upload tokens.

## Token format

Codecov upload tokens: 32-char lowercase alphanumeric. Found in the Codecov repository settings page. Used by the Codecov Bash uploader to submit coverage reports.

## Risk context: the Codecov supply chain attack (2021)

In April 2021, attackers modified the Codecov Bash Uploader script to exfiltrate all CI environment variables to a remote server. CI pipelines that trusted the tampered script leaked secrets including AWS keys, GitHub tokens, and other credentials. The attack was possible because many projects downloaded the script without verifying its integrity.

## What a leaked token enables

- Submit falsified coverage data to Codecov reports (gaming coverage metrics)
- More relevantly: if the uploader script is modified, legitimate CI runs that use the token will execute malicious code

## True positive criteria

Flag when:
1. `CODECOV_TOKEN` is set to a 32-char literal value in a CI config (`.github/workflows/`, `circle.yml`, `.travis.yml`)
2. Especially flag if `CODECOV_TOKEN` is hardcoded in a workflow file rather than referenced as a secret

## What to ignore

- `${{ secrets.CODECOV_TOKEN }}` — correctly stored as a CI secret
- `$CODECOV_TOKEN` with no literal value visible — safe env reference

## Recommendation

Codecov tokens should always be stored as CI secrets (GitHub Actions secrets, CircleCI environment variables) and injected at runtime — never committed to source.

Report: where the token is committed (CI workflow file, .env file, application config), and whether the Codecov uploader is called with `curl | bash` (which was the attack vector in 2021).
