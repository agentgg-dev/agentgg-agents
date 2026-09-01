---
slug: zendesk-token
name: Zendesk API Token Exposure
description: 'Hardcoded Zendesk API tokens committed to source. Grants access to Zendesk support ticket data, customer PII, and admin functions depending on the associated user role.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)zendesk.{0,30}[=:"''\s]+[a-z0-9]{40}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Zendesk API key near zendesk keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:zendesk)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{40})(?:[''"\n\r\s`;]|$)'
      label: Zendesk 40-char token pattern
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Zendesk API tokens.

## Token format

Zendesk API tokens: 40-char lowercase alphanumeric. Found in Zendesk Admin > Apps and Integrations > Zendesk API > API token.

## What a leaked token enables

- Read all support tickets, including customer messages and attachments
- Access customer PII: names, emails, phone numbers, addresses
- Create/update/delete tickets and users (if associated with an admin account)
- Configure Zendesk integrations and webhooks

## True positive criteria

Flag when ALL hold:
1. A 40-char lowercase alphanumeric string appears near `zendesk`, `ZENDESK_TOKEN`, `ZENDESK_API_KEY`, or `ZENDESK_SECRET`
2. It is a string literal, not an environment variable reference
3. Not a placeholder value

## What to ignore

- `process.env.ZENDESK_API_TOKEN` — safe env reference
- Zendesk subdomain names (`company.zendesk.com`) — not secrets
- The Zendesk email address used with the token — not itself a secret

Report where the token appears and what Zendesk subdomain it is associated with (if visible from nearby config).
