---
slug: zapier-webhook
name: Zapier Webhook URL Exposure
description: 'Zapier Catch Hook webhook URLs committed to source. Anyone with the URL can trigger Zapier automation workflows, potentially exfiltrating data sent to the hook or executing automated actions (emails, database writes, API calls).'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'hooks\.zapier\.com/hooks/catch/'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Zapier webhook URL
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: 'https://(?:www\.)?hooks\.zapier\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/'
      label: Zapier Catch Hook URL
references:
  - CWE-798
  - CWE-200
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Zapier webhook URLs.

## URL format

```
https://hooks.zapier.com/hooks/catch/<account_id>/<hook_id>/
```

Zapier "Catch Hook" trigger URLs. Anyone who knows the URL can send a POST request to trigger the Zap.

## What a leaked webhook URL enables

An attacker who discovers the URL can:
1. Trigger the Zapier automation repeatedly (spam, resource exhaustion)
2. Inject arbitrary data into the Zap's payload — if the Zap forwards data to a database, email, or Slack channel, the attacker controls that data
3. Trigger automated actions like sending emails, creating records in Google Sheets, or posting to Slack with attacker-controlled content

The risk level depends on what the Zap does downstream.

## True positive criteria

Flag when:
1. A Zapier webhook URL appears as a string literal in source code or config
2. The Zap performs non-trivial actions (not just logging) — check the surrounding code for context about what data is sent

## Severity assessment

Flag at high:
- URL appears in server-side code where the payload is constructed from database data or user input

Flag at medium:
- URL appears in client-side code (client-exposed anyway) but Zap likely writes to shared systems

## What to ignore

- URLs in documentation or README files marked as examples with a note like "replace with your webhook"
- Zapier URLs that are intentionally public (e.g., public form submission hooks documented as such)

Report: the hook URL found, any surrounding code showing what data is sent in the payload, and whether the URL is in server-side or client-side code.
