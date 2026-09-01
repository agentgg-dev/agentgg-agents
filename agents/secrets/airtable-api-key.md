---
slug: airtable-api-key
name: Airtable API Key Exposure
description: 'Hardcoded Airtable API keys committed to source. Grants read/write access to all Airtable bases the key owner can access — often containing structured business data, contacts, and customer records.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)airtable.{0,30}[=:"''\s]+[a-z0-9]{17}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Airtable API key near airtable keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:airtable)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9]{17})(?:[''"\n\r\s`;]|$)'
      label: Airtable 17-char API key
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Airtable API keys.

## Token format

Airtable legacy personal API keys: 17-char lowercase alphanumeric. Airtable is also migrating to personal access tokens (PATs) which start with `pat` followed by alphanumeric chars.

## What a leaked token enables

- Read/write all Airtable bases the owner can access
- Access structured business data: customer lists, product catalogs, project trackers, financial records
- Add/delete records, modify table structure
- Enumerate all bases accessible to the key owner

## True positive criteria

Flag when ALL hold:
1. A 17-char lowercase alphanumeric string appears near `airtable`, `AIRTABLE_API_KEY`, `AIRTABLE_KEY`, or an Airtable base URL
2. It is a string literal, not `process.env.AIRTABLE_API_KEY`
3. Not a base ID (those are prefixed with `app`) or table ID (prefixed with `tbl`)

## What to ignore

- Airtable base IDs starting with `app` (`appXXXXXXXXXXXX`) — these are not secrets, can be public
- Table IDs starting with `tbl` — also not secrets
- Environment variable references

Report: any Airtable base IDs visible nearby (indicates which data is exposed), and whether the key appears in server-side or client-side code.
