---
slug: salesforce-token
name: Salesforce Access Token Exposure
description: 'Hardcoded Salesforce OAuth access tokens (00D prefix, 104-char format) in source or config. Grants full API access to Salesforce orgs — CRM records, contacts, opportunities, and custom data.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '00[a-zA-Z0-9]{13}!'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Salesforce OAuth access token prefix (00D...!)
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '\b(00[a-zA-Z0-9]{13}![a-zA-Z0-9._]{96})\b'
      label: Salesforce access token (00D...! format, 110 chars)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Salesforce OAuth access tokens.

## Token format

Salesforce access tokens: `00D` followed by 12 alphanumeric chars, a `!`, then 96 alphanumeric/dot/underscore chars — approximately 110 characters total. Example prefix: `00D1r000000xMab!`.

## What a leaked token enables

- Full API access to the Salesforce org (all records the token owner can see)
- Read/write to CRM records: Accounts, Contacts, Leads, Opportunities, custom objects
- Trigger Apex code, call Salesforce REST/SOAP APIs
- Access to sensitive PII stored in Salesforce

## True positive criteria

Flag when ALL hold:
1. String matches the Salesforce token format (00D...! prefix)
2. Found as a string literal, not a template placeholder like `${SALESFORCE_TOKEN}`
3. Not in a test fixture with obviously synthetic values

## What to ignore

- `${SF_ACCESS_TOKEN}` or `process.env.SALESFORCE_TOKEN` — safe environment variable reference
- Salesforce record IDs (18-char alphanumeric, no `!` separator) — not tokens

Report the org prefix (first 15 chars before the `!`) and where the token appears in the codebase.
