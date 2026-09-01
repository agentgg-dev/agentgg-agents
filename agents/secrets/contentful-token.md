---
slug: contentful-token
name: Contentful API Token Exposure
description: 'Hardcoded Contentful Content Delivery API or Content Management API tokens committed to source. CMA tokens grant write access to all content in the space; CDA tokens expose all published content including draft content depending on access level.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)contentful.{0,30}[=:"''\s]+[a-z0-9=_\-]{43}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Contentful API token near contentful keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:contentful)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9=_\-]{43})(?:[''"\n\r\s`;]|$)'
      label: Contentful 43-char API token
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Contentful API tokens.

## Token types

- **Content Delivery API (CDA) token**: read-only access to published content. 43-char alphanumeric. Exposing this reveals all CMS content to anyone who finds it — typically less critical but still a finding.
- **Content Management API (CMA) token**: read/write access to content, models, and space settings. 43-char alphanumeric. Critical — allows modifying or deleting all CMS content.
- **Content Preview API token**: like CDA but includes unpublished draft content.

## True positive criteria

Flag at critical:
1. `CONTENTFUL_MANAGEMENT_TOKEN` or `CONTENTFUL_CMA_TOKEN` set to a 43-char literal — write access to CMS

Flag at high:
2. `CONTENTFUL_ACCESS_TOKEN` or `CONTENTFUL_DELIVERY_TOKEN` set to a 43-char literal — read all published content

Flag at medium:
3. `CONTENTFUL_PREVIEW_TOKEN` — exposes draft/unpublished content

## What to ignore

- `process.env.CONTENTFUL_ACCESS_TOKEN` — safe env reference
- Space IDs (`CONTENTFUL_SPACE_ID`) — 12-char alphanumeric, semi-public, not a secret
- Environment IDs (`master`, `staging`) — not secrets

Report: the token type (CDA/CMA/preview) if determinable from the variable name, and the Contentful space ID if visible nearby.
