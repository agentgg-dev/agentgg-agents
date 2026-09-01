---
slug: alibaba-cloud-key
name: Alibaba Cloud Access Key Exposure
description: 'Hardcoded Alibaba Cloud access key IDs (LTAI prefix) in source or config. These credentials grant API access to Alibaba Cloud services: ECS instances, OSS buckets, RDS databases, and more.'
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
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\bLTAI[a-zA-Z0-9]{17,21}\b'
      label: Alibaba Cloud access key ID (LTAI prefix)
    - regex: '(?i)(?:aliyun|alibaba|ALIBABA_CLOUD|ALICLOUD).{0,40}[=:"''\s]+[A-Za-z0-9]{30,}'
      label: Alibaba Cloud secret key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Alibaba Cloud credentials. Alibaba Cloud is the dominant cloud provider in Asia — leaked credentials give API access to all cloud resources under the account.

## Credential types

**Access Key ID:** `LTAI<17-21 alphanumeric chars>` — identifies the key.
**Access Key Secret:** 30-character alphanumeric string — authenticates the API call. Both are needed for API access.

## What a leaked key pair enables

- Access and modify ECS (VM) instances
- Read/write OSS (object storage) buckets
- Access RDS database connection details
- Enumerate all cloud resources in the account
- Create new access keys (persistence)
- Incur billing charges

## True positive criteria

Flag when ALL hold:
1. An `LTAI...` access key ID appears as a literal string
2. Ideally the access key secret is also nearby (look for a 30-char alphanumeric string adjacent to the key ID)
3. Not an env var reference

## Examples

True positives:
```python
import oss2
auth = oss2.Auth('LTAI5tAbCdEfGhIjKlMnOpQr', 'SecretKeyHere30CharAlphaNum')
```
```env
ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI5tAbCdEfGhIjKlMnOpQr
ALIBABA_CLOUD_ACCESS_KEY_SECRET=SecretKeyHere30CharAlphaNum
```

Report the services used (OSS, ECS, RDS) and whether the secret key is also present.
