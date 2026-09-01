---
slug: sendinblue-api-key
name: Sendinblue / Brevo API Key Exposure
description: 'Hardcoded Sendinblue (now Brevo) API keys (xkeysib- prefix, 81 chars) in source or config. Grants access to send emails and SMS, read contact lists, and access transactional message logs.'
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
    - regex: '\bxkeysib-[A-Za-z0-9_\-]{81}\b'
      label: Sendinblue/Brevo API key (xkeysib- prefix, 81 chars)
    - regex: '(?i)(?:sendinblue|brevo|SENDINBLUE_API_KEY|BREVO_API_KEY).{0,30}[=:"''\s]+xkeysib-[A-Za-z0-9_\-]{81}'
      label: Sendinblue/Brevo key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Sendinblue (now rebranded as Brevo) API keys. Sendinblue/Brevo handles transactional email, marketing campaigns, and SMS.

## Token format

```
xkeysib-<81 alphanumeric/dash/underscore characters>
```

Total length: 89 characters (8 prefix + 81 chars).

## What a leaked key enables

- Send emails and SMS from any sender address configured on the account
- Read the full contact database (email addresses, names, custom attributes)
- Access transactional email logs (content, recipients, delivery status)
- Send marketing campaigns to all contacts
- Create or delete contacts and lists

## True positive criteria

Flag when ALL hold:
1. Value matches `xkeysib-[A-Za-z0-9_-]{81}` exactly
2. String literal, not `process.env.SENDINBLUE_API_KEY`
3. Not a placeholder

## Examples

True positive:
```python
import sib_api_v3_sdk
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = 'xkeysib-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz'
```

Report what email/SMS operations the code performs and whether it accesses the contact database.
