---
slug: mailgun-api-key
name: Mailgun API Key Exposure
description: 'Hardcoded Mailgun API keys (key- prefix + 32 alphanumeric chars) in source or config. Grants access to send emails, read message logs, access mailing lists, and manage domain settings.'
version: 0.1.0
author: agentgg
noiseTier: normal
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
    - regex: '\bkey-[0-9a-zA-Z]{32}\b'
      label: Mailgun API key (key- prefix + 32 chars)
    - regex: '(?i)(?:mailgun|MAILGUN_API_KEY|MG_API_KEY).{0,30}[=:"''\s]+key-[0-9a-zA-Z]{32}'
      label: Mailgun API key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Mailgun API keys. Mailgun handles transactional email — a leaked key allows sending emails as the domain and reading message history.

## Token format

```
key-<32 alphanumeric characters>
```

Note: `key-` is a relatively generic prefix. Only flag when the Mailgun context is confirmed (variable named `MAILGUN_API_KEY`, Mailgun SDK import, or mailgun.com domain reference nearby).

## What a leaked key enables

- Send emails from any domain on the Mailgun account (phishing, spam)
- Read message logs including email content and recipient addresses
- Access mailing lists (read subscriber lists)
- Modify domain settings and routing rules
- Delete sent message logs

## True positive criteria

Flag when ALL hold:
1. Value matches `key-[0-9a-zA-Z]{32}` exactly
2. Mailgun context is confirmed: variable name, SDK import (`require('mailgun-js')`), or `mailgun.com` reference nearby
3. String literal, not an env var reference

## What to ignore

- `key-` prefix appearing in non-Mailgun contexts (other services use similar formats)

## Examples

True positive:
```js
const mailgun = require('mailgun-js');
const mg = mailgun({ apiKey: 'key-AbCdEfGhIjKlMnOpQrStUvWxYz123456', domain: 'mg.example.com' });
```

Report which sending domains the key has access to and what email operations the code performs.
