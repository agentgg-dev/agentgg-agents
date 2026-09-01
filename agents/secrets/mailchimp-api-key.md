---
slug: mailchimp-api-key
name: Mailchimp API Key Exposure
description: 'Hardcoded Mailchimp API keys ([32 hex]-us[1-2 digits]) in source or config. A leaked key gives full access to marketing lists, audience data, and the ability to send bulk email campaigns.'
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
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '[0-9a-f]{32}-us[0-9]{1,2}'
      label: Mailchimp API key (32 hex-usN format)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Mailchimp API keys.

## Key format

Mailchimp API keys follow a distinctive format: `[32 hex characters]-us[1-2 digits]`. The suffix (`-us1`, `-us2`, `-us21`, etc.) identifies the data center where the account is hosted.

Example: `<mailchimp-api-key>-us1`

## Risk

An attacker with a Mailchimp API key can:
- Export all audience/contact lists — full name, email, phone, purchase history, segmentation tags, and any custom fields (PII exposure)
- Send email campaigns to the entire list, impersonating the brand for phishing or spreading malware
- Create and modify automations — add malicious email sequences triggered by user actions
- Access e-commerce data linked to the account (orders, products, revenue)
- Modify account settings, templates, and sender domains

## Cross-file analysis

When a key is found, look for:
1. Mailchimp list IDs or audience IDs — indicates the size and sensitivity of the subscriber data
2. Campaign content templates — determines what the attacker could say while impersonating the brand
3. Whether the integration manages transactional email (mandrill) vs. marketing campaigns

## True positive criteria

Flag when ALL hold:
1. The value matches `[0-9a-f]{32}-us[0-9]{1,2}`
2. It is a string literal, not an environment variable reference (`process.env.MAILCHIMP_API_KEY`, `os.environ.get('MAILCHIMP_API_KEY')`)
3. It is not a placeholder: all same hex digit, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-us1`, documentation examples

## What to ignore

- Environment variable references
- Mock values in unit tests (check no real HTTP calls are made)
- The `-us` portion appearing in URLs or other non-key contexts

## Examples

True positives:
```ts
const mailchimp = require('@mailchimp/mailchimp_marketing');
mailchimp.setConfig({ apiKey: '<mailchimp-api-key>-us21', server: 'us21' });
```
```python
mailchimp = Client()
mailchimp.set_config({"api_key": "<mailchimp-api-key>-us1"})
```
```yaml
MAILCHIMP_API_KEY: <mailchimp-api-key>-us1
```

False positives to skip:
```ts
mailchimp.setConfig({ apiKey: process.env.MAILCHIMP_API_KEY });
```

Note which audience/list IDs appear in the code to estimate the number of subscribers whose data is at risk.
