---
slug: sendgrid-api-key
name: SendGrid API Key Exposure
description: 'Hardcoded SendGrid API keys (SG. prefix) in source or config. A leaked key can send bulk email as the account, access contact lists, modify sending domains, and suppress deliverability reports.'
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
    - regex: '(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:[''"\n\r\s;`]|$)'
      label: SendGrid API key (SG. prefix, 66+ chars)
    - regex: '\bSG\.[a-zA-Z0-9_\-\.]{60,}\b'
      label: SendGrid API key broad pattern
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded SendGrid API keys.

## Key format

SendGrid API keys always begin with `SG.` followed by approximately 66 base64url-compatible characters. The total length is around 69 characters.

## Risk

An attacker with a SendGrid API key can:
- Send unlimited email as any verified sender domain on the account — enables phishing, spam, and reputation damage
- List and export marketing contact lists (PII exposure)
- Modify or delete email templates, suppression lists, and inbound parse settings
- View email activity logs and engagement statistics
- Depending on key scopes: manage account settings, add/remove team members, modify IP pools

## Key scopes

SendGrid keys can be scoped to specific permissions. The code context reveals what operations are performed — look for `sendgrid.send()`, `sgClient.request()`, `/v3/marketing/contacts`, `/v3/mail/send`, etc.

## Cross-file analysis

Look for:
1. What the key is used for — transactional email, marketing campaigns, contact management
2. Whether `from` addresses are hardcoded alongside the key (reveals sender identity)
3. Whether the key appears in a frontend or client-side bundle — SendGrid keys should never reach the browser

## True positive criteria

Flag when ALL hold:
1. The value starts with `SG.` and is approximately 69 characters total
2. It is a string literal, not an environment variable reference (`process.env.SENDGRID_API_KEY`)
3. It is not a placeholder: `SG.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`, obvious all-same-character values

## What to ignore

- Environment variable references: `process.env.SENDGRID_API_KEY`, `os.environ.get('SENDGRID_API_KEY')`
- Example/documentation keys from SendGrid tutorials
- Redacted or masked values

## Examples

True positives:
```ts
sgMail.setApiKey('SG.<sendgrid-api-key>');
```
```python
sg = sendgrid.SendGridAPIClient(api_key='SG.<sendgrid-api-key>')
```
```yaml
SENDGRID_API_KEY: SG.<sendgrid-api-key>12
```

False positives to skip:
```ts
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
```

Note what the code uses the key for (transactional vs. marketing email, contact management) and whether it appears in server-side vs. client-side code.
