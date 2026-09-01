---
slug: twilio-api-key
name: Twilio API Key Exposure
description: 'Hardcoded Twilio API keys (SK[32 hex]) in source or config. Combined with the Account SID and secret, an attacker can send SMS/voice messages as the account, enumerate phone numbers, and incur billing charges.'
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
    - regex: '(?i)twilio.{0,20}\b(sk[a-f0-9]{32})\b'
      label: Twilio API key (SK + 32 hex near "twilio")
    - regex: '\bSK[a-f0-9]{32}\b'
      label: Twilio API key standalone pattern
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Twilio API keys.

## Credential format

Twilio API keys begin with `SK` followed by 32 lowercase hexadecimal characters: `SK[a-f0-9]{32}`.

Twilio uses a trio of credentials for authentication:
1. **Account SID** (`AC[a-f0-9]{32}`) — identifies the account (semi-public)
2. **API Key SID** (`SK[a-f0-9]{32}`) — the key identifier
3. **API Key Secret** — a random string shown only once at creation

The key SID alone is not exploitable. However, the API key secret often appears directly below the SID in the same config block, and both together grant API access.

## Cross-file analysis

When an API key SID is found, look in the same file or nearby config for:
1. The API key secret (variable names: `TWILIO_API_SECRET`, `apiSecret`, `auth_secret`)
2. The Account SID (`AC[a-f0-9]{32}`)
3. What the code does with the credentials: send SMS, make voice calls, access Verify, Conversations, or Flex

## True positive criteria

Flag when ALL hold:
1. The value matches `SK[a-f0-9]{32}` and appears near Twilio-related code or config
2. It is a string literal, not an environment variable reference (`process.env.TWILIO_API_KEY`)
3. It is not a placeholder or test value (all same hex digit, documentation examples)

Upgrade to high severity if the API key secret is also present in the file.

## What to ignore

- Environment variable references: `process.env.TWILIO_API_KEY_SID`, `os.environ.get('TWILIO_API_KEY')`
- Account SIDs (`AC...`) alone — they are account identifiers, not authentication secrets by themselves
- Mock/stub values used in unit tests with no real HTTP calls

## Examples

True positives:
```ts
const client = twilio(
  'SK<32-hex-api-key>',  // API Key SID
  'YourAPIKeySecret',                      // API Key Secret
  { accountSid: 'AC<32-hex-account-sid>' }
);
```
```yaml
TWILIO_API_KEY: SK<32-hex-api-key>
TWILIO_API_SECRET: YourAPIKeySecretHere
```

False positives to skip:
```ts
const client = twilio(
  process.env.TWILIO_API_KEY_SID,
  process.env.TWILIO_API_KEY_SECRET,
  { accountSid: process.env.TWILIO_ACCOUNT_SID }
);
```

Note whether the API key secret is also present, what Twilio services the code uses (SMS, Voice, Verify, Conversations), and whether the account appears to be production (by checking outgoing phone numbers or service names).
