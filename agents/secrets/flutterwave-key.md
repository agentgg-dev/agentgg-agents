---
slug: flutterwave-key
name: Flutterwave Secret Key Exposure
description: 'Hardcoded Flutterwave secret keys (FLWSECK- prefix) in source or config. Flutterwave processes payments across Africa and globally — leaked keys enable fraudulent charges and access to customer payment data.'
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
    - regex: '\bFLWSECK-[0-9a-z]{32}-X\b'
      label: Flutterwave secret key (FLWSECK-...-X format)
    - regex: '(?i)(?:flutterwave|FLW_SECRET_KEY|FLUTTERWAVE_SECRET).{0,30}[=:"''\s]+FLWSECK-'
      label: Flutterwave key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Flutterwave secret keys. Flutterwave is a major payment processor for Africa and global markets — a leaked secret key enables fraudulent transactions and customer data access.

## Token format

```
FLWSECK-<32 lowercase alphanumeric characters>-X
```

The `-X` suffix is part of the token. Live keys use this format; test keys use `FLWSECK_TEST-`.

## What a leaked key enables

- Initiate payment charges on behalf of the merchant
- Access transaction history and customer card data
- Initiate refunds
- Verify payments (can be used to mark fraudulent transactions as legitimate)
- For live keys: real money movement

## True positive criteria

Flag at high severity:
1. Live key matching `FLWSECK-[0-9a-z]{32}-X` — string literal, not env var

Flag at lower severity:
2. Test key `FLWSECK_TEST-...` — note credential management pattern

## Examples

True positive:
```js
const Flutterwave = require('flutterwave-node-v3');
const flw = new Flutterwave('FLW_PUBLIC_KEY', 'FLWSECK-<your_secret_key>-X');
```

Report whether the key is live or test, and what payment operations the code performs.
