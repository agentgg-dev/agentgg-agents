---
slug: paystack-api-key
name: Paystack Secret Key Exposure
description: 'Hardcoded Paystack secret keys (sk_live_ or sk_test_ prefix + 40 chars) in source or config. Paystack processes payments primarily in Africa — leaked keys enable fraudulent charges and access to customer transaction data.'
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
    - regex: '\bsk_live_[A-Za-z0-9]{40}\b'
      label: Paystack live secret key (sk_live_ + 40 chars)
    - regex: '\bsk_test_[A-Za-z0-9]{40}\b'
      label: Paystack test secret key (sk_test_ + 40 chars)
    - regex: '(?i)(?:paystack|PAYSTACK_SECRET|PAYSTACK_SK).{0,30}[=:"''\s]+sk_(?:live|test)_[A-Za-z0-9]{40}'
      label: Paystack secret key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Paystack secret keys. Paystack is a major payment processor in Nigeria and across Africa — a leaked secret key enables fraudulent transactions.

## Token format

```
sk_live_<40 alphanumeric characters>   (production)
sk_test_<40 alphanumeric characters>   (test)
```

Note: Paystack uses 40-char keys vs Stripe's 24-char keys — this distinguishes them.

## What a leaked live key enables

- Initiate payment charges
- Read all transaction history and customer data
- Issue refunds
- Manage subscriptions and plans
- Access transfer recipients (bank account details)

## True positive criteria

Flag at high severity:
1. `sk_live_` + 40 alphanumeric chars — string literal, not env var

Flag at lower severity:
2. `sk_test_` key — note credential management pattern

## Examples

True positive:
```js
const paystack = require('paystack')('sk_live_<your_live_key_here>');
```

Report whether live or test, and what payment operations the code performs.
