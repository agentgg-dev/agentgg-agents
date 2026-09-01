---
slug: razorpay-api-key
name: Razorpay API Key Exposure
description: 'Hardcoded Razorpay secret keys (rzp_live_ or rzp_test_ prefix) in source or config. Razorpay is a major payment processor in India — leaked keys enable fraudulent charges and expose customer payment data.'
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
    - regex: '\brzp_live_[a-zA-Z0-9]{10,20}\b'
      label: Razorpay live secret key (rzp_live_)
    - regex: '\brzp_test_[a-zA-Z0-9]{10,20}\b'
      label: Razorpay test secret key (rzp_test_)
    - regex: '(?i)(?:razorpay|RAZORPAY_KEY_SECRET|RZP_SECRET).{0,30}[=:"''\s]+rzp_(?:live|test)_[a-zA-Z0-9]{10,20}'
      label: Razorpay key in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Razorpay API credentials. Razorpay is a leading payment gateway in India processing UPI, cards, and net banking.

## Credential structure

Razorpay uses a Key ID + Key Secret pair:
- **Key ID:** `rzp_live_<10-20 chars>` or `rzp_test_<10-20 chars>` — semi-public, identifies the merchant
- **Key Secret:** alphanumeric string, typically 20+ chars — the actual secret used to sign requests

Both the Key ID and Key Secret appear in API calls. The Key Secret alone is sufficient to sign fraudulent requests.

## What a leaked live key enables

- Process payment orders and capture charges
- Read all transaction history and customer data
- Issue refunds
- Access virtual account details
- Read linked bank account information

## True positive criteria

Flag at high severity:
1. `rzp_live_` Key ID — string literal in production code (and look for the Key Secret nearby)

Flag at lower severity:
2. `rzp_test_` Key ID — note credential management pattern

## Examples

True positive:
```python
import razorpay
client = razorpay.Client(auth=('rzp_live_AbCdEfGhIjKl', 'SecretKeyHere'))
```

Report whether live or test, and what payment operations the code performs.
