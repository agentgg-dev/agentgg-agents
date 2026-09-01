---
slug: stripe-secret-key
name: Stripe Secret Key Exposure
description: 'Hardcoded Stripe secret keys (sk_live_*, sk_test_*) or restricted keys (rk_live_*, rk_test_*) in source or config. A live secret key can list customers, create charges, issue refunds, and modify subscription plans.'
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
    - regex: '\b(sk_(?:live|test)_[0-9a-zA-Z]{24})\b'
      label: Stripe secret key (sk_live_ / sk_test_)
    - regex: '\b(rk_(?:live|test)_[0-9a-zA-Z]{24})\b'
      label: Stripe restricted key (rk_live_ / rk_test_)
    - regex: '(?i)\b((sk|rk)_(test|live|prod)_[0-9a-z]{10,99})(?:[''"\n\r\s;]|$)'
      label: Stripe key broad pattern
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Stripe API keys. Stripe keys control payment processing and financial data.

## Key types and risk

**Secret key (`sk_live_*`):** Full access to the Stripe account. Can list all customers and their payment methods, create charges, issue refunds, cancel subscriptions, create payout transfers, and download transaction history. A live secret key exposure is a critical financial security incident.

**Secret key (`sk_test_*`):** Same capabilities, but on the Stripe test environment. No real money risk, but leaking test keys can reveal account structure and be used to understand the payment integration.

**Restricted key (`rk_live_*` / `rk_test_*`):** Scoped to specific Stripe resources and operations. Risk depends on the permissions granted — some restricted keys have narrow read access, others are nearly as powerful as a full secret key.

## Cross-file analysis

When a key is found, check:
1. Whether it is a `live` or `test` key — live keys are immediately exploitable
2. What Stripe API endpoints the code calls — determines what an attacker can do with the key
3. Whether the publishable key (`pk_live_*`) is also present — by itself, `pk_*` is safe (it is meant to be public), but its presence confirms the account is active

## True positive criteria

Flag when ALL hold:
1. The value matches `sk_live_`, `sk_test_`, `rk_live_`, or `rk_test_` followed by at least 10 alphanumeric characters
2. It is a string literal, not a reference to an environment variable or secrets manager
3. It is not a placeholder: `sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXX`, all same characters, or Stripe's own documentation examples

Give higher severity to `sk_live_` over `sk_test_` — live keys can cause real financial harm.

## What to ignore

- Publishable keys `pk_live_*` / `pk_test_*` — these are intentionally public and safe to expose in frontend code
- Environment variable references: `process.env.STRIPE_SECRET_KEY`, `stripe.api_key = os.environ['STRIPE_SECRET_KEY']`
- Clearly redacted or masked values

## Examples

True positives:
```ts
const stripe = require('stripe')('sk_live_<24-char-key>');
```
```python
stripe.api_key = 'sk_test_<24-char-key>'
```
```yaml
STRIPE_SECRET_KEY: sk_live_<24-char-key>
```

False positives to skip:
```ts
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
```
```ts
// publishable key — intentionally public
const stripePromise = loadStripe('pk_live_AbCdEfGhIjKlMnOpQrStUvWx');
```

Rate the finding as critical for `sk_live_` keys, high for `sk_test_` keys, and medium for restricted keys. Note which Stripe API calls the code makes to describe the blast radius.
