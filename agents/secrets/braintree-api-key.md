---
slug: braintree-api-key
name: Braintree Payment API Key Exposure
description: 'Hardcoded Braintree/PayPal production access tokens or private keys in source or config. Grants access to payment processing, customer payment vault, and transaction history.'
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
    - regex: '\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b'
      label: Braintree production access token (precise format)
    - regex: '(?i)(?:braintree|BRAINTREE_PRIVATE_KEY|BT_PRIVATE_KEY).{0,30}[=:"''\s]+[a-f0-9]{32}'
      label: Braintree private key in named variable
    - regex: '(?i)braintree.{0,60}(?:private_key|privateKey)\s*[=:]\s*[''"]?[a-f0-9]{32}'
      label: Braintree privateKey in gateway config
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Braintree payment credentials. Braintree (a PayPal subsidiary) handles credit card processing — leaked credentials expose customer payment data and enable fraudulent transactions.

## Credential types

**Production access token:** `access_token$production$<16 lowercase alphanumeric>$<32 lowercase hex>`

**Private key (32 lowercase hex):** used with Merchant ID and Public Key to authenticate the Braintree gateway. The private key is the secret — the public key and merchant ID are less sensitive.

## What a leaked key enables

- Process transactions and charge stored payment methods
- Access the payment vault: read customer card details
- Issue refunds, read full transaction history
- Submit fraudulent transactions as the merchant

## True positive criteria

Flag at high severity:
1. Production access token (`$production$`) — string literal, not env var ref
2. 32-hex private key near "braintree" context

Flag at lower severity:
3. Sandbox token (`$sandbox$`) — lower risk but note the credential management pattern

## Examples

True positive:
```python
gateway = braintree.BraintreeGateway(
    braintree.Configuration(
        environment=braintree.Environment.Production,
        merchant_id="abc123",
        public_key="def456",
        private_key="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    )
)
```

Report whether production or sandbox, what payment operations the code performs, and whether a payment vault (stored customer cards) is in use.
