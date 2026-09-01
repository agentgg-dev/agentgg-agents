---
slug: shopify-token
name: Shopify API Token Exposure
description: 'Hardcoded Shopify admin API tokens (shpat_, shpca_, shpss_, shppa_ prefixes) in source or config. A leaked token can read/write orders, customers, products, and fulfillments — full store data access.'
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
    - regex: '\b(shpat_[a-fA-F0-9]{32})\b'
      label: Shopify admin API access token (shpat_)
    - regex: '\b(shpca_[a-fA-F0-9]{32})\b'
      label: Shopify custom app token (shpca_)
    - regex: '\b(shpss_[a-fA-F0-9]{32})\b'
      label: Shopify app secret key (shpss_)
    - regex: '\b(shppa_[a-fA-F0-9]{32})\b'
      label: Shopify legacy private app password (shppa_)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Shopify API credentials.

## Token types

**Admin API Access Token (`shpat_[32 hex]`):** Current format for custom app and app store app tokens. Grants access to the Shopify Admin API with whatever scopes the app was authorized. Often has broad access including orders, customers, products, inventory, and fulfillments.

**Custom App Token (`shpca_[32 hex]`):** Used by custom apps installed on a single Shopify store. Same scope system as admin tokens.

**App Secret Key (`shpss_[32 hex]`):** The client secret for a Shopify app. Used to verify webhook signatures and exchange OAuth authorization codes for access tokens. If leaked, an attacker can forge webhook requests and potentially hijack OAuth flows.

**Legacy Private App Password (`shppa_[32 hex]`):** Older format for private app API passwords. Still fully functional on stores that haven't migrated to custom apps.

## Risk

An attacker with a Shopify admin token can:
- Read all orders, including customer PII (names, addresses, email, phone) and payment summaries
- Read and write customer records, metafields, and custom data
- Create discount codes, modify prices, or apply fraudulent orders
- Access fulfillment, inventory, and shipping data
- For app secret keys: forge Shopify webhook signatures to inject false events

## Cross-file analysis

When a token is found, look for:
1. The Shopify store URL (`mystore.myshopify.com`) — identifies which store is exposed
2. Which Admin API resources the code accesses (orders, customers, products, GraphQL mutations)
3. Whether the token appears in a webhook handler — if so, the secret key being exposed also undermines webhook verification

## True positive criteria

Flag when ALL hold:
1. The value matches `shpat_`, `shpca_`, `shpss_`, or `shppa_` followed by 32 hex characters
2. It is a string literal, not an environment variable reference (`process.env.SHOPIFY_ACCESS_TOKEN`, `$SHOPIFY_API_SECRET`)
3. It is not a placeholder

## What to ignore

- Environment variable references
- Webhook HMAC signatures — those are computed values, not stored tokens
- Test mode credentials clearly labelled as test/development store tokens

## Examples

True positives:
```ts
const client = new Shopify.Clients.Rest('mystore.myshopify.com', 'shpat_<32-hex-token>');
```
```python
shopify.Session.setup(api_key='AbCdEfAbCdEf', secret='shpss_<32-hex-token>')
```
```yaml
SHOPIFY_ACCESS_TOKEN: shpat_<32-hex-token>
```

False positives to skip:
```ts
const client = new Shopify.Clients.Rest(
  process.env.SHOPIFY_STORE_DOMAIN,
  process.env.SHOPIFY_ACCESS_TOKEN
);
```

Note the store URL and the API scopes used (orders, customers, products) to describe what customer data and store operations are exposed.
