---
slug: pii-credit-card
name: Credit Card Number in Source Code or Config
description: 'Credit card numbers (Visa, Mastercard, Amex, Discover, and others) present as string literals in source code, test fixtures, or committed config files. Real card numbers are a PCI DSS violation; test card numbers in production code indicate improper data handling.'
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
    - regex: '4[0-9]{12}(?:[0-9]{3})?'
      label: Visa card number pattern (13 or 16 digits starting with 4)
    - regex: '(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}'
      label: Mastercard number pattern
    - regex: '3[47][0-9]{13}'
      label: American Express card number (15 digits, starts with 34/37)
    - regex: '6(?:011|5[0-9]{2})[0-9]{12}'
      label: Discover card number pattern
    - regex: '(?:2131|1800|35\d{3})\d{11}'
      label: JCB card number pattern
    - regex: '3(?:0[0-5]|[68][0-9])[0-9]{11}'
      label: Diners Club card number pattern
references:
  - CWE-312
  - CWE-359
  - 'OWASP-A02:2021'
---

You are reviewing source code, test fixtures, and config files for credit card numbers. These patterns have a high false-positive rate — your job is to apply judgment and determine whether each match is a real card number in a meaningful context.

## Judgment: is this really a card number?

The preFilter matches any sequence of digits in the right range. Flag only when the context confirms it's a card:

1. **Payment context nearby:** checkout code, Stripe/Braintree/Square SDK, `payment`, `card`, `billing` variable names
2. **Expiry date or CVV adjacent:** `exp_month`, `exp_year`, `cvc`, `cvv`, `expiry`, `MM/YY`
3. **Data file with user records:** CSV, JSON, or SQL with multiple fields (name, email, address)

If none of these apply, it is almost certainly a false positive (order ID, timestamp, phone number, etc.).

## Known test card numbers (lower severity)

Stripe test cards (flag as code hygiene, not PCI violation):
- `4242424242424242` — Visa
- `4000056655665556` — Visa debit
- `5555555555554444` — Mastercard
- `378282246310005` — Amex
- `6011111111111117` — Discover

If you see these exact values, note them as test card numbers and flag at lower severity (these should be in fixture files, not hardcoded in source).

## True positive criteria

Flag at critical severity:
1. A card number not matching known test cards
2. Appears alongside expiry date and/or CVV, OR in a data export/CSV with PII fields
3. Variable name or context implies a real card (`customer_card`, `stored_pan`, `payment_method.number`)

Flag at lower severity:
4. Known Stripe test card in production application code (not in a test fixture file)

## What to ignore

- 16-digit numbers without payment context: timestamps in milliseconds, order IDs, product SKUs, phone numbers with country codes
- Card number masks: `**** **** **** 1234`, `XXXX-XXXX-XXXX-4567`
- Tokenized references: Stripe `tok_`, `pm_`, `card_` IDs — not card numbers
- Comments explaining the format: `// example: 4111111111111111`
- Numbers in regex patterns for card validation in validation library code

## Examples

Critical (real card with expiry + CVV):
```python
cards = [
    {'number': '4532015112830366', 'exp': '12/25', 'cvv': '123', 'name': 'John Smith'},
]
```

Lower severity (known test card in source):
```js
const testCard = { number: '4242424242424242', exp_month: 12, exp_year: 2025 };
```

Not a card number:
```python
order_id = '4532015112830366'  # no payment context
```

Report: whether the number is a known test card or unknown, whether expiry/CVV data is nearby, the file type, and the approximate number of records if in a data file.
