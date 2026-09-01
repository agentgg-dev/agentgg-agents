---
slug: coinbase-api-key
name: Coinbase API Key Exposure
description: 'Hardcoded Coinbase API keys and secrets committed to source. Grants access to cryptocurrency account balances, trade history, and with write permissions: ability to execute trades, send funds, and manage account settings.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)coinbase.{0,30}[=:"''\s]+[a-z0-9\-]{36,44}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Coinbase API key near coinbase keyword
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|''"]){0,3}(?:=|>|:=|:)(?:[''"\s=`]{0,5})([a-z0-9\-]{32,44})(?:[''"\n\r\s`;]|$)'
      label: Coinbase API key/secret pattern
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Coinbase API credentials.

## Credential types

Coinbase API credentials come in pairs:
- **API Key**: alphanumeric, typically 32-44 chars
- **API Secret**: alphanumeric or base64, typically 64+ chars

Coinbase Advanced Trade also uses CDP API keys with a different format.

## What leaked credentials enable

- Read account balances, portfolio value, transaction history
- With trade permission: execute buy/sell orders for cryptocurrency
- With transfer permission: send funds to external wallets — financial theft
- Access to linked bank accounts or payment methods

## True positive criteria

Flag at critical:
1. API key AND secret both present as string literals (both required for authentication)
2. Near `coinbase`, `COINBASE_API_KEY`, `COINBASE_API_SECRET`, `COINBASE_SECRET`

Flag at high:
3. Only the API key present (secret needed for actual API calls, but reduces the attacker's work)

## What to ignore

- `process.env.COINBASE_API_KEY` — safe env reference
- Coinbase account IDs (UUID format) — not secrets by themselves
- Webhook shared secrets for receiving event notifications — lower risk than trade credentials

Report: whether both key and secret are present, any visible permission scopes (view-only vs. trade vs. transfer), and whether the code appears to execute trades or just display account data.
