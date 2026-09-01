---
slug: wireguard-key
name: WireGuard Private or Pre-Shared Key Exposure
description: 'WireGuard private keys (PrivateKey = base64) or pre-shared keys (PresharedKey = base64) committed to source. A WireGuard private key allows impersonation of the peer and decryption of intercepted VPN traffic.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/]{43}='
        in:
          - '**/*'
          - '**/*.conf'
          - '**/*.ini'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
        label: WireGuard key assignment (PrivateKey or PresharedKey)
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: 'PrivateKey\s*=\s*[A-Za-z0-9+/]{43}='
      label: WireGuard PrivateKey
    - regex: 'PresharedKey\s*=\s*[A-Za-z0-9+/]{43}='
      label: WireGuard PresharedKey
references:
  - CWE-321
  - CWE-798
---

You are reviewing configuration files for committed WireGuard VPN private or pre-shared keys.

## Key formats

WireGuard uses Curve25519 keys in base64 encoding. Both private keys and pre-shared keys are 44 chars (43 base64 chars + `=` padding):

```ini
[Interface]
PrivateKey = wB3/M5A/5a+WRRpriFD8t4fUh5k1L7xU7eeLVKxnuFg=

[Peer]
PresharedKey = 7iWEMeZMSF+RKpmdZ1s9lI7XtYPz9t5Y5uMxz4rVHEo=
```

## What a leaked key enables

**Private key:** Allows decrypting all recorded traffic sent to/from that peer. Allows impersonating the peer to other nodes in the VPN — gaining access to the private network the VPN protects.

**Pre-shared key:** Provides an additional layer of symmetric encryption. If leaked alongside the private key (which may be separately committed), it fully compromises the tunnel.

## True positive criteria

Flag at critical:
1. `PrivateKey = <base64_44_chars>` found in any committed file — keys must be rotated immediately
2. `PresharedKey = <base64_44_chars>` alongside peer configuration — rotate the tunnel

## What to ignore

- `PublicKey = <base64>` in peer blocks — public keys are not secrets
- Placeholder values: `PrivateKey = REPLACE_ME` or all-zeros base64 — not real keys

## Context

WireGuard config files are often committed to infrastructure-as-code repos. Check whether the repo is infrastructure, CI/CD, or application code — infrastructure repos are the most common source of this exposure.

Report: whether it is a PrivateKey or PresharedKey, the WireGuard interface name if visible, and how many peers are configured.
