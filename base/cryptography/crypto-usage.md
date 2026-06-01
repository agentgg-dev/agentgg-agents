---
slug: crypto-usage
name: Crypto Primitive Usage (Review Site)
description: 'Any file touching cryptographic primitives — sign, verify, encrypt, decrypt, hash, HMAC, random, key derivation. Surfaces subtle bugs the narrow insecure-crypto rule misses (IV reuse, missing AEAD tag verify, weak key sizes, algorithm confusion). Follows key + IV generation across files.'
version: 0.1.0
author: agentgg
noiseTier: noisy
precondition:
  regex:
    patterns:
      - regex: createCipheriv|createDecipheriv|createHash|createHmac|createSign|createVerify|generateKeyPair|randomBytes|pbkdf2|hkdf|scrypt
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,go,py}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Node crypto primitive
      - regex: crypto\.subtle\.(encrypt|decrypt|sign|verify|digest|deriveBits|deriveKey|importKey|exportKey)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,go,py}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Web Crypto API call
      - regex: 'from\s+[''"](jose|jsonwebtoken|bcrypt|bcryptjs|argon2|tweetnacl|libsodium-wrappers|node-forge|@noble/|elliptic|sjcl|tweetsodium)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,go,py}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Imports crypto library
      - regex: '"crypto/(aes|cipher|des|hmac|md5|rand|rc4|rsa|sha1|sha256|sha512|subtle|x509|tls)"'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,go,py}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Go crypto stdlib import
      - regex: from\s+(cryptography|hashlib|hmac|secrets|nacl|jwt|passlib|argon2|Crypto)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,go,py}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Python crypto import
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - go
    - py
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: createCipheriv|createDecipheriv|createHash|createHmac|createSign|createVerify|generateKeyPair|randomBytes|pbkdf2|hkdf|scrypt
      label: Node crypto primitive
    - regex: crypto\.subtle\.(encrypt|decrypt|sign|verify|digest|deriveBits|deriveKey|importKey|exportKey)
      label: Web Crypto API call
    - regex: 'from\s+[''"](jose|jsonwebtoken|bcrypt|bcryptjs|argon2|tweetnacl|libsodium-wrappers|node-forge|@noble/|elliptic|sjcl|tweetsodium)'
      label: Imports crypto library
    - regex: '"crypto/(aes|cipher|des|hmac|md5|rand|rc4|rsa|sha1|sha256|sha512|subtle|x509|tls)"'
      label: Go crypto stdlib import
    - regex: from\s+(cryptography|hashlib|hmac|secrets|nacl|jwt|passlib|argon2|Crypto)\b
      label: Python crypto import
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-327
  - CWE-326
  - 'OWASP-A02:2021'
---

You are reviewing any source file that uses cryptographic primitives.
This is a wide-net rule designed to surface every call site so the
specific subtle bugs (IV reuse, missing tag verification, wrong key
sizes, replay protection gaps) can be checked manually or by the AI
pass. The narrow `insecure-crypto` agent catches obvious bad
algorithms; this agent catches the more nuanced misuses.

**Cross-file analysis:** the most dangerous crypto bugs (IV reuse,
weak key sizes, missing tag verification) require seeing how the
*key* and *IV* are generated, which is usually in a separate config
or key-management module. When a candidate calls
`createCipheriv("aes-256-gcm", key, iv)`, open the source of `key`
and `iv` to confirm randomness, key length, and IV uniqueness.

## Issues to look for at each call site

**Encryption / AEAD:**
- IV / nonce reuse with the same key (GCM/ChaCha20-Poly1305 fail
  catastrophically with IV reuse).
- IV generated from a counter you don't reset on rekey.
- Decryption that doesn't verify the authentication tag, or
  processes plaintext before verification completes.
- AES-CBC without an integrity layer.
- AES-ECB ever.

**Signing / verification:**
- Algorithm chosen from the data instead of pinned.
- Public key used as HMAC key (RS256 ↔ HS256 confusion).
- Signature compared with `===` instead of timing-safe.
- Replay protection: missing nonce/timestamp + window check.

**Hashing for passwords:**
- SHA-* instead of bcrypt / scrypt / argon2 / pbkdf2.
- Missing salt.
- Common salt across users.

**Key derivation:**
- PBKDF2 with low iteration count (< 100k for SHA-256).
- HKDF without `info` parameter when binding to a context.

**Random:**
- `Math.random()` for any security purpose.
- `crypto.randomInt(low, high)` with non-`crypto`-prefix biased
  modulo arithmetic.

**Key sizes:**
- RSA < 2048 bits.
- ECDSA on non-standard curves.

## Library import patterns to watch

- Go: `crypto/aes`, `crypto/cipher`, `crypto/des`, `crypto/hmac`,
  `crypto/md5`, `crypto/rand`, `crypto/rc4`, `crypto/rsa`,
  `crypto/sha1`, `crypto/sha256`, `crypto/subtle`, `crypto/x509`,
  `crypto/tls`, `golang.org/x/crypto/*`
- Node: `crypto`, `node:crypto`, `crypto-js`, `tweetnacl`,
  `@noble/*`, `jose`, `jsonwebtoken`, `bcrypt`, `bcryptjs`,
  `argon2`, `scrypt`, `tweetsodium`, `libsodium-wrappers`,
  `node-forge`, `elliptic`, `sjcl`
- Web Crypto: `crypto.subtle.*`
- Python: `cryptography`, `hashlib`, `hmac`, `secrets`, `Crypto`,
  `nacl`, `jwt`, `passlib`, `bcrypt`, `argon2`

## True positive criteria

Surface every file that imports / uses a cryptographic primitive
listed above. The agent's role is the review site, not the verdict —
the AI pass evaluates each site for the specific issues listed.

## What to ignore

- Test files (`*.test.*`, `*.spec.*`, under `__tests__/`).
- Documentation files that mention crypto in comments only.

## Examples

Flagged (every site is reviewed):
```ts
import crypto from "node:crypto";
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

import { jwtVerify } from "jose";
const { payload } = await jwtVerify(token, key);

import bcrypt from "bcrypt";
const hash = await bcrypt.hash(password, 10);
```

```go
import "crypto/aes"
import "crypto/sha256"

block, _ := aes.NewCipher(key)
h := sha256.Sum256(data)
```
