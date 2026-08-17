---
slug: aes-mode-misuse
name: AES Mode / Nonce / Key-Derivation Misuse
description: 'AES used insecurely despite being a sound cipher: ECB mode, unauthenticated CBC/CTR without HMAC/AEAD, GCM/CCM with a static or reused nonce/IV, a hardcoded IV, or a raw password used directly as the key without a KDF. Traces key/IV/nonce origin across helpers. Complements insecure-crypto which covers MD5/SHA1/DES/RC4.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'AES\.MODE_ECB|AES/ECB/|aes-[0-9]{3}-ecb|"ECB"|''ECB'''
        in:
          - '**/*.py'
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.java'
          - '**/*.kt'
          - '**/*.go'
          - '**/*.php'
          - '**/*.cs'
        notIn:
          - '**/__tests__/**'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/*_test.go'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
        label: AES ECB mode
      - regex: 'AES\.MODE_(CBC|CTR)|aes-[0-9]{3}-(cbc|ctr)|AES/(CBC|CTR)/'
        in:
          - '**/*.py'
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.java'
          - '**/*.kt'
          - '**/*.go'
          - '**/*.php'
          - '**/*.cs'
        notIn:
          - '**/__tests__/**'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/*_test.go'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
        label: AES CBC/CTR mode (check for missing auth tag)
      - regex: 'AES\.MODE_(GCM|CCM|EAX)|aes-[0-9]{3}-(gcm|ccm)|AES/GCM/|createCipheriv\s*\(\s*[''"]aes'
        in:
          - '**/*.py'
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.java'
          - '**/*.kt'
          - '**/*.go'
          - '**/*.php'
          - '**/*.cs'
        notIn:
          - '**/__tests__/**'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/*_test.go'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
        label: AES AEAD / createCipheriv (check nonce/IV and key derivation)
      - regex: 'openssl_encrypt\s*\(|Cipher\.getInstance\s*\(\s*["'']AES'
        in:
          - '**/*.php'
          - '**/*.java'
          - '**/*.kt'
        notIn:
          - '**/tests/**'
          - '**/vendor/**'
        label: PHP openssl_encrypt / Java Cipher.getInstance AES
where:
  extensions:
    - py
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - java
    - kt
    - go
    - php
    - cs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/*_test.go'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'AES\.MODE_ECB|AES/ECB/|aes-[0-9]{3}-ecb'
      label: AES ECB mode (deterministic, leaks plaintext patterns)
    - regex: 'AES\.MODE_(CBC|CTR)|aes-[0-9]{3}-(cbc|ctr)|AES/(CBC|CTR)/'
      label: AES CBC/CTR (unauthenticated unless HMAC/AEAD present)
    - regex: 'AES\.MODE_(GCM|CCM|EAX)|aes-[0-9]{3}-(gcm|ccm)|AES/GCM/'
      label: AES AEAD (check nonce uniqueness)
    - regex: 'createCipheriv\s*\(\s*[''"]aes'
      label: Node createCipheriv (check IV/nonce and key source)
    - regex: 'openssl_encrypt\s*\('
      label: PHP openssl_encrypt (check mode/IV)
    - regex: 'Cipher\.getInstance\s*\(\s*["'']AES'
      label: Java Cipher.getInstance AES
    - regex: 'iv\s*=\s*[''"][0-9a-fA-F]{8,}[''"]|nonce\s*=\s*[''"][0-9a-fA-F]{8,}[''"]|IV\s*=\s*[''"]'
      label: Hardcoded IV/nonce literal
    - regex: 'createCipheriv\s*\([^)]*,\s*(password|passphrase|pwd|secret)\b'
      label: Raw password used as key (no KDF)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-327
  - CWE-329
  - CWE-326
  - 'OWASP-A02:2021'
---

You are reviewing code that uses AES for cipher-*usage* mistakes.
AES itself is fine; the bug is the mode, the nonce/IV, or the key
derivation. The attacker — anyone who can observe or capture the
ciphertext (a leaked DB dump, a sniffed message, a stored token) —
can recover plaintext, detect repeated plaintext, or forge/tamper
with messages.

Stay in scope: do NOT re-flag MD5/SHA1/DES/RC4/Blowfish or generic
weak primitives — those belong to `insecure-crypto`. This agent is
only about AES mode, nonce/IV, and key-derivation misuse.

**Cross-file analysis:** the key, IV, and nonce often originate in
a different function or a config/constants module. To judge a
GCM/CTR call you must find where the nonce comes from — is it
`os.urandom(12)` / `crypto.randomBytes(12)` per message, or a
module-level constant reused on every call? To judge the key, trace
it back: is it a random 32-byte key / a KDF output, or the user's
password sliced to 32 bytes? Open the helper that builds the cipher
and the constants file that holds `IV = ...`.

## What to look for

**1. ECB mode (deterministic — identical blocks leak):**
```py
cipher = AES.new(key, AES.MODE_ECB)
```
```js
crypto.createCipheriv("aes-256-ecb", key, null)
```
```java
Cipher.getInstance("AES/ECB/PKCS5Padding")
```
```php
openssl_encrypt($pt, "aes-256-ecb", $key)
```
ECB is almost never acceptable for real data.

**2. CBC / CTR without authentication (malleable):**
```py
cipher = AES.new(key, AES.MODE_CBC, iv)   # no HMAC over ciphertext anywhere
```
Unauthenticated CBC enables padding-oracle attacks; CTR is
trivially malleable (bit-flip). A finding unless an HMAC covers the
ciphertext+IV (encrypt-then-MAC) or the code switches to an AEAD
mode.

**3. GCM/CCM/EAX with a static or reused nonce:**
```py
NONCE = b"000000000000"
cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)   # same nonce every call
```
```js
const iv = Buffer.alloc(12, 0);                    // constant
crypto.createCipheriv("aes-256-gcm", key, iv);
```
Nonce reuse in GCM is catastrophic: it leaks the XOR of plaintexts
and the authentication subkey, allowing forgery.

**4. Hardcoded IV (constant across encryptions):**
```py
iv = b"1234567890123456"
cipher = AES.new(key, AES.MODE_CBC, iv)
```
A constant IV makes CBC partly deterministic and breaks
semantic security.

**5. Raw password used directly as the AES key (no KDF):**
```py
key = password.encode().ljust(32, b"0")   # or password[:32]
cipher = AES.new(key, AES.MODE_GCM, nonce=n)
```
```js
crypto.createCipheriv("aes-256-cbc", Buffer.from(password), iv)
```
Passwords are low-entropy and not key-sized. Derive the key with
PBKDF2 / scrypt / Argon2 (with a per-record salt) — not by padding
or hashing once with a plain digest.

## True positive criteria

Flag when ANY of these hold and the code does not demonstrate the
safe alternative:

1. AES used in ECB mode for real data.
2. AES-CBC or AES-CTR with no authentication tag / HMAC over the
   ciphertext anywhere on the encrypt or decrypt path.
3. AES-GCM/CCM/EAX where the nonce/IV is a constant, a hardcoded
   literal, derived deterministically, or otherwise reused across
   encryptions under the same key.
4. A hardcoded IV literal passed to any AES mode.
5. A user password / passphrase used as the AES key without a
   password-based KDF (PBKDF2 / scrypt / Argon2 / bcrypt-derived).

State the impact concretely, e.g. "Two ciphertexts under the same
GCM nonce let me recover `P1 XOR P2` and forge messages" or
"Identical plaintext blocks produce identical ECB blocks, so I can
read structure from the database dump."

## What to ignore

- AES-GCM / ChaCha20-Poly1305 with a *fresh random* nonce per
  message (`os.urandom(12)`, `crypto.randomBytes(12)`,
  `secrets.token_bytes`, `SecureRandom`) stored alongside the
  ciphertext — this is the correct pattern.
- CBC/CTR that IS authenticated: an HMAC over IV+ciphertext is
  computed and verified (encrypt-then-MAC), or a library AEAD
  wrapper is used.
- A random IV generated per encryption and prepended to the
  ciphertext (standard for CBC).
- Keys derived via PBKDF2/scrypt/Argon2 with a per-record salt, or a
  random key from a KMS / `randomBytes(32)`.
- A nonce that is a per-message counter guaranteed unique under the
  key (e.g. monotonic sequence persisted) — acceptable for GCM if
  truly never reused.
- ECB used only to wrap a single random key block in a documented
  key-wrapping context (prefer AES-KW; flag for review, lower
  severity).
- Test vectors / KAT fixtures that hardcode IV+key to match a
  published test vector.

## Examples

True positives:
```py
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(data, 16))
```
```js
const iv = Buffer.alloc(12, 0);
const c = crypto.createCipheriv("aes-256-gcm", key, iv);   // reused nonce
```
```py
key = password.encode()[:32].ljust(32, b"\0")
cipher = AES.new(key, AES.MODE_CBC, iv)                    # password as key
```

False positives to skip:
```py
nonce = os.urandom(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
blob = nonce + cipher.encrypt(pt) + cipher.digest()        # fresh nonce, AEAD
```
```py
salt = os.urandom(16)
key = scrypt(password, salt=salt, n=2**15, r=8, p=1, dklen=32)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()  # KDF + encrypt-then-MAC
```
