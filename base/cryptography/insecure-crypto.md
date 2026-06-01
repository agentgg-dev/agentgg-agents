---
slug: insecure-crypto
name: Insecure Cryptographic Primitives
description: 'Weak hashes (MD5, SHA1), deprecated ciphers (createCipher, DES, RC4, Blowfish), timing-unsafe equality checks on HMACs/digests, and Math.random for security tokens. Walker mode traces helper functions to confirm the security context.'
version: 0.1.0
author: agentgg
noiseTier: noisy
precondition:
  regex:
    patterns:
      - regex: 'createHash\s*\(\s*[''"](md5|sha1)[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: createHash with MD5/SHA1
      - regex: createCipher\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'createCipher (deprecated, no IV)'
      - regex: '[''"](DES|3DES|RC4|Blowfish)[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Deprecated cipher algorithm literal
      - regex: (hmac|digest|signature|expected|computed)\s*(===|==)\s*
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Timing-unsafe comparison on HMAC/digest/signature
      - regex: 'Math\.random\s*\(\s*\)[\s\S]{0,100}(token|secret|otp|id|password|key)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Math.random used near security-shaped name
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'createHash\s*\(\s*[''"](md5|sha1)[''"]'
      label: createHash with MD5/SHA1
    - regex: createCipher\s*\(
      label: 'createCipher (deprecated, no IV)'
    - regex: '[''"](DES|3DES|RC4|Blowfish)[''"]'
      label: Deprecated cipher algorithm literal
    - regex: (hmac|digest|signature|expected|computed)\s*(===|==)\s*
      label: Timing-unsafe comparison on HMAC/digest/signature
    - regex: 'Math\.random\s*\(\s*\)[\s\S]{0,100}(token|secret|otp|id|password|key)'
      label: Math.random used near security-shaped name
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-327
  - CWE-330
  - CWE-208
  - 'OWASP-A02:2021'
---

You are reviewing JavaScript / TypeScript source code for use of
broken or deprecated cryptographic primitives — weak hashes, removed
ciphers, non-constant-time comparisons, and PRNGs that aren't
cryptographically secure.

**Walker mode advantage:** MD5/SHA1 for content addressing (e.g.,
ETag, dedup) is acceptable; for password hashing or HMAC it's not.
Trace the call result: where does the hash flow? If it's compared
against a stored password or used as a session token, it's a finding.
Also follow any `compare()` helper to see whether it actually uses
`timingSafeEqual` internally.

## What to look for

**MD5 / SHA1 in security contexts:**
```ts
crypto.createHash("md5").update(s).digest();
crypto.createHash("sha1").update(s);
const h = md5(input);
```
MD5 and SHA1 are broken for collision resistance. Use SHA-256 or
better. (MD5/SHA1 are still fine for non-security uses like
file-integrity checksums against accidental corruption — flag for
review.)

**`createCipher` (deprecated, IV reuse risk):**
```ts
crypto.createCipher("aes", key);
```
`createCipher` derives the IV deterministically from the key, so
encrypting the same plaintext twice produces identical ciphertext —
catastrophic for confidentiality of repeated values. Use
`crypto.createCipheriv` with a random IV.

**Weak ciphers:**
```ts
const algo = "DES";   // 56-bit key, broken
const algo = "RC4";   // multiple known biases, broken
const algo = "Blowfish";  // 64-bit block — birthday-bound issues
```
Use AES-256-GCM or ChaCha20-Poly1305.

**Timing-unsafe comparison on HMAC / digest / signature:**
```ts
if (computed === hmac) ok();
if (digest === expected) return;
if (signature == provided) return;
```
String equality short-circuits on the first differing byte —
attackers can time the response to extract the secret byte by byte.
Use `crypto.timingSafeEqual(a, b)`.

**`Math.random` for tokens / IDs / secrets:**
```ts
const token = Math.random().toString(36);
const otp = Math.floor(Math.random() * 1_000_000);
```
`Math.random` is not cryptographic. Use `crypto.randomBytes` /
`crypto.randomUUID` / `crypto.getRandomValues`.

## True positive criteria

Flag when ANY of the following hold:

1. `createHash("md5"|"sha1")` is called in a security context
   (password storage, HMAC, signature, key derivation).
2. `createCipher` (without `iv`) is called.
3. The literal string `"DES"`, `"RC4"`, `"Blowfish"`, or `"3DES"`
   appears as a cipher algorithm argument.
4. `===` / `==` is used to compare a value named `hmac`, `digest`,
   `signature`, `token`, or `expected` (against another such value).
5. `Math.random()` is used to generate a token, ID, OTP, or any
   value reaching a security check.

## What to ignore

- MD5/SHA1 used for non-security file integrity (Git-style content
  addressing, checksum against accidental corruption — context-
  dependent).
- `===` comparisons on plain identifiers (not the named secret-like
  variables above).
- Test files.

## Examples

True positives:
```ts
// MD5 for password
const hash = crypto.createHash("md5").update(password).digest("hex");

// createCipher
const c = crypto.createCipher("aes-256-cbc", key);

// Timing-unsafe HMAC compare
if (computed === providedSignature) return ok();

// Math.random for OTP
const otp = Math.floor(Math.random() * 1000000);
```

False positives to skip:
```ts
// SHA-256 for password (still wrong — should be bcrypt/scrypt/argon2,
// but not within scope of this agent)
crypto.createHash("sha256").update(password).digest();

// Constant-time comparison
crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Cryptographic randomness
const token = crypto.randomBytes(32).toString("hex");
```
