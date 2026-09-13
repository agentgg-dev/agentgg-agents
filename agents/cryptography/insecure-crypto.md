---
slug: insecure-crypto
name: Insecure Cryptographic Primitives
description: 'Weak hashes (MD5, SHA1), deprecated ciphers (createCipher, DES, RC4, Blowfish), timing-unsafe equality checks on HMACs/digests, Math.random for security tokens, undersized RSA/ECDSA keys, and weak PBKDF2/HKDF derivation parameters. Traces helper functions to confirm the security context.'
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
      - regex: hashlib\.(md5|sha1)\s*\(|hashlib\.new\s*\(\s*[\"'](md5|sha1)[\"']
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: hashlib MD5/SHA1
      - regex: \brandom\.(random|randint|choice|randrange)\s*\([^)]*\)[\s\S]{0,100}(token|secret|otp|key|password)
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: random module used near a security-shaped name
      - regex: (hmac|digest|signature|expected|computed|mac)\s*==\s*
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Timing-unsafe comparison on HMAC/digest/signature
      - regex: "[\\\"'](DES|3DES|RC4|Blowfish|ECB)[\\\"']"
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Deprecated cipher/mode literal
      - regex: Crypto\.Cipher|from\s+Crypto\s+import
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: pycryptodome low-level cipher use
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
      - regex: 'from\s+[''\"](jose|jsonwebtoken|bcrypt|bcryptjs|argon2|tweetnacl|libsodium-wrappers|node-forge|@noble/|elliptic|sjcl|tweetsodium)'
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
      - regex: MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: MessageDigest MD5/SHA-1
      - regex: Cipher\.getInstance\s*\(\s*[\"'][^\"']*(DES|RC4|ECB)
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: weak cipher or ECB mode
      - regex: new\s+Random\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: java.util.Random (not SecureRandom)
      - regex: DigestUtils\.(md5|sha1)
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: commons-codec MD5/SHA-1
      - regex: \w*(signature|hmac|digest|mac)\w*\s*\.equals\s*\(|\.equals\s*\(\s*\w*(signature|hmac|digest|mac)
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: timing-unsafe equals on a signature
where:
  extensions:
    - java
    - kt
    - py
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - go
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/.venv/**'
    - '**/venv/**'
    - '**/site-packages/**'
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
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
    - regex: hashlib\.(md5|sha1)\s*\(
      label: hashlib MD5/SHA1
    - regex: hashlib\.new\s*\(\s*[\"'](md5|sha1)[\"']
      label: hashlib.new with MD5/SHA1
    - regex: (hmac|digest|signature|expected|computed|mac)\s*==\s*
      label: Timing-unsafe comparison
    - regex: "[\\\"'](DES|3DES|RC4|Blowfish|ECB)[\\\"']"
      label: Deprecated cipher/mode literal
    - regex: \brandom\.(random|randint|choice|randrange)\s*\(
      label: random module (verify not security-relevant)
    - semgrepRule: cryptography/crypto-primitive
      label: Crypto primitive call (cipher, hash, HMAC, key derivation)
    - regex: MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']
      label: MD5/SHA-1 digest
    - regex: Cipher\.getInstance\s*\(\s*[\"'][^\"']*(DES|RC4|ECB)
      label: weak cipher/ECB
    - regex: new\s+Random\s*\(
      label: java.util.Random
    - regex: DigestUtils\.(md5|sha1)
      label: commons-codec weak digest
    - regex: \.equals\s*\(\s*\w*(signature|hmac|digest|mac)
      label: timing-unsafe equals
  maxFilesPerBatch: 5
references:
  - CWE-327
  - CWE-330
  - CWE-326
  - CWE-208
  - 'OWASP-A02:2021'

---

You are reviewing JavaScript / TypeScript, Python, and Go source code
for use of broken or deprecated cryptographic primitives — weak
hashes, removed ciphers, non-constant-time comparisons, and PRNGs that
aren't cryptographically secure, plus key sizes and derivation
parameters too weak to carry the security the code claims.

**Cross-file analysis:** MD5/SHA1 for content addressing (e.g.,
ETag, dedup) is acceptable; for password hashing or HMAC it's not.
Trace the call result: where does the hash flow? If it's compared
against a stored password or used as a session token, it's a finding.
Also follow any `compare()` helper to see whether it actually uses
`timingSafeEqual` internally. Key material is usually generated in a
separate key-management or config module, so when a call site takes a
`key` argument, open the source of that key to confirm its length and
how it was generated.

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

**Undersized keys and unusual curves:**
```ts
crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
crypto.createSign("sha256");   // check the key this signs with
```
RSA below 2048 bits is too small for any signing or encryption key in
production. For ECDSA, confirm the curve is a standard one such as
P-256, P-384, or Ed25519. A non-standard or hand-rolled curve is a
finding on its own, since its security is unreviewed.

**Weak key derivation parameters:**
```ts
crypto.pbkdf2(password, salt, 1000, 32, "sha256", cb);
crypto.hkdfSync("sha256", ikm, salt, "", 32);
```
PBKDF2 under 100k iterations with SHA-256 is below current guidance
and cheap to grind offline. HKDF called with an empty or missing
`info` parameter cannot bind the derived key to a context, so the same
input keying material yields the same key for two different uses.

**Third-party crypto libraries.** The same rules apply when the
primitive comes from a library rather than the platform. Watch for
`crypto-js`, `node-forge`, `libsodium-wrappers`, `tweetnacl`,
`@noble/*`, `elliptic`, `sjcl`, `jose`, `jsonwebtoken`, `bcrypt`,
`bcryptjs`, and `argon2` in JavaScript; `cryptography`, `hashlib`,
`hmac`, `secrets`, `nacl`, `passlib`, and `Crypto` in Python; and
`crypto/aes`, `crypto/cipher`, `crypto/des`, `crypto/hmac`,
`crypto/md5`, `crypto/rand`, `crypto/rc4`, `crypto/rsa`,
`crypto/sha1`, `crypto/subtle`, `crypto/x509`, `crypto/tls`, and
`golang.org/x/crypto/*` in Go. In Go, `aes.NewCipher(key)` is the call
site to inspect: check the key length and where the key came from.

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
6. An RSA key is generated or loaded with a modulus under 2048 bits.
7. An ECDSA key uses a non-standard curve, or the curve is selected
   from data rather than pinned in code.
8. PBKDF2 runs with fewer than 100k iterations for SHA-256.
9. HKDF is called without an `info` parameter where the derived key
   is bound to a specific context or use.

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

// Undersized RSA key
crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });

// PBKDF2 with too few iterations
crypto.pbkdf2Sync(password, salt, 1000, 32, "sha256");
```

```go
// 1024-bit RSA signing key
key, _ := rsa.GenerateKey(rand.Reader, 1024)

// MD5 over a secret
h := md5.Sum(secret)
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
