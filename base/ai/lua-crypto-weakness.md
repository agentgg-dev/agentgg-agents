---
slug: lua-crypto-weakness
name: Lua Cryptographic Weakness
description: OpenResty / Lua code using weak cryptographic primitives — MD5 / SHA1 for security, AES-ECB, hardcoded IVs, timing-unsafe HMAC compare, insecure random.
version: 0.1.0
author: agentgg
mode: file
noiseTier: noisy
outputType: finding
filePatterns:
  - "**/*.lua"
references:
  - CWE-327
  - CWE-208
  - CWE-330
---

You are reviewing OpenResty / Lua code for weak cryptographic
primitives.

## What to look for

**MD5 / SHA1 in security contexts:**
```lua
local digest = md5(payload)
local h = ngx.sha1(data)
local d = ngx.md5(payload)
```
Broken for collision resistance. Use SHA-256 or better for signing
and integrity.

**AES-ECB mode:**
```lua
local cipher = aes:new(key, nil, aes.cipher(256, "ecb"))
```
ECB encrypts identical plaintext blocks to identical ciphertext
blocks — leaks structure. Use GCM or CBC with HMAC.

**Hardcoded IV / nonce:**
```lua
local iv = "0123456789abcdef"
local cipher = aes:new(key, nil, aes.cipher(128, "cbc"), iv)
```
IVs must be random per encryption. Hardcoded IV makes
deterministic ciphertext.

**Timing-unsafe HMAC / hash comparison:**
```lua
if computed_hmac == provided_hmac then ok() end
if hash_value == expected_hash then proceed() end
```
Lua `==` short-circuits — attackers can time the response. Use
`ngx.crypto.timing_safe_equal` (resty.openssl) or
`ngx.encode_base64 + constant-time compare`.

**Insecure random for tokens:**
```lua
math.randomseed(os.time())
local token = math.random(1, 10^10)
```
`math.random` is not cryptographic. Use `resty.random` or
`/dev/urandom`:
```lua
local random = require "resty.random"
local token = ngx.encode_base64(random.bytes(32, true))
```

## True positive criteria

Flag when:
1. `md5(...)`, `ngx.md5(...)`, `ngx.sha1(...)` is used for password
   hashing, HMAC, signing, key derivation, or integrity verification
   on adversarial input.
2. `aes:new` is called with `ecb` mode.
3. AES with CBC/CTR/GCM is called with a hardcoded or static IV.
4. `==` is used to compare a value named `hmac`, `digest`,
   `signature`, `mac`, or `token`.
5. `math.random` / `math.randomseed` is used to generate a token,
   session ID, OTP, or any value reaching a security decision.

## What to ignore

- MD5/SHA1 used for file integrity checksums against accidental
  corruption (context-dependent).
- AES-CBC with a freshly generated random IV per encryption.
- `ngx.sha256` and stronger — those are fine.
- `resty.random` usage.
- Test files.

## Examples

True positives:
```lua
-- MD5 for password
local hash = ngx.md5(password)

-- AES-ECB
local cipher = aes:new(key, nil, aes.cipher(256, "ecb"))

-- Hardcoded IV
local iv = "00000000000000000000000000000000"
local cipher = aes:new(key, nil, aes.cipher(128, "cbc"), iv)

-- Timing-unsafe HMAC compare
if computed_hmac == request_hmac then return true end
```

False positives to skip:
```lua
-- SHA-256 for digest
local hash = ngx.sha256(data)

-- AES-GCM with random IV
local random = require "resty.random"
local iv = random.bytes(12, true)
local cipher = aes:new(key, nil, aes.cipher(256, "gcm"), iv)

-- Cryptographic random for token
local token = ngx.encode_base64(random.bytes(32, true))
```
