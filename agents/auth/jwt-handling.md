---
slug: jwt-handling
name: 'JWT Handling (Signing, Verification, Key Management)'
description: 'JWT signing and verification (jose, jsonwebtoken, custom) — verify algorithm pinning, key management, secret strength, and audience/issuer/expiration checks. Follows key sources and verifier helpers.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: jwt\.(verify|sign|decode)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: jsonwebtoken jwt.verify/sign/decode call
      - regex: \bjwtVerify\s*\(|new\s+SignJWT\s*\(|\bjwtDecrypt\s*\(|new\s+EncryptJWT\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: jose verify/sign/decrypt/encrypt call
      - regex: (verifyJwt|verifyJWT|signJwt|signJWT)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Custom JWT helper
      - regex: 'split\s*\(\s*["'']\.["'']\s*\)|base64url|atob\s*\([^)]*\.'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'Manual JWT decoding (split on ''.'', base64) — possible hand-rolled verifier'
      - regex: jwt\.(decode|encode)\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: PyJWT decode/encode call
      - regex: verify_signature[\"']?\s*:\s*False|verify\s*=\s*False
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: JWT signature verification disabled
      - regex: base64\.(urlsafe_)?b64decode\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Manual base64 JWT payload decode
      - regex: \.split\s*\(\s*[\"']\.[\"']\s*\)
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Manual JWT split on '.' (hand-rolled decoder)
      - regex: from\s+jose\s+import|import\s+jose\b
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: python-jose import
      - regex: jwt_obj\s*:\s*verify\s*\(
        in:
          - '**/*.lua'
        notIn:
          - '**/spec/**'
          - '**/*_spec.lua'
        label: OpenResty resty.jwt verify call
      - regex: algorithms\s*=\s*\[[^\]]*[\"']none[\"']
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: alg 'none' accepted in allowlist
      - regex: jwt\.get_unverified_(header|claims)\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Unverified JWT header/claims read
where:
  extensions:
    - py
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - lua
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
  preFilter:
    - regex: jwt\.(verify|sign|decode)\s*\(
      label: jsonwebtoken jwt.verify/sign/decode call
    - regex: \bjwtVerify\s*\(|new\s+SignJWT\s*\(|\bjwtDecrypt\s*\(|new\s+EncryptJWT\s*\(
      label: jose verify/sign/decrypt/encrypt call
    - regex: (verifyJwt|verifyJWT|signJwt|signJWT)\s*\(
      label: Custom JWT helper
    - regex: 'split\s*\(\s*["'']\.["'']\s*\)|base64url|atob\s*\([^)]*\.'
      label: 'Manual JWT decoding (split on ''.'', base64) — possible hand-rolled verifier'
    - regex: jwt\.(decode|encode)\s*\(
      label: PyJWT decode/encode call
    - regex: verify_signature[\"']?\s*:\s*False
      label: JWT signature verification disabled
    - regex: base64\.(urlsafe_)?b64decode\s*\(
      label: Manual base64 JWT payload decode
    - regex: \.split\s*\(\s*[\"']\.[\"']\s*\)
      label: Manual JWT split on '.'
    - regex: jwt_obj\s*:\s*verify\s*\(
      label: Lua resty.jwt verify
    - regex: algorithms\s*=\s*\[
      label: JWT algorithms allowlist
    - regex: jwt\.get_unverified_(header|claims)\s*\(
      label: Unverified JWT header/claims read
  maxFilesPerBatch: 5
references:
  - CWE-345
  - CWE-347
  - CVE-2015-9235
  - 'OWASP-A02:2021'

---

You are reviewing source code that signs, verifies, encrypts, or
decrypts JWTs — looking for misconfigurations that lead to token
forgery or authentication bypass.

**Cross-file analysis:** the signing key and verifier options are
usually centralized in `lib/jwt.ts` or `auth/config.ts`. Open the
config to verify: is the key strong (env-sourced, not a default
fallback)? Are the verifier defaults pinning algorithms, audience,
and issuer? If the candidate file just calls `verifySession(token)`,
the actual config lives in the helper — read it.

This is the broad JWT review pass, and it also covers algorithm
confusion: a verifier that trusts whichever `alg` the incoming token
header declares. Check pinning all the way down the wrapper chain
before reporting it.

## What to look for

**Algorithm not pinned at verification:**
```ts
jwt.verify(token, secret);                       // accepts any algorithm
await jwtVerify(token, key);                     // jose without algorithms option
```
Safe form: `jwt.verify(token, secret, { algorithms: ["RS256"] })`.
Without a pin the verifier uses the algorithm named in the token
header, so the caller chooses it. Two ways that is abused: strip the
signature with `alg: none`, or downgrade RS256 to HS256. Pin one
expected algorithm, or a short allowlist of the ones actually in use,
and never include `none`. jose's defaults are safer than
jsonwebtoken's, but pin explicitly there too.

**OpenResty / `resty.jwt` without `alg_whitelist`:**
```lua
local ok, err = jwt_obj:verify(secret, token)
-- accepts any algorithm; alg_whitelist is not set
```
Safe form passes an `alg_whitelist` table naming the expected
algorithm.

**Unverified header or claims read as if trusted:**
```py
header = jwt.get_unverified_header(token)
claims = jwt.get_unverified_claims(token)
```
Reading the header to select a JWKS key is fine. Making an
authorization decision on unverified claims is not.

**`none` inside the allowlist:**
```py
jwt.decode(token, key, algorithms=["RS256", "none"])
```
An allowlist containing `none` is the same as no verification.

**`alg: none` accepted:**
```ts
jwt.sign(payload, key, { algorithm: "none" });
jwt.sign(payload, key, { alg: "none" });
```
Signing with `none` is rarely intentional. Verifying tokens that
declare `alg: none` accepts unsigned tokens.

**Public key used as HMAC secret:**
```ts
// RS256 token verified with public key — but lib also accepts HS256
// signing the same key, allowing forgery.
jwt.verify(token, pubKey);   // no algorithms pin
```
This is the RS256 to HS256 confusion. The code intends asymmetric
verification, so it hands the library the RSA public key. With no
algorithm pin the attacker re-signs the token as HS256, and the
library then treats that same key as an HMAC secret. The public key
is published, so the attacker already has everything needed to mint
valid tokens. Treat a verify call whose key material is a public key
or a JWKS entry, with no `algorithms` option, as a finding.

**Weak HMAC secret:**
```ts
jwt.sign(payload, "secret");
jwt.sign(payload, "changeme");
jwt.sign(payload, process.env.JWT_SECRET ?? "default");
```

**Missing audience / issuer / expiration checks:**
```ts
const decoded = jwt.verify(token, secret, { algorithms: ["RS256"] });
// No `audience: "..."` or `issuer: "..."` option — token issued for
// a different service is accepted.
```

**Storing JWTs in localStorage on the client:**
```ts
localStorage.setItem("token", jwt);   // XSS-readable
```
Prefer httpOnly cookies for session tokens.

**Custom JWT verification implementations:**
Hand-rolled base64-decode + HMAC compare is almost always wrong.
Flag any file that splits a token on `.`, base64-decodes, and
compares signatures manually instead of using `jose` or
`jsonwebtoken`.

## True positive criteria

Flag for review when:
1. `jwt.verify`, `jwtVerify`, `verifyJwt`, `jwt.sign`, `SignJWT`,
   `jwtDecrypt`, or `EncryptJWT` is called AND any of the
   misconfigurations above are visible in the same file.
2. The secret used for signing is a hardcoded string or has a
   weak default fallback.
3. The verification call lacks an `algorithms` option, an
   `audience` option, or an `issuer` option where the JWT
   represents a session for this specific service.
4. A custom JWT verifier is implemented from scratch.
5. `jwt_obj:verify` is called without an `alg_whitelist`.
6. An `algorithms` allowlist contains `none`.
7. `get_unverified_header` / `get_unverified_claims` output drives an
   authorization decision.

## What to ignore

- `jwt.verify(...)` calls that include `algorithms: [...]`,
  `audience`, and `issuer` checks.
- Tests / fixtures / mock files.
- JWT helper utilities that delegate to a library and pass through
  the caller's options.
- `jwt_obj:verify` calls that pass an `alg_whitelist` naming a
  concrete algorithm.
- Unverified header reads used only to pick a JWKS key, where the
  token is verified afterwards.

## Examples

True positives:
```ts
// No algorithm pinning
const decoded = jwt.verify(token, process.env.JWT_PUBLIC_KEY);

// alg: none in sign
jwt.sign(payload, "secret", { algorithm: "none" });

// Hardcoded weak secret
jwt.sign({ userId }, "supersecret");

// Token stored in localStorage
localStorage.setItem("jwt", response.token);

// Missing audience / issuer
const claims = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
// No audience check — token from another service of ours is accepted
```
```lua
-- No alg_whitelist
local ok, err = jwt_obj:verify(secret, token)
```
```py
# 'none' in the allowlist
jwt.decode(token, key, algorithms=["RS256", "none"])
```

False positives to skip:
```ts
// Well-configured verification
const { payload } = await jwtVerify(token, key, {
  algorithms: ["RS256"],
  audience: "api.example.com",
  issuer: "auth.example.com",
});

// Test
it("verifies signed token", () => {
  const token = jwt.sign({}, "test-secret");
  expect(jwt.verify(token, "test-secret")).toBeTruthy();
});

// Wrapper that requires the caller to specify the algorithm
function verify(token, opts: { algorithms: string[] }) {
  return jwt.verify(token, getKey(), opts);
}
```
```lua
-- Algorithm pinned
jwt_obj:set_alg_whitelist({ RS256 = 1 })
local ok, err = jwt_obj:verify(public_key, token)
```
