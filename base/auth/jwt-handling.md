---
slug: jwt-handling
name: JWT Handling (Signing, Verification, Key Management)
description: JWT signing and verification (jose, jsonwebtoken, custom) — verify algorithm pinning, key management, secret strength, and audience/issuer/expiration checks. Walker mode follows key sources and verifier helpers.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "jwt\\.(verify|sign|decode)\\s*\\("
    label: "jsonwebtoken jwt.verify/sign/decode call"
  - regex: "\\bjwtVerify\\s*\\(|new\\s+SignJWT\\s*\\(|\\bjwtDecrypt\\s*\\(|new\\s+EncryptJWT\\s*\\("
    label: "jose verify/sign/decrypt/encrypt call"
  - regex: "(verifyJwt|verifyJWT|signJwt|signJWT)\\s*\\("
    label: "Custom JWT helper"
  - regex: "split\\s*\\(\\s*[\"']\\.[\"']\\s*\\)|base64url|atob\\s*\\([^)]*\\."
    label: "Manual JWT decoding (split on '.', base64) — possible hand-rolled verifier"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-345
  - CWE-347
  - OWASP-A02:2021
---

You are reviewing source code that signs, verifies, encrypts, or
decrypts JWTs — looking for misconfigurations that lead to token
forgery or authentication bypass.

**Walker mode advantage:** the signing key and verifier options are
usually centralized in `lib/jwt.ts` or `auth/config.ts`. Open the
config to verify: is the key strong (env-sourced, not a default
fallback)? Are the verifier defaults pinning algorithms, audience,
and issuer? If the candidate file just calls `verifySession(token)`,
the actual config lives in the helper — read it.

This agent is the broad JWT review pass. The `algorithm-confusion`
agent is the more specific check for missing algorithm pinning.

## What to look for

**Algorithm not pinned at verification:**
```ts
jwt.verify(token, secret);                       // accepts any algorithm
await jwtVerify(token, key);                     // jose without algorithms option
```
Safe form: `jwt.verify(token, secret, { algorithms: ["RS256"] })`.

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

## What to ignore

- `jwt.verify(...)` calls that include `algorithms: [...]`,
  `audience`, and `issuer` checks.
- Tests / fixtures / mock files.
- JWT helper utilities that delegate to a library and pass through
  the caller's options.

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
```
