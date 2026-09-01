---
slug: two-factor-bypass-deep
name: Two-Factor Authentication Bypass (Deep)
description: '2FA / MFA verification steps that can be skipped — full session granted before the second factor is validated, the second-factor endpoint trusts client-supplied "verified" flags, brute-forceable OTP codes, or step-up paths that don''t gate sensitive actions. Reads the auth flow across login, verify, and session-issuance handlers.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: (totp|otp|mfa|twoFactor|two_factor|2fa)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
        label: 2FA reference
      - regex: (speakeasy|otplib|@otplib|pyotp|rotp|node-2fa)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
        label: TOTP library
      - regex: (verifyToken|verifyOtp|verify_otp|verifyMfa|verifyTwoFactor)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
        label: 2FA verification call
      - regex: (jwt\.sign|createSession|issueToken|setSession)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
        label: Session/token issuance
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - php
    - java
    - kt
    - cs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
    - '**/node_modules/**'
  preFilter:
    - semgrepRule: auth/totp-verification
      label: TOTP/OTP verify call or session issuance after MFA check
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-287
  - CWE-308
  - 'OWASP-A07:2021'
---

You are reviewing the multi-step authentication flow for 2FA / MFA
bypass — patterns where the second factor can be skipped, bypassed,
or made trivial to brute-force.

**Cross-file analysis:** 2FA flows span at least three files —
`POST /login` (validates password), `POST /verify-2fa` (validates
TOTP), and the session-issuance helper. The bug is usually in how
state is passed between them. Read the whole flow, not just one file.

## What you're hunting for

**1. Full session issued before 2FA verification.**
```ts
// /login
const ok = await comparePassword(req.body.password, user.password);
if (ok) {
  const token = jwt.sign({ userId: user.id }, SECRET);    // already a real session
  return res.json({ token, requires2fa: user.totpSecret != null });
}
```
The client receives a real authenticated token and is supposed to
"voluntarily" call `/verify-2fa` afterward. Anyone can ignore that
step. The signal: `requires2fa` flag in the response but the token
is already valid for protected endpoints.

**2. 2FA verification endpoint trusts a client-supplied user ID.**
```ts
// /verify-2fa
const { userId, code } = req.body;
const user = await User.findByPk(userId);
if (verifyTotp(user.totpSecret, code)) {
  return res.json({ token: jwt.sign({ userId, mfaPassed: true }, SECRET) });
}
```
The handler doesn't verify a partial-auth token; the attacker can
submit any `userId` with a guessed code (especially if combined with
no rate limit).

**3. `mfaPassed` flag in the JWT/session is client-settable or
self-signed.**
```ts
const token = jwt.sign({ userId, mfaPassed: req.body.mfa === "yes" }, SECRET);
```
or trusting a client header `X-2FA-Verified: true`.

**4. No rate limit on OTP submission.** TOTP is 6 digits → 10 to the power of 6 space.
Without rate limiting and account lockout, brute-force is trivial.

**5. 2FA enrollment lets attackers enroll their own secret on a
victim account** during a partial-auth flow.

**6. Recovery-code flow that doesn't burn the used code.**

**7. "Remember this device" tokens that never expire or are not
tied to the device's binding (cookie value reusable from any
browser).**

**8. Protected actions that don't require step-up.** Listing 2FA as
"enabled" but the change-email / change-password / disable-2FA
endpoints don't require recent re-auth.

## How to investigate

1. Find the login handler. Identify what it issues when password is
   correct AND `totpSecret` is set on the user.
2. Find the 2FA verification handler. What does it trust to identify
   the user? A short-lived partial-auth token bound to the userId at
   step 1? Or `req.body.userId`?
3. Find the session/token issuer. Is `mfaPassed`/`amr=["mfa"]` set
   only after successful TOTP verify, or is it derivable from request
   input?
4. Find the OTP rate-limit / lockout — `express-rate-limit`,
   `lockoutAfterNAttempts`. Absence is a finding.
5. Find the disable-2FA / change-password / change-email handlers.
   Do they require recent-auth or current-password? Or just a valid
   session?

## True positive criteria

Flag when ANY of the following hold:

1. `/login` issues a session/JWT that is accepted by protected
   endpoints **before** 2FA is verified.
2. `/verify-2fa` trusts `userId` (or equivalent) from request input
   instead of from a partial-auth token bound to the password step.
3. The "MFA passed" assertion in the session/JWT is settable by the
   client or absent entirely.
4. No rate limit / lockout on OTP submission (`>` ~5 attempts /
   minute on a 6-digit code = brute-forceable).
5. Sensitive flows (disable-2FA, change-email, change-password) do
   not require step-up / recent re-auth.

## What to ignore

- Single-factor systems with no 2FA wiring at all (different bug
  class — not "bypass", just "absent").
- TOTP verify endpoints that take a partial-auth token (one-time, TTL
  <= a few minutes, bound to userId), validate the code, and only then
  swap it for a full session — that's the correct shape.
- Test fixtures.

## Examples

True positives:
```ts
// Full token issued before 2FA — /login
const valid = await argon2.verify(user.password, req.body.password);
if (valid) {
  return res.json({
    token: jwt.sign({ sub: user.id }, SECRET),    // unrestricted token
    requires2fa: !!user.totpSecret,
  });
}

// Verify endpoint trusts request userId
app.post("/verify-2fa", async (req, res) => {
  const u = await User.findByPk(req.body.userId);
  if (verifyTotp(u.totpSecret, req.body.code)) {
    return res.json({ ok: true });   // session already exists from /login
  }
  res.sendStatus(401);
});
```

False positives to skip:
```ts
// /login — issues a SHORT partial-auth token bound to the userId
if (valid && user.totpSecret) {
  const partial = jwt.sign(
    { sub: user.id, scope: "mfa-pending", purpose: "verify-2fa" },
    SECRET,
    { expiresIn: "5m" },
  );
  return res.json({ partialToken: partial, requires2fa: true });
}

// /verify-2fa — derives userId from the partial token only
const partial = verify(req.headers.authorization, SECRET);
if (partial.scope !== "mfa-pending") return res.sendStatus(401);
if (!await rateLimiter.allow(partial.sub)) return res.sendStatus(429);
if (verifyTotp(user.totpSecret, req.body.code)) {
  return res.json({
    token: jwt.sign({ sub: partial.sub, amr: ["pwd", "mfa"] }, SECRET),
  });
}
```

The most reliable test: "if I never call /verify-2fa, what protected
endpoints can I hit with the response from /login?" If the answer is
"all of them", it's a bypass.
