---
slug: security-behind-flag
name: Security Check Behind Feature Flag
description: 'Auth, CSRF, WAF, encryption, or signature verification gated by a feature flag (LaunchDarkly, Statsig, custom isEnabled) — disabling the flag turns off the protection without code changes. Follows flag helpers and verifier definitions.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: (LaunchDarkly|statsig|Optimizely|Unleash|growthbook)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go,java,kt}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Feature-flag provider reference
      - regex: \.(variation|checkGate|isEnabled|getFlag|getVariant)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go,java,kt}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Feature-flag check call
      - regex: \b(isEnabled|flag_enabled|flagFor|featureFlag)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go,java,kt}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Generic feature-flag helper
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
    - java
    - kt
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/spec/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: (LaunchDarkly|statsig|Optimizely|Unleash|growthbook)\b
      label: Feature-flag provider reference
    - regex: \.(variation|checkGate|isEnabled|getFlag|getVariant)\s*\(
      label: Feature-flag check call
    - regex: \b(isEnabled|flag_enabled|flagFor|featureFlag)\s*\(
      label: Generic feature-flag helper
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-693
  - 'OWASP-A05:2021'
---

You are reviewing source code for security checks gated by feature
flags. A feature flag that disables a security check is a switch
operators can flip without a deploy or PR — and remote configuration
systems (LaunchDarkly, Statsig, Optimizely, internal flag services)
are themselves potential attack surfaces.

**Cross-file analysis:** the body of the `if` may call a helper
like `requireAuth()` or `verifyCsrf()` — open it to confirm that's a
real security verb (not a logging or instrumentation helper). Also
check whether the unflagged path has a parallel baseline check; if
the baseline runs unconditionally, the flag is enabling EXTRA
hardening, not the only protection.

## The bug shape

```ts
if (LaunchDarkly.variation("rate-limit", false)) {
  throttle(req);
}
if (statsig.checkGate("csrf-check")) {
  validateCsrf(req);
}
if (flag_enabled("encryption")) {
  encrypt(payload);
}
if (isEnabled("auth-required")) {
  await verifyToken(req);
}
```
Each makes the security control optional. If the flag returns false
(intentionally or via a flag-service outage with a `false` default),
the protection silently disappears.

## What to look for

**Feature-flag function call wrapping a security verb:**
- Flag function names: `variation`, `checkGate`, `isEnabled`,
  `getFlag`, `flag_enabled`, `flagFor`, `getVariant`
- Provider namespaces: `LaunchDarkly`, `statsig`, `Optimizely`,
  `Unleash`, `featureFlags`, `flags`, `growthbook`
- Security verbs inside the `if`: `verify*`, `authenticate`,
  `authorize`, `validateCsrf`, `firewallCheck`, `encrypt`,
  `signRequest`, `checkSignature`, `throttle`, `rateLimit`,
  `sanitize*`, `escape*`.

## True positive criteria

Flag when ALL of the following hold:

1. A feature-flag check is the condition of an `if` or guard.
2. The block performs a security action: authentication,
   authorization, CSRF check, WAF check, encryption, signing,
   signature verification, rate limiting, input sanitization.

## What to ignore

- Feature flags used to control non-security functionality.
- Flags that ENABLE additional security checks (extra hardening
  gated by a flag is fine, as long as the baseline is always on).
- Flags used during a rollout where the unflagged path runs the
  existing security check too (look for a fallthrough).
- Test files.

## Examples

True positives:
```ts
if (LaunchDarkly.variation("require-mfa", false)) {
  await checkMfa(user);
}
// MFA is OFF when the flag returns false

if (isEnabled("auth-required")) {
  await verifyToken(req);
}
// Auth is OFF when "auth-required" is false

if (statsig.checkGate("validate-signature")) {
  if (!verifySignature(req)) return forbidden();
}
```

False positives to skip:
```ts
// Flag enables EXTRA hardening; base check still runs unconditionally
await verifyToken(req);
if (statsig.checkGate("require-mfa")) {
  await checkMfa(req);
}

// Non-security feature behind a flag
if (isEnabled("new-dashboard")) renderNewUi();
```
