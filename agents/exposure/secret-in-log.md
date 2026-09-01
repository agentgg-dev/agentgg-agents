---
slug: secret-in-log
name: Secrets in Logs or Error Messages
description: 'Credentials, tokens, passwords, or API keys passed to console.log, logger calls, JSON.stringify, or error message bodies — secrets persist in log aggregation systems and crash reports.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
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
      - cs
      - php
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
    - cs
    - php
  preFilter:
    - semgrepRule: exposure/secret-in-log
      label: Secret-named variable passed to a logging or response sink
references:
  - CWE-532
  - 'OWASP-A09:2021'
---

You are reviewing source code for credentials, tokens, passwords, or
API keys being written to log statements, error messages, or
serialized into JSON that ends up in logs or HTTP error responses.

## What to look for

**Logger / console with a secret-shaped value:**
```ts
console.log("token", token);
console.error("failed:", apiKey);
console.warn("auth", refreshToken);
console.info("got", accessToken);

logger.info({ secret });
logger.error({ password });
log.debug({ credential });
```

**JSON.stringify of an object that includes a secret:**
```ts
JSON.stringify({ token: t, user });
```

**Error message includes a secret:**
```ts
throw new Error("token=" + token);
throw new Error(`auth failed for ${apiKey}`);
```

**HTTP response returns a secret in an error body:**
```ts
res.json({ token });     // intentional? or oops?
res.send({ secret });
return { error: `missing token: ${token}` };
```

**Variable names that signal "secret":**
`token`, `accessToken`, `refreshToken`, `idToken`, `secret`,
`apiKey`, `api_key`, `password`, `passwd`, `credential`,
`privateKey`, `bearerToken`, `sessionId` (sometimes — depends on
domain).

## True positive criteria

Flag when BOTH of the following hold:

1. The line is a logger, console, error-throw, or HTTP response
   call.
2. An argument or interpolated value uses a secret-shaped variable
   name from the list above (or a property access ending in such a
   name, e.g., `req.headers.authorization`, `user.passwordHash`).

## What to ignore

- Logging a redacted value: `console.log("token: <redacted>")`,
  `logger.info({ tokenPrefix: token.slice(0, 6) })`.
- Logging metadata about a secret: `console.log("token length:", token.length)`.
- Logging a hash / fingerprint rather than the raw value:
  `logger.info({ tokenHash: sha256(token) })`.
- Test fixtures / mock servers.
- Type definitions / interfaces that mention secrets without using
  them.

## Examples

True positives:
```ts
console.log("Bearer token:", req.headers.authorization);
logger.error("api call failed", { apiKey, error });
throw new Error(`Stripe key invalid: ${stripeKey}`);
res.json({ debug: { token, user } });
```

False positives to skip:
```ts
// Redacted
console.log("token: <set>", token ? "yes" : "no");

// Metadata only
logger.info({ tokenLength: token.length, hasToken: !!token });

// Hashed
logger.info({ tokenFingerprint: sha256(token).slice(0, 8) });
```
