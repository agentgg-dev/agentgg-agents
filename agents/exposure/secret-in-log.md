---
slug: secret-in-log
name: Secrets in Logs or Error Messages
description: 'Credentials, tokens, passwords, API keys, or freshly decrypted plaintext passed to console.log, logger calls, JSON.stringify, HTTP response bodies, or error message bodies — secrets persist in log aggregation systems and crash reports.'
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
  - CWE-201
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

**Go logging and error sinks:**
```go
log.Info("token=", token)
log.Printf("got %s", apiKey)
fmt.Errorf("auth failed: %s", secret)
```

**Decrypted plaintext reaching a sink:**
```ts
console.log(plaintext);
logger.info({ decryptedSecret, userId });
res.json({ value: decryptResponse.plaintext });
throw new Error(`decrypt failed: ${decryptedValue}`);
```
A value that was just decrypted is as sensitive as the ciphertext it
came from. Once it is written to a log, returned in an HTTP response
body, or interpolated into a thrown `Error`, the decryption is undone
for anyone reading the log or the error. Treat the decrypt call as the
start of a scope the plaintext must not leave.

**Variable names that signal "secret":**
`token`, `accessToken`, `refreshToken`, `idToken`, `secret`,
`apiKey`, `api_key`, `password`, `passwd`, `credential`,
`privateKey`, `bearerToken`, `sessionId` (sometimes — depends on
domain).

**Post-decrypt value names:**
`plaintext`, `decryptedValue`, `decryptedSecret`, `decryptedEnv`,
`decryptResponse.plaintext`, `result.plaintext`, and anything named
`decrypted*` or named after a known secret once a decrypt call has
produced it.

## True positive criteria

Flag when BOTH of the following hold:

1. The line is a logger, console, error-throw, or HTTP response
   call. In Go this covers `log.Info`, `log.Printf`, and
   `fmt.Errorf`.
2. An argument or interpolated value uses a secret-shaped or
   post-decrypt variable name from the lists above (or a property
   access ending in such a name, e.g.,
   `req.headers.authorization`, `user.passwordHash`,
   `decryptResponse.plaintext`).

## What to ignore

- Logging a redacted value: `console.log("token: <redacted>")`,
  `logger.info({ tokenPrefix: token.slice(0, 6) })`.
- Logging metadata about a secret: `console.log("token length:", token.length)`.
- Logging a hash / fingerprint rather than the raw value:
  `logger.info({ tokenHash: sha256(token) })`.
- Test fixtures / mock servers.
- Type definitions / interfaces that mention secrets without using
  them.
- The decrypt call itself, before the plaintext is used anywhere.
- Plaintext passed into another internal function that scopes its
  lifetime, such as a `useSecret(plaintext, () => {...})` wrapper, or
  used only as input to crypto: `const ct = await encrypt(plaintext);`.
- Length or emptiness checks on a plaintext that is never written out.

## Examples

True positives:
```ts
console.log("Bearer token:", req.headers.authorization);
logger.error("api call failed", { apiKey, error });
throw new Error(`Stripe key invalid: ${stripeKey}`);
res.json({ debug: { token, user } });
return Response.json({ secret: decryptResponse.plaintext });
if (!ok) throw new Error(`decrypt failed: ${plaintext}`);
```

```go
log.Printf("decrypted=%s", plaintext)
fmt.Errorf("failed with plaintext %s", plaintext)
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
