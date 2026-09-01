---
slug: secrets-plaintext-exposure
name: Decrypted Plaintext Exposure
description: 'Decrypted secret values (decryptedValue, plaintext, decryptResponse.plaintext) flowing into logs, HTTP response bodies, error messages, or trace spans.'
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
      - go
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - go
  preFilter:
    - semgrepRule: exposure/secret-in-log
      label: Decrypted value or secret-named variable flowing to a log or response sink
references:
  - CWE-532
  - CWE-201
  - 'OWASP-A02:2021'
---

You are reviewing source code that handles decrypted secrets — and
looking for places where the plaintext value flows into a sink that
persists, transmits, or transmits-to-third-party the plaintext:
logger calls, HTTP response bodies, error strings, or observability
spans.

## What to look for

**Plaintext / decrypted variable names:**
- `plaintext`, `decryptedValue`, `decryptedSecret`, `decryptedEnv`,
  `decryptResponse.plaintext`, `result.plaintext`
- Anything explicitly named `decrypted*` or named after a known
  secret (`apiKey`, `password`, `token`) AFTER a decrypt call

**Sink categories:**

1. **Logger / console:**
   ```ts
   console.log(plaintext);
   logger.info({ plaintext });
   logger.error("got", decryptedSecret);
   ```
2. **HTTP response body:**
   ```ts
   res.json({ value: decryptResponse.plaintext });
   response.send(plaintext);
   reply.send(decryptedValue);
   ```
3. **Error messages thrown to the caller:**
   ```ts
   throw new Error(`failed: ${plaintext}`);
   ```
4. **Trace / span attributes (Sentry, Datadog, OTel):**
   ```ts
   span.setAttribute("v", plaintext);
   span.recordException(decryptedSecret);
   ```
5. **Go equivalents:**
   ```go
   log.Info("plaintext=", plaintext)
   log.Printf("got %s", plaintext)
   fmt.Errorf("err: %s", plaintext)
   ```

## True positive criteria

Flag when BOTH of the following hold:

1. A variable named `plaintext`, `decryptedValue`, `decryptedSecret`,
   `decryptedEnv`, `decryptResponse.plaintext`, or similar appears
   in the line.
2. The line is a logger call (`console.*`, `logger.*`, `log.*`),
   HTTP response (`res.json`, `res.send`, `reply.send`), thrown
   `Error()`, or observability call (`span.set*`, `Sentry.*`).

## What to ignore

- The line that initially decrypts the value, before it's used.
- Cases where the plaintext is passed to another internal function
  by reference (e.g., a `useSecret(plaintext, () => {...})`
  wrapper that scopes the secret's lifetime).
- Test files.

## Examples

True positives:
```ts
// Logger
console.log(plaintext);
logger.info({ plaintext, userId });

// Response body
return Response.json({ secret: decryptResponse.plaintext });

// Error message
if (!ok) throw new Error(`decrypt failed: ${plaintext}`);

// Span
span.setAttribute("api_key", decryptedSecret);
```

```go
log.Printf("decrypted=%s", plaintext)
fmt.Errorf("failed with plaintext %s", plaintext)
```

False positives to skip:
```ts
// Plaintext used as input to crypto, not logged
const ciphertext = await encrypt(plaintext);

// Length checked, value not logged
if (plaintext.length === 0) throw new Error("empty value");
```
