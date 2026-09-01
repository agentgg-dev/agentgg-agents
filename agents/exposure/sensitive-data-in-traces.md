---
slug: sensitive-data-in-traces
name: Sensitive Data in Observability Traces
description: 'PII, passwords, credit cards, secrets, or tokens passed as attributes to OpenTelemetry spans, Datadog tracer, Sentry contexts, or other observability tools — data persists in third-party trace storage.'
version: 0.1.0
author: agentgg
noiseTier: normal
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
      - go
      - java
      - kt
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - go
    - java
    - kt
  preFilter:
    - semgrepRule: exposure/sensitive-data-in-traces
      label: Sensitive-named variable passed to a span attribute or Sentry context
references:
  - CWE-359
  - CWE-532
  - 'OWASP-A09:2021'
---

You are reviewing source code for sensitive data being attached to
observability traces — OpenTelemetry, Datadog, Sentry, New Relic,
Honeycomb. The data ends up in third-party trace storage where it
persists indefinitely, is searchable by anyone with trace-tool
access, and may be exported to other systems.

## What to look for

**OpenTelemetry span attributes / events:**
```ts
span.setAttribute("payload", req.body);
span.setAttribute("secret", token);
span.addEvent("payment.received", { card: req.body.creditCard });
```

**Datadog tracer:**
```ts
tracer.trace("charge", () => stripe.charge(card));
addTagsToCurrentSpan({ user: req.body });
span.setTag("payload", req.body);
```

**Sentry contexts:**
```ts
Sentry.captureException(err, { extra: { password, apiKey } });
Sentry.setContext("billing", invoice);
Sentry.setExtra("credential", credential);
Sentry.setUser({ email, ssn });   // PII in user context
```

**Datadog log injection / structured logs:**
```ts
ddLogger.info({ token, sessionId });
```

**Variable / property names that signal sensitive data:**
- Auth: `token`, `accessToken`, `refreshToken`, `apiKey`, `password`,
  `secret`, `credential`, `bearerToken`, `privateKey`, `jwt`
- Payment: `creditCard`, `cardNumber`, `cvc`, `cvv`, `iban`,
  `routingNumber`, `accountNumber`
- PII: `ssn`, `taxId`, `nationalId`, `dateOfBirth`, `dob`,
  `passport`, `driverLicense`
- Whole request bodies: `req.body`, `request.body`, `request.json`
  (often contain a mix of all the above)

## True positive criteria

Flag when BOTH of the following hold:

1. An observability call is made: `span.setAttribute`, `span.addEvent`,
   `tracer.trace`, `addTagsToCurrentSpan`, `setTag`, `Sentry.setContext`,
   `Sentry.setExtra`, `Sentry.captureException` (with extras),
   `Sentry.setUser` (with PII).
2. The argument or attribute value is a sensitive-named variable, a
   property access ending in one of the names above, or a raw
   request body / headers object.

## What to ignore

- Tracing metadata that is genuinely safe: HTTP method, route,
  status code, duration, error class name.
- IDs that are opaque tokens, not the secret itself (`userId`,
  `requestId`, `traceId`).
- Sentry user context with `id` only and no PII.
- Test / mock servers.

## Examples

True positives:
```ts
// Sentry context with credential
Sentry.setExtra("credential", credential);

// Span attribute with full body
span.setAttribute("body", JSON.stringify(req.body));

// Datadog tag with token
addTagsToCurrentSpan({ token });

// Sentry user with PII
Sentry.setUser({ id, email, ssn: user.ssn });
```

False positives to skip:
```ts
// Safe metadata
span.setAttribute("http.method", req.method);
span.setAttribute("http.status_code", res.statusCode);
span.setAttribute("user.id", session.userId);

// Sentry with ID only
Sentry.setUser({ id: session.userId });

// Tracing wraps the call, doesn't pass sensitive data as a tag
tracer.trace("charge", () => stripe.charge(card));   // OK if no PII in tags
```
