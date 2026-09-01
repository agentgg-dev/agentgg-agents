---
slug: deprecated-endpoint
name: Deprecated / Legacy Endpoint Still Mounted
description: 'Routes documented as deprecated, legacy, or "old API" that are still registered on the router — often retaining weaker auth, unsafer parsers, or test-only credentials that pre-date current security hardening.'
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
      - php
      - java
      - kt
      - cs
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
  preFilter:
    - semgrepRule: shared/http-endpoints
      label: HTTP route registration or handler function
references:
  - CWE-1059
  - CWE-477
  - 'OWASP-A05:2021'
---

You are reviewing source code for **deprecated endpoints that are still
reachable** — handlers explicitly labeled "deprecated", "legacy",
"old", "v1" (when the rest of the app is v2+), or "remove after",
that are still wired into the router.

The risk is structural: deprecated paths usually pre-date current auth
middleware, current input validation, current rate limits, or current
content-type filtering. Even if they once worked correctly, the rest
of the app has moved on around them and they accrete vulnerabilities
by omission.

## What to look for

**Comments / log lines / response text that name the endpoint as
deprecated:**
```ts
// DEPRECATED: B2B XML upload — kept for legacy customers
app.post("/b2b/v1/complaints", handleXmlUpload);

// Legacy login — remove after Q3 migration
app.post("/auth/legacy", legacyLogin);

res.status(410).send("This endpoint is deprecated.");
//   ^ Gone status returned, but next() called — handler still runs
```

**Routes named `/v1/`, `/legacy/`, `/old/`, `/_internal/`, `/support/`
when newer versions exist elsewhere:**
```ts
app.post("/api/v1/...", handler);
app.use("/api/v2/...", v2Router);
// v1 still mounted; v2 is the supported path
```

**Handlers that respond with `410 Gone` or a deprecation notice but
then call `next()` or continue processing:**
```ts
function handleXmlUpload(req, res, next) {
  // ...
  res.status(410);
  next(new Error("...deprecated..."));
  // The error handler may render the parser output, leaking it.
}
```

**Routes guarded behind a feature flag that's enabled by default in
production:**
```ts
if (config.legacyApiEnabled) {
  app.use("/legacy", legacyRouter);
}
```

**Hardcoded support / debug / legacy credentials:**
```ts
if (req.body.email === "support@example.com" && req.body.password === "L3g4cy!") {
  // login as support team — predates SSO migration
}
```

## True positive criteria

Flag when ALL of the following hold:

1. A handler, route registration, or middleware references itself as
   deprecated/legacy/old (via comment, response text, header
   `Deprecation: true`, or a name like `legacyXxx`).
2. The route is actually registered (an `app.use` / `router.post` /
   `@RequestMapping` line is reachable, not commented out).
3. The handler still executes meaningful work — parses input, queries
   the DB, returns data, or sends mail — rather than returning an
   unconditional 410 with no side effects.

## What to ignore

- Routes wrapped in a hard `404` / `410` short-circuit that returns
  immediately and runs no business logic:
  ```ts
  app.post("/v1/foo", (req, res) => res.status(410).end());
  ```
- Genuinely versioned APIs where v1 is supported policy (e.g., 12-month
  deprecation window communicated to customers and reflected in CI).
- Endpoints renamed `legacyXxx` in code for refactoring purposes but
  still under active use as the primary API.
- Test files.

## Examples

True positives:
```ts
// DEPRECATED comment, but handler still parses XML (XXE territory)
app.post("/b2b/v1/complaints", handleXmlUpload);   // see handleXmlUpload's logic

// Legacy login bypass via hardcoded support creds
app.post("/auth/support-login", (req, res) => {
  if (req.body.email === "support@example.com" && req.body.password === "L3g4cy!") {
    return res.json({ token: jwt.sign({ sub: "support", role: "admin" }, SECRET) });
  }
});

// 410 returned but handler still runs upstream work and leaks parse output
function handleYamlUpload(req, res, next) {
  const data = yaml.load(req.file.buffer.toString());   // YAML bomb risk + leaks
  res.status(410);
  next(new Error("Deprecated: " + JSON.stringify(data).slice(0, 400)));
}
```

False positives to skip:
```ts
// Hard 410, no side effects
app.all("/v1/*", (req, res) => res.status(410).end());

// Properly versioned with v2 explicitly preferred and v1 still supported by
// policy with full current auth/middleware coverage
app.use("/api/v1", currentMiddleware, v1Router);
app.use("/api/v2", currentMiddleware, v2Router);
```

When you see "deprecated" in a comment, treat the surrounding handler
as guilty until proven safe — check what it does, not what the comment
implies it doesn't do.
