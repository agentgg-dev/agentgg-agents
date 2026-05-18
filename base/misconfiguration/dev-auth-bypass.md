---
slug: dev-auth-bypass
name: Development Auth Bypass Reachable in Production
description: Dev/test login endpoints, NODE_ENV=development guards, hardcoded test tokens, or mock session helpers that bypass auth — reachable in production if NODE_ENV isn't actually set or the deploy doesn't strip them. Walker mode follows mock helpers and env-flag definitions.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
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
  - regex: "(NODE_ENV|isDev|IS_TEST|isTest)\\s*(===|==|!==|!=)\\s*[\"'](development|test|dev)[\"']"
    label: "NODE_ENV / isDev / IS_TEST guard"
  - regex: "(createMockSession|mockSession|fakeUser|devLogin|testLogin)\\s*\\("
    label: "Mock-session / dev-login helper"
  - regex: "[\"'](test_api_key|test-token|dev-token|bypass-secret)[\"']"
    label: "Hardcoded test token literal"
  - regex: "(app|router)\\.(get|post|use)\\s*\\(\\s*[\"']/(dev|test|debug|internal)/"
    label: "Route registered under /dev /test /debug /internal"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-489
  - CWE-1188
  - OWASP-A05:2021
---

You are reviewing source code for "dev only" or "test only" auth
shortcuts that ship with the production build. The fix in source is
usually "don't ship this," but if it's in the codebase, it can be
reachable if:
- `NODE_ENV` is not set in a production deployment
- The deploy doesn't tree-shake the dev paths
- An attacker can flip `NODE_ENV` via env injection

**Walker mode advantage:** the candidate may use a `createMockSession`
or `devAuth()` helper imported from a `dev-tools/` module. Open the
helper to confirm it actually grants admin or skips checks. Also
verify whether the `NODE_ENV` branch sets user state (a finding) or
just logs (not a finding).

## What to look for

**Dev-only login / token endpoints:**
```ts
app.post("/auth/dev", (req, res) => res.json({ token: "dev-token" }));
router.get("/dev/login", devLoginHandler);
app.post("/test/auth/login", testLoginHandler);
```

**NODE_ENV / IS_TEST / isDev guards that skip auth:**
```ts
if (NODE_ENV === "development") return skipAuthMiddleware();
if (NODE_ENV === "test") return mockAuthResponse();
if (isDev) {
  ctx.user = { id: 1, role: "admin" };
}
if (IS_TEST) return adminUser;
```

**Hardcoded test tokens / API keys:**
```ts
if (apiKey === "test_api_key_12345") return ok();
const token = headers.get("test-token") || "";
```

**Mock session injection:**
```ts
const session = createMockSession({ userId: 1 });
ctx.session = mockSession;
```

## True positive criteria

Flag when ANY of the following hold:

1. A handler file declares a route under `/dev`, `/test`, `/debug`,
   `/internal` that returns auth credentials or skips auth.
2. A guard checks `NODE_ENV === "development"` /
   `NODE_ENV === "test"` / `isDev` / `IS_TEST` AND inside the guard
   sets a user, skips auth, returns a token, or grants admin.
3. A hardcoded token string is compared against an inbound credential
   (`apiKey === "test_api_key_12345"`).
4. A mock session factory is called in production-reachable code.

## What to ignore

- Dev tooling fully isolated in a folder excluded from the build
  (e.g., `dev-server/` not imported by `app/`).
- Test files (`*.test.ts`, `__tests__/`, `*.spec.ts`).
- Guard blocks where the body only logs / mocks data and doesn't
  affect auth state.
- Mock session factories used only in tests.

## Examples

True positives:
```ts
// /dev/login — returns a token
app.post("/dev/login", (req, res) => {
  res.json({ token: jwt.sign({ id: 1, admin: true }, secret) });
});

// NODE_ENV bypass
if (process.env.NODE_ENV === "development") {
  ctx.user = { id: 1, role: "admin" };
  return next();
}

// Hardcoded test API key
if (apiKey === "test_api_key_12345") return { ok: true };

// Mock session
const session = createMockSession({ userId: "admin-user" });
ctx.session = session;
```

False positives to skip:
```ts
// Logging only — no auth state change
if (process.env.NODE_ENV === "development") {
  console.log("dev mode active");
}

// Real test file
// auth.test.ts
const session = createMockSession({ userId: 1 });
```
