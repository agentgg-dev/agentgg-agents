---
slug: missing-auth
name: Missing Authentication on Endpoint
description: HTTP route handlers (Next.js App Router exports, Express handlers, pages/api default exports) with no authentication check — every export reachable without a session is a public endpoint. Walker mode follows middleware and HOFs across files.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/api/**/*.{ts,tsx,js,jsx}"
  - "**/app/api/**/*.{ts,tsx,js,jsx}"
  - "**/pages/api/**/*.{ts,tsx,js,jsx}"
  - "**/routes/**/*.{ts,tsx,js,jsx}"
  - "**/server/**/*.{ts,tsx,js,jsx}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "export\\s+(async\\s+function|const|function)\\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\b"
    label: "App Router HTTP method export"
  - regex: "export\\s+default\\s+(async\\s+)?function\\s+handler"
    label: "Pages Router default handler"
  - regex: "(app|router|fastify)\\.(get|post|put|patch|delete|use)\\s*\\(\\s*[\"'][^\"']*[\"']"
    label: "Express/Fastify route registration"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-306
  - OWASP-A01:2021
---

You are reviewing HTTP route handlers for missing authentication —
endpoints that handle requests but never call an auth verifier, so
every caller is treated as authorized regardless of session.

**Walker mode advantage:** an unguarded-looking handler may be wrapped
by an HOF (`withAuth(handler)`) or covered by middleware (`middleware.ts`,
an Express `app.use(authMiddleware)`). Open those before reporting:
read the HOF to confirm it enforces auth, and for Next.js verify the
middleware matcher actually covers the candidate route.

## What to look for

**Next.js App Router route handlers:**
```ts
// app/api/users/route.ts
export async function GET(req: Request) {
  return Response.json(await db.users.findMany());
}
```
No auth call. Anyone can hit this endpoint.

**Next.js Pages Router default export:**
```ts
// pages/api/users.ts
export default async function handler(req, res) {
  res.json(await db.users.findMany());
}
```

**Express / Koa / Fastify route definitions:**
```ts
router.get("/items", (req, res) => res.json(items));
app.post("/login", handler);
fastify.get("/users", async () => users);
```

**Auth indicators that, if PRESENT, mean the endpoint is protected:**
- `getSession(...)`, `auth()`, `requireAuth(...)`, `withAuth(...)`,
  `withAuthentication(...)`, `withSchema(...)`, `verifyToken(...)`,
  `parseAuthToken(...)`, `isAuthenticated(...)`, `assertAuth(...)`
- Middleware wrappers around the handler: `withAuth(handler)`,
  `requireUser(handler)`.
- A check on the result: `if (!session?.user) return 401;`.

If none of these appear in the file (and no middleware wraps the
handler), it is a candidate for missing auth.

## True positive criteria

Flag when ALL of the following hold:

1. A file exports an HTTP handler (Next.js App Router `GET/POST/...`,
   Pages Router default export, Express `app.get/post/...`,
   Fastify/Koa route).
2. The handler body does not call an auth verifier and is not wrapped
   in an auth middleware/HOF.
3. The endpoint is not explicitly marked as public (e.g., `/health`,
   `/version`, `/api/public/*`, login/registration endpoints).

## What to ignore

- Genuinely public endpoints: `/api/health`, `/api/version`,
  `/api/sign-in`, `/api/sign-up`, `/api/forgot-password`, webhooks
  with their own signature verification (flag those under
  `webhook-handler` instead).
- Static asset serving handlers.
- Handlers wrapped in an auth HOF: `withAuth(handler)`.
- Files where the auth check is in a parent middleware that
  unambiguously covers this route — but **only trust this if the
  middleware is clearly present and routes are not bypass-able**
  (see `js-nextjs-middleware-only-auth` for the failure mode).
- Test files / fixtures.

## Examples

True positives:
```ts
// app/api/users/route.ts — no auth
export async function GET() {
  const users = await db.users.findMany();
  return Response.json(users);
}

// pages/api/admin.ts — no auth on admin action
export default async function handler(req, res) {
  await db.users.delete({ where: { id: req.query.id } });
  res.json({ ok: true });
}

// Express — public endpoint with sensitive operation
app.post("/api/transfer", (req, res) => {
  return performTransfer(req.body);
});
```

False positives to skip:
```ts
// Auth check present
export async function GET() {
  const session = await auth();
  if (!session?.user) return new Response("401", { status: 401 });
  return Response.json(await db.users.findMany());
}

// Wrapped in HOF
export const GET = withAuth(async (req, session) => {
  return Response.json({ user: session.user });
});

// Public by design
export async function GET() {
  return Response.json({ status: "ok" });  // /api/health
}
```
