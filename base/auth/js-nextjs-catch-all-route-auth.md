---
slug: js-nextjs-catch-all-route-auth
name: Next.js Catch-All Route Auth Coverage
description: Next.js catch-all routes ([...slug], [[...rest]]) and Payload CMS / GraphQL endpoints — auth must cover every sub-path, not just the explicit ones in the codebase. Walker mode follows route handlers and HOF wrappers.
version: 0.1.0
author: agentgg
mode: walker
tech: [nextjs]
noiseTier: precise
outputType: finding
filePatterns:
  - "**/[[...rest]]/**/*.{ts,tsx}"
  - "**/[...slug]/**/*.{ts,tsx}"
  - "**/[...path]/**/*.{ts,tsx}"
  - "**/(payload)/**/*.{ts,tsx}"
  - "**/graphql/route.{ts,tsx}"
  - "**/app/api/**/*.{ts,tsx}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "export\\s+(async\\s+function|const|function)\\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\b"
    label: "App Router HTTP handler export"
  - regex: "export\\s+default\\s+(async\\s+)?function\\s+handler"
    label: "Pages Router default handler"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-862
  - OWASP-A01:2021
---

You are reviewing Next.js catch-all route handlers ([...slug],
[[...rest]]) and aggregate endpoints (Payload CMS, GraphQL) for
missing auth coverage. The risk: the route catches every sub-path the
file system rule matches, and an auth check that only covers some
sub-paths leaves the rest exposed.

**Walker mode advantage:** catch-all dispatchers commonly delegate
to a registry of sub-handlers (`payloadHandler`, `executeGraphQL`,
`adminRoutes`). Follow the import to verify whether the delegated
function performs per-request auth, or whether it accepts whatever
comes in. Also check for an HOF wrapper (`withAuth(catchAllHandler)`)
defined elsewhere — open the wrapper to confirm it enforces auth.

## Why catch-all routes are special

A handler in `app/api/[[...rest]]/route.ts` serves every URL under
`/api/`. If the handler dispatches internally based on the path
segments, every dispatch branch must be auth-gated. A single early
branch returning without auth is a public endpoint.

Payload CMS embeds its admin routes under a `(payload)` group;
GraphQL endpoints accept arbitrary queries (each query is effectively
a sub-endpoint). The same logic applies: one auth check at the
entrance must cover every code path.

## What to look for

**Catch-all route handler with no auth call:**
```ts
// app/api/[[...rest]]/route.ts
export async function GET(request: Request) {
  // No auth — every /api/* path served by this handler is public
  return Response.json({ data: await loadData(request.url) });
}
```

**Payload CMS routes:**
```ts
// app/(payload)/[[...slug]]/route.ts
export async function POST(req: Request) {
  return payloadHandler(req);   // Does payloadHandler require auth?
}
```

**GraphQL handler with no auth gate:**
```ts
// app/api/graphql/route.ts
export async function POST(req: Request) {
  const query = await req.text();
  return executeGraphQL(query);   // Per-field auth, or no auth at all?
}
```

**Auth indicators that, if PRESENT, address the issue:**
`withAuthentication(...)`, `getSession(...)`, `auth()`,
`requireAuth(...)`, `verifyToken(...)`, `withSchema(...)`.

## True positive criteria

Flag when ALL of the following hold:

1. The file path matches a catch-all pattern (`[[...]]`, `[...]`),
   the `(payload)` group, or a `graphql/route.ts`.
2. The file exports an HTTP handler (`GET`/`POST`/etc.).
3. No top-level auth call appears in the handler body and the
   handler is not wrapped in an auth HOF.

## What to ignore

- Catch-all routes that are public by design (file serving,
  documentation, embed previews).
- Handlers wrapped in an auth HOF: `withAuth(handler)`.
- Catch-all routes where the auth check is the first statement and
  reliably covers every branch.
- Test files.

## Examples

True positives:
```ts
// app/api/[[...rest]]/route.ts — public dispatcher
export async function GET(req: Request) {
  const path = new URL(req.url).pathname;
  if (path.startsWith("/api/admin")) return handleAdmin(req);
  return handlePublic(req);
  // Admin branch is reachable without auth
}

// app/(payload)/[[...slug]]/route.ts
export const GET = REST_GET(config);   // depends on Payload's own auth
export const POST = REST_POST(config);
// Verify Payload's per-handler auth covers all collections
```

False positives to skip:
```ts
// First statement is auth; covers every branch
export async function POST(req: Request) {
  const session = await getSession();
  if (!session) return new Response("401", { status: 401 });
  return dispatch(req, session);
}

// Wrapped in HOF
export const GET = withAuth(catchAllHandler);
```
