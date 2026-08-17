---
slug: js-nextjs-middleware-only-auth
name: Next.js Middleware-Only Auth
description: 'Next.js route handlers under a "protected" route group with no per-handler auth check, relying solely on middleware.ts — bypassable via direct RSC fetch or by middleware misconfiguration. Reads middleware.ts and verifies its matcher covers the route.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: export\s+(async\s+function|const|function)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b
        in:
          - '**/app/**/route.{ts,tsx}'
          - '**/app/api/**/route.{ts,tsx}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: App Router HTTP method export
  prompt: Run only if this project uses nextjs — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  filePatterns:
    - '**/app/**/route.{ts,tsx}'
    - '**/app/api/**/route.{ts,tsx}'
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: export\s+(async\s+function|const|function)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b
      label: App Router HTTP method export
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-862
  - 'OWASP-A01:2021'
---

You are reviewing Next.js App Router route handlers that have no
per-handler authentication check, apparently relying on the global
`middleware.ts` to guard them. This is a real risk:

**Cross-file analysis:** this finding is inherently cross-file.
For each candidate handler, locate the project's `middleware.ts`
(usually at the project root or `src/`) and read its `matcher` config.
Verify whether the candidate's route is actually covered, and whether
the middleware enforces auth (vs. only doing redirects, geo checks,
header rewriting). A handler is unsafe if the matcher excludes it or
if the middleware doesn't actually verify a session.

Why this matters:

1. Middleware can be misconfigured (matcher excludes the route).
2. Internal RSC fetches and the experimental
   `x-middleware-subrequest` header can skip middleware in some
   Next.js versions.
3. A new route added to the protected group is silently public if
   no one updates the middleware matcher.

Defense-in-depth means each handler should also check auth.

## What to look for

**Route handler in a `(protected)`, `(dashboard)`, `(auth)` group
with no auth check:**
```ts
// app/(dashboard)/api/users/route.ts
export async function GET(req: Request) {
  return Response.json(await db.users.findMany());
}
```
The path implies protection. The handler does not enforce it.

**Auth indicators that, if PRESENT, address the issue:**
`getSession(...)`, `auth(...)`, `requireAuth(...)`,
`withAuth(...)`, `verifyToken(...)`, `parseAuthToken(...)`,
`withSchema(...)`, `withAuthentication(...)`.

## True positive criteria

Flag when ALL of the following hold:

1. The file is named `route.ts` / `route.tsx` under an `app/`
   directory.
2. The directory path includes a route group `(protected)`,
   `(dashboard)`, `(auth)`, `(admin)`, or the file is under
   `app/api/`.
3. The handler body and surrounding file do not call an auth
   verifier and are not wrapped in an auth HOF.

## What to ignore

- Handlers that include any auth verification call.
- Handlers wrapped in an auth HOF.
- Public endpoints inside an `api/public/` subfolder.
- Test files.

## Examples

True positives:
```ts
// app/(protected)/api/projects/route.ts — no auth
export async function GET() {
  return Response.json(await db.projects.findMany());
}

// app/api/users/route.ts — no auth
export const POST = async (req: Request) => {
  await db.users.create({ data: await req.json() });
  return Response.json({ ok: true });
};
```

False positives to skip:
```ts
// Auth check present
export async function GET() {
  const session = await auth();
  if (!session?.user) return new Response("401", { status: 401 });
  return Response.json(await db.projects.findMany());
}

// Wrapped
export const GET = withAuth(async (req, session) => { ... });
```
