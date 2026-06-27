---
slug: debug-endpoint
name: Debug / Test / Dev Endpoint Reachable in Production
description: 'HTTP handlers under /api/debug/, /api/test/, /api/dev/, or gated by x-debug / x-internal headers — these often leak internal state or skip auth and can be reachable in production.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    files:
      - '**/api/debug/**/*.{ts,tsx,js,jsx,mjs}'
      - '**/api/test/**/*.{ts,tsx,js,jsx,mjs}'
      - '**/api/dev/**/*.{ts,tsx,js,jsx,mjs}'
      - '**/api/**/*.{ts,tsx,js,jsx,mjs}'
      - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
where:
  filePatterns:
    - '**/api/debug/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/api/test/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/api/dev/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
references:
  - CWE-489
  - CWE-215
  - 'OWASP-A05:2021'
---

You are reviewing HTTP handlers that look like debug, test, or
development endpoints. The risk: these endpoints often skip auth,
dump internal state (env vars, DB rows, session contents), or expose
admin actions. If the deploy doesn't strip them, they're public in
production.

## What to look for

**Path-based indicators:**
- `app/api/debug/...`
- `app/api/test/...`
- `app/api/dev/...`
- Any route under a folder named `debug`, `dev`, `internal`,
  `_test`, `_dev`

**Comment / file content indicators:**
- `// debug endpoint`, `// dev only`, `// internal use only`
- `// development only — do not ship`
- `if (process.env.NODE_ENV !== "production")` gating the handler
  registration (good intent, but the file is still bundled)

**Header-based debug toggles:**
```ts
if (req.headers.get("x-debug")) return Response.json(state);
if (req.headers["x-internal"]) return dumpInternals();
```
A header that "unlocks" extra response data is a debug endpoint by
another name — if production routes accept the header, the data is
exposed.

**Common debug payloads to flag:**
- Returning `process.env` (or any subset)
- Returning the full DB row of any record by ID
- Allowing arbitrary SQL execution
- Allowing impersonation of arbitrary users
- Echoing the full request including headers

## True positive criteria

Flag when ANY of the following hold:

1. File path contains `debug`, `dev`, `test`, `internal`, `_admin`
   (under an `api/` folder).
2. File contains a comment like `// debug`, `// dev only`,
   `// internal`, `// do not ship`.
3. A handler returns `process.env`, dumps the full request, returns
   uninspected DB rows, or executes caller-supplied code/SQL.
4. A handler is gated by `x-debug`, `x-internal`, `x-test`,
   `x-skip-auth` headers and is not behind an auth wall.

## What to ignore

- `/api/health` and `/api/version` endpoints that return a static
  health status.
- Storybook / dev-only routes that are stripped from production
  builds (Next.js `app/(dev)/` group excluded via `next.config.js`).
- Test files (`*.test.ts`).
- Endpoints clearly behind admin auth (`requireAdmin()` called first).

## Examples

True positives:
```ts
// app/api/debug/state/route.ts
export async function GET() {
  return Response.json({ env: process.env, session: globalState });
}

// Header toggle without auth
export async function GET(req: Request) {
  if (req.headers.get("x-debug") === "1") {
    return Response.json(await dumpAllUsers());
  }
  return Response.json({ ok: true });
}

// Comment marker, no env gating
// dev only handler
export function DELETE() {
  return new Response(null, { status: 204 });
}
```

False positives to skip:
```ts
// /api/health
export async function GET() {
  return Response.json({ status: "ok" });
}

// Behind admin auth
export async function GET() {
  await requireAdmin();
  return Response.json(await getInternalState());
}
```
