---
slug: js-nextjs-server-action-no-auth
name: Next.js Server Action Without Auth
description: '''use server'' files where exported functions don''t call an auth check — every exported server action is a public POST endpoint. Walker mode follows auth HOFs and shared verifiers.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '^[''"]use server[''"]\s*;?'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: File-level 'use server' directive
      - regex: '^\s*[''"]use server[''"]\s*;?'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Inline 'use server' directive in function body
  prompt: Run only if this project uses nextjs — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '^[''"]use server[''"]\s*;?'
      label: File-level 'use server' directive
    - regex: '^\s*[''"]use server[''"]\s*;?'
      multiline: true
      label: Inline 'use server' directive in function body
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-862
  - 'OWASP-A01:2021'
---

You are reviewing Next.js server actions for missing authentication.

**Walker mode advantage:** projects commonly define an auth HOF
(`withAuth`, `withServerActionAuth`) in a shared module. When an
export is `withAuth(async (...) => {...})`, open the HOF to confirm
it actually verifies a session before invoking the wrapped action.
Also follow imports for any shared `requireAuth()` / `getSession()`
helper used at the top of the action — verify it throws or returns
on missing auth.

## Why this matters

Every function exported from a file with `"use server"` at the top
(or every function with `"use server"` as its first statement) is
exposed to clients as a POST endpoint at a stable identifier. There
is no "private" server action — if it is exported and reachable from
client code, an attacker can call it directly via crafted fetch.

Adding an `<form action={...}>` or `onClick` handler does NOT add
auth. The auth check must be inside the server action body.

## What to look for

**File-level `"use server"` with un-gated exports:**
```ts
"use server";

export async function createUser(name: string) {
  await db.users.create({ data: { name } });
}

export async function deleteAccount(id: string) {
  await db.users.delete({ where: { id } });
}
```
Both functions are public POST endpoints.

**Inline `"use server"` in a function with no auth:**
```ts
export async function doThing(x: string) {
  "use server";
  return processSensitive(x);
}
```

**Auth indicators that, if PRESENT in the function body, address
the issue:**
`getSession(...)`, `auth(...)`, `requireAuth(...)`, `withAuth(...)`,
`verifyToken(...)`, `assertAuth(...)`, `checkAuth(...)`,
`parseAuthToken(...)`, `isAuthenticated(...)`.

The auth call must be reached before any side effect in the same
function.

## True positive criteria

Flag when ALL of the following hold:

1. The file begins with `"use server"` OR a function in the file
   has `"use server"` as its first statement.
2. An exported function in the file performs a mutation, returns
   user data, or otherwise takes sensitive action.
3. The function body does not call an auth verifier as one of
   its first statements.

## What to ignore

- Server actions that begin with `await auth()` or equivalent.
- Server actions wrapped in an auth HOF before export:
  `export const action = withAuth(async (...) => {...})`.
- Genuinely public actions like newsletter signup or a contact
  form (flag for review, but a finding here is low severity).
- Test files / mocks.

## Examples

True positives:
```ts
"use server";

// Public POST — any client can call
export async function fetchSecret() {
  return { secret: await db.secret.findFirst() };
}

// Mutation with no auth
export async function deleteAccount(id: string) {
  await db.users.delete({ where: { id } });
}

// Inline use server
export async function getProfile(id: string) {
  "use server";
  return db.users.findUnique({ where: { id } });
  // Anyone can fetch any user
}
```

False positives to skip:
```ts
"use server";

// Auth check before action
export async function adminWipe() {
  await requireAuth();
  return { ok: true };
}

// Wrapped
export const updateUser = withAuth(async (id: string, data: UserPatch) => {
  await db.users.update({ where: { id }, data });
});
```
