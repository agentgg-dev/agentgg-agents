---
slug: missing-await
name: Missing await on Async Call
description: 'Async function called without await — error is swallowed, return value is a Promise (truthy), and the result is silently discarded. Especially dangerous around auth verifiers, mutex/lock helpers, and transactions. Follows function definitions to confirm async-ness.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: if\s*\(\s*(verifyToken|verifyJwt|isAuthenticated|requireUser|assertAuth|checkPermission|hasAccess)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Likely-async verifier used in if() without await
      - regex: \b(withMutex|withLock|withUserMutex|withDistributedLock|withTransaction)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Mutex/lock/transaction helper call (confirm await)
      - regex: '^\s*(redis|cache|prisma|db|client)\.[a-z][a-zA-Z]+\s*\([^)]*\)\s*;?\s*$'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: DB/cache call as a statement (verify await)
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: if\s*\(\s*(verifyToken|verifyJwt|isAuthenticated|requireUser|assertAuth|checkPermission|hasAccess)\s*\(
      label: Likely-async verifier used in if() without await
    - regex: \b(withMutex|withLock|withUserMutex|withDistributedLock|withTransaction)\s*\(
      label: Mutex/lock/transaction helper call (confirm await)
    - regex: '^\s*(redis|cache|prisma|db|client)\.[a-z][a-zA-Z]+\s*\([^)]*\)\s*;?\s*$'
      label: DB/cache call as a statement (verify await)
      multiline: true
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-393
  - CWE-754
---

You are reviewing TypeScript / JavaScript code for async functions
called without `await`.

**Cross-file analysis:** the verdict depends on whether the called
function is actually async. Open the function definition: if
`verifyToken` is declared `async function` (or returns a Promise),
the unawaited usage in `if (verifyToken(...))` is a bug. If it's
synchronous, no finding. Also follow `withLock` / `withTransaction`
helpers to confirm they return Promises. Three failure modes:

1. **The result is a Promise (truthy)**, so `if (verifyToken(t)) grant()`
   passes for any token because `Promise` is truthy.
2. **Errors are unhandled.** Rejected promises without await become
   uncaughtPromiseRejection events at runtime, often silent.
3. **Order of operations breaks.** Code after the unawaited call
   runs before the call's side effects complete.

## What to look for

**Async verifiers used in conditionals:**
```ts
if (verifyToken(token)) { grant(); }
// verifyToken returns a Promise — truthy — always grants
```

**Mutex / lock helpers without await:**
```ts
withMutex(() => doStuff());
withUserMutex(() => updateUser(id));
withLock(key, () => criticalSection());
withDistributedLock(key, fn);
```
The critical section runs, but the surrounding function returns
before it finishes; subsequent code may run while the lock is held
elsewhere.

**Transactions:**
```ts
withTransaction(async (tx) => {
  await tx.user.update({ id });
});
// Without await, the function returns before the transaction commits
```

**DB calls and Redis calls with side effects:**
```ts
redis.set(key, value);
prisma.session.delete({ where: { id } });
db.user.update({ ... });
```
These return Promises; without await, the caller doesn't know when
(or whether) the operation completed.

## True positive criteria

Flag when an async function is called and:
1. The result is used in a boolean / truthiness context, OR
2. The function has security-critical side effects (auth, mutex,
   lock, transaction, DB write, secret rotation), AND
3. No `await` precedes the call AND the result isn't explicitly
   discarded via `void` or chained with `.then(...)/.catch(...)`.

## What to ignore

- Calls explicitly marked `void asyncFn()` to indicate the discard
  is intentional.
- Calls inside an `async` function that the caller of THAT function
  awaits (chain through the boundary).
- Calls inside `Promise.all([...])` / `Promise.allSettled([...])`.
- Calls used for side-effecting telemetry that the author
  intentionally does not block on (and the function name signals
  "fire and forget": `logAsync`, `trackEvent`).
- Top-level scripts where event loop drainage is the intent.
- Test files.

## Examples

True positives:
```ts
// Promise in conditional — always truthy
if (verifyToken(req.headers.authorization)) {
  return handler(req);
}

// Lock without await
function updateUserSafely(id: string) {
  withLock(`user:${id}`, async () => {
    await db.user.update({ where: { id }, data: { ... } });
  });
  // Function returns before the lock body runs
}

// Forgotten await on rotation
function rotateKey() {
  generateNewKey();   // returns Promise — old key still in use
}
```

False positives to skip:
```ts
// Awaited
if (await verifyToken(req.headers.authorization)) {
  return handler(req);
}

// Explicit fire-and-forget
void logAsyncEvent({ ... });

// Inside Promise.all
await Promise.all([
  db.user.update({ ... }),
  redis.set(key, value),
]);
```
