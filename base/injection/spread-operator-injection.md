---
slug: spread-operator-injection
name: Mass Assignment via Spread Operator
description: 'Object spread of req.body / params / query into a DB insert, update, or trusted object — allows callers to set fields the application never intended to expose. Walker mode traces validation between spread and DB write.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '\{\s*\.\.\.\s*(req|request)\.(body|query|params)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'Spread of req/request.{body,query,params}'
      - regex: '\{\s*\.\.\.\s*(body|payload|input|formData|parsed)\s*[,}]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Spread of body/payload/input variable
      - regex: '\{\s*\.\.\.\s*searchParams\s*[,}]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Spread of searchParams
      - regex: 'Object\.assign\s*\(\s*\{\}\s*,\s*(req|request)\.(body|query|params)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'Object.assign({}, req.body) pattern'
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
    - regex: '\{\s*\.\.\.\s*(req|request)\.(body|query|params)'
      label: 'Spread of req/request.{body,query,params}'
    - regex: '\{\s*\.\.\.\s*(body|payload|input|formData|parsed)\s*[,}]'
      label: Spread of body/payload/input variable
    - regex: '\{\s*\.\.\.\s*searchParams\s*[,}]'
      label: Spread of searchParams
    - regex: 'Object\.assign\s*\(\s*\{\}\s*,\s*(req|request)\.(body|query|params)'
      label: 'Object.assign({}, req.body) pattern'
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-915
  - 'OWASP-A08:2021'
---

You are reviewing JavaScript / TypeScript source code for mass
assignment via the object spread operator — spreading a request body,
query, or params object into a payload that is sent to the database
without an explicit allowlist of fields.

**Walker mode advantage:** the spread might happen on a Zod/Joi
parse result, not on the raw body. Trace the spread target: if it's
`parsedBody` where `parsedBody = schema.parse(req.body)` and the
schema strips unknown keys, the bug is closed. Open the schema and
verify there's no `.passthrough()`. Also confirm the spread result
actually reaches a persistent write — pure DTO usage is lower risk.

## The vulnerability

When `{ ...req.body }` is passed directly to a database write, the
caller can include fields the UI never exposed: `role`, `isAdmin`,
`verified`, `createdAt`, `subscriptionTier`, `deletedAt`. If the ORM
or database accepts them, the attacker has written to those columns.

```ts
// Caller sends: { name: "Alice", role: "admin" }
await db.users.update({ id }, { ...req.body });
// role is now "admin"
```

## What to look for

**Spread of `req.body` / `request.body`:**
```ts
const payload = { ...req.body, createdAt: new Date() };
await db.user.create({ data: { ...request.body } });
```

**Spread of parsed body or query:**
```ts
const merged = { ...parsed.body };
return { ...parsed.query, page: 1 };
```

**Spread of `searchParams`, `params`, or `query`:**
```ts
const next = { ...searchParams };
const opts = { ...params };
```

**`Object.assign({}, req.body)` or `Object.assign({}, body)`:**
```ts
const user = Object.assign({}, req.body);
await db.save(user);
```

**Pattern: safe-looking fields added alongside the spread:**
```ts
// The spread still carries arbitrary extra keys from the caller
const data = { ...req.body, userId: session.userId, updatedAt: new Date() };
await db.posts.update({ id: postId }, data);
```

## True positive criteria

Flag when BOTH of the following hold:

1. User input (`req.body`, `request.body`, parsed body, query, params,
   `searchParams`) is spread or assigned with `Object.assign` into
   an object.
2. That object is then passed to a database write (ORM insert/update,
   raw query), used to set properties on a persistent model, or
   returned as the authenticated user's profile.

If the spread result is only used as a local DTO that is never written
to persistent state or privileged contexts, the risk is lower (but
still worth noting if it carries sensitive keys).

## What to ignore

- Spread of a type-narrowed variable where TypeScript's type guarantees
  only safe fields can be present (e.g., `z.object({ name: z.string() }).parse(req.body)`
  result spread — the schema strip removed unknown keys).
- Spread used only to pass data to a logging call or non-sensitive
  display context.
- Test files.

## Examples

True positives:
```ts
// Direct DB write with spread
await db.user.create({ data: { ...req.body } });

// Extra field added, but spread still leaks caller-controlled keys
const data = { ...req.body, updatedAt: new Date() };
await db.users.update({ where: { id } }, { data });

// searchParams spread into query
const filters = { ...searchParams };
const results = await db.products.findMany({ where: filters });
```

False positives to skip:
```ts
// Zod parse with .strip() (default) removes unknown fields
const body = updateSchema.parse(req.body);  // no unknown keys
await db.users.update({ where: { id } }, { data: body });

// Only used for logging
logger.info({ ...req.body });

// Read-only — no DB write
const debug = { ...req.query };
return Response.json(debug);
```
