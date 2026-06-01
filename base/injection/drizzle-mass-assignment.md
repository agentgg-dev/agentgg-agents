---
slug: drizzle-mass-assignment
name: Drizzle ORM Mass Assignment
description: Drizzle insert/update where .values() or .set() receives a request body directly or via spread — caller can write to columns the application never intended to expose. Traces the payload source and any schema parser between request and DB call.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: \.values\s*\(\s*(req\.body|request\.body|body|payload|input|formData|data|json)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Drizzle .values() with request-body variable
      - regex: '\.values\s*\(\s*\{\s*\.\.\.\s*(req\.body|request\.body|body|payload|input|formData)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Drizzle .values() with spread of request body
      - regex: \.set\s*\(\s*(req\.body|request\.body|body|payload|input|data)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Drizzle .set() with request-body variable
      - regex: '\.set\s*\(\s*\{\s*\.\.\.\s*(req\.body|request\.body|body|payload)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Drizzle .set() with spread of request body
  prompt: Run only if this project uses drizzle — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
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
    - regex: \.values\s*\(\s*(req\.body|request\.body|body|payload|input|formData|data|json)\b
      label: Drizzle .values() with request-body variable
    - regex: '\.values\s*\(\s*\{\s*\.\.\.\s*(req\.body|request\.body|body|payload|input|formData)'
      label: Drizzle .values() with spread of request body
    - regex: \.set\s*\(\s*(req\.body|request\.body|body|payload|input|data)\b
      label: Drizzle .set() with request-body variable
    - regex: '\.set\s*\(\s*\{\s*\.\.\.\s*(req\.body|request\.body|body|payload)'
      label: Drizzle .set() with spread of request body
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-915
  - 'OWASP-A08:2021'
---

You are reviewing TypeScript source code for mass assignment in Drizzle
ORM — specifically `db.insert(table).values(payload)` and
`db.update(table).set(payload)` where `payload` is a request body or
spread of one, allowing callers to write to any column the table has.

**Cross-file analysis:** the payload variable is often defined a few
lines or one helper away. Trace it: was it `await req.json()`, was it
`schema.parse(...)` (Zod), or did it come from a sanitizing helper?
Also read the schema definition — `.passthrough()` defeats Zod's
strip. The mass-assignment verdict depends on that chain.

## What to look for

**`.values()` with direct request body:**
```ts
await db.insert(users).values(req.body);
await db.insert(posts).values(body);
await db.insert(items).values(payload);
```

**`.values()` with spread of request body:**
```ts
await db.insert(users).values({ ...req.body });
await db.insert(posts).values({ ...input });
await db.insert(users).values({ ...formData });
```

**`.set()` with request body (update):**
```ts
await db.update(users).set(body);
await db.update(posts).set({ ...request.body });
await db.update(users).set(data);
```

**Variable names that signal "incoming payload":**
`req.body`, `request.body`, `body`, `payload`, `input`, `formData`,
`data`, `json`, `args`, `params` — especially when defined as the
parsed request body and then passed directly to a Drizzle call.

## True positive criteria

Flag when BOTH of the following hold:

1. A Drizzle `insert(...).values(...)` or `update(...).set(...)` is
   called.
2. The argument is a request-body variable (or spread of one) without
   explicit column selection — i.e., the caller controls which keys
   are present rather than the code enumerating safe fields.

## What to ignore

- `.values()` with an object literal where every key is explicitly
  written out:
  ```ts
  await db.insert(users).values({ name: req.body.name, email: req.body.email });
  ```
  The code controls which columns are written.
- `.values()` with output from a schema parser that strips unknown
  keys (Zod default, Joi `allowUnknown: false`).
- Test files and seed scripts that insert controlled test data.

## Examples

True positives:
```ts
// Direct body — any DB column can be set
await db.insert(users).values(req.body);

// Spread — still carries all caller-supplied keys
await db.insert(posts).values({ ...req.body, authorId: session.userId });

// Update mass assignment
await db.update(users)
  .set({ ...body, updatedAt: new Date() })
  .where(eq(users.id, id));
```

False positives to skip:
```ts
// Explicit columns only — safe
await db.insert(users).values({
  name: body.name,
  email: body.email,
  createdAt: new Date(),
});

// Zod strips unknown keys before insert
const safe = createUserSchema.parse(req.body);
await db.insert(users).values(safe);

// Seed script with hardcoded data
await db.insert(users).values({ name: "Admin", role: "admin" });
```
