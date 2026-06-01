---
slug: zod-passthrough-mass-assignment
name: Zod Passthrough Mass Assignment
description: 'Zod schema using .passthrough() allows arbitrary extra fields through validation — if the parsed output is written to the database, callers can set columns the schema never declared. Walker mode follows imports to see whether parsed output reaches a DB write.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: \.passthrough\s*\(\s*\)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Zod .passthrough() (disables strip of unknown keys)
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
    - regex: \.passthrough\s*\(\s*\)
      label: Zod .passthrough() (disables strip of unknown keys)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-915
  - 'OWASP-A08:2021'
---

You are reviewing TypeScript source code for mass assignment via Zod's
`.passthrough()` method — a schema modifier that allows the parsed
output to include fields beyond those declared in the schema. When the
result of such a parse is fed directly into a database write, the
caller can set columns the application never intended to expose.

**Walker mode advantage:** schemas with `.passthrough()` are often
defined in a `schemas/` or `validators/` module and consumed
elsewhere. Follow the import of the schema export to find every
callsite — flag only those where the parsed output reaches a DB
write (`.values()`, `.set()`, `.create()`, `.update()`, raw query)
or another security-relevant assignment.

## The vulnerability

By default, `z.object({...}).parse(input)` strips unknown keys (Zod's
`strip` mode). `.passthrough()` disables this stripping:

```ts
const schema = z.object({ name: z.string() }).passthrough();
const data = schema.parse(req.body);
// data may now include: { name: "Alice", role: "admin", isVerified: true }
await db.insert(users).values(data);  // role and isVerified leak in
```

## What to look for

**Schema defined with `.passthrough()`:**
```ts
const schema = z.object({ name: z.string() }).passthrough();
const input = z.object({ id: z.string() }).passthrough();
```

**`.passthrough()` output used in a DB write:**
```ts
const parsed = schema.parse(req.body);
await db.insert(users).values(parsed);

const data = inputSchema.parse(req.body);
await db.update(users).set(data);
```

**Combined in one expression:**
```ts
await db.insert(posts).values(
  z.object({ title: z.string() }).passthrough().parse(req.body)
);
```

## True positive criteria

Flag when BOTH of the following hold:

1. A Zod schema is defined or called with `.passthrough()`.
2. The parsed output flows into a database write (ORM insert/update,
   `.values()`, `.set()`, `.create()`, `.update()`, raw query).

Even without a direct DB write, flag `.passthrough()` on any schema
that processes external input — the schema owner should consciously
decide whether unknown keys are safe to allow.

## What to ignore

- `.passthrough()` on a schema that processes internal / server-side
  data only (not from HTTP request bodies or external sources).
- `.passthrough()` where the parsed output is only used for reading
  or display (not written back to persistent state).
- `.passthrough()` on nested schemas where the top-level schema does
  NOT use `.passthrough()` and strips unknowns by default.
- Test files.

## Examples

True positives:
```ts
// Schema with passthrough, output fed to DB insert
const schema = z.object({ name: z.string() }).passthrough();
const parsed = schema.parse(req.body);
await db.insert(users).values(parsed);

// Inline — same risk
await db.update(users).set(
  z.object({ email: z.string().email() }).passthrough().parse(req.body)
);
```

False positives to skip:
```ts
// Default strip mode — unknown keys removed
const schema = z.object({ name: z.string() });  // no passthrough
const data = schema.parse(req.body);
await db.insert(users).values(data);  // only name can appear

// passthrough on output schema, not input — reading from DB, not writing
const userSchema = z.object({ id: z.string() }).passthrough();
const user = userSchema.parse(dbRow);  // display only
```
