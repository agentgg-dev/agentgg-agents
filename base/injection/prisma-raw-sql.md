---
slug: prisma-raw-sql
name: Prisma Raw SQL Escape Hatch
description: Prisma $queryRawUnsafe / $executeRawUnsafe accept plain strings and bypass parameterization. Also flags $queryRaw / $executeRaw called as a function rather than a tagged template. Walker mode follows query helpers to verify whether arguments are user-controlled.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
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
  - regex: "\\$(query|execute)RawUnsafe\\s*\\("
    label: "Prisma $queryRawUnsafe / $executeRawUnsafe call"
  - regex: "\\$(query|execute)Raw\\s*\\([^`]"
    label: "Prisma $queryRaw / $executeRaw called as a function (not tagged template)"
  - regex: "Prisma\\.raw\\s*\\("
    label: "Prisma.raw() literal-injection helper"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing TypeScript / JavaScript source code for SQL
injection in Prisma raw-query escape hatches.

**Walker mode advantage:** Prisma raw calls are often wrapped in
repository helpers (`lib/db.ts`, `repositories/*.ts`). When the
candidate site is `userRepo.searchByName(q)`, follow the import to
the repository and verify whether the helper builds the SQL via
tagged template (safe) or by concatenation passed into
`$queryRawUnsafe` (unsafe). Also trace the argument back to confirm
it includes user input — a `$queryRawUnsafe("VACUUM ANALYZE")` is
not a finding.

## Prisma's safety model

- **`prisma.$queryRaw\`SELECT * FROM users WHERE id = ${id}\`** —
  safe. Tagged-template form auto-parameterizes `${id}` as a bind
  value.
- **`prisma.$queryRawUnsafe("SELECT ... WHERE id = " + id)`** —
  unsafe by name. The argument string is sent to the database
  unmodified.
- **`prisma.$queryRaw(someString)`** (called as a function rather
  than as a tagged template) — unsafe. Common transcription error
  that silently disables parameterization.
- **`prisma.$queryRaw(Prisma.raw(...))`** — unsafe. `Prisma.raw`
  wraps a string and tells Prisma to inject it literally.

## What to look for

**`$queryRawUnsafe` / `$executeRawUnsafe`:**
```ts
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
await prisma.$executeRawUnsafe("DELETE FROM users WHERE id = " + id);
```
Safe form: `prisma.$queryRaw\`SELECT * FROM users WHERE name = ${name}\``.

**`$queryRaw` / `$executeRaw` called as a function (not tagged template):**
```ts
const query = `SELECT * FROM users WHERE id = ${id}`;
await prisma.$queryRaw(query);   // bypasses parameterization!
await prisma.$executeRaw(query);
```
The lack of a backtick after `$queryRaw` is the giveaway.

**`Prisma.raw` injection:**
```ts
await prisma.$queryRaw(Prisma.raw(`SELECT * FROM ${tableName}`));
```
`Prisma.raw` is the explicit "insert this string literally"
escape valve.

## True positive criteria

Flag when ANY of the following hold:

1. `$queryRawUnsafe` or `$executeRawUnsafe` is called.
2. `$queryRaw` or `$executeRaw` is called with `()` followed by a
   non-backtick argument (i.e., used as a function, not a tagged
   template).
3. `Prisma.raw(...)` appears as an argument to `$queryRaw` /
   `$executeRaw` with user-controlled content.

## What to ignore

- Tagged-template form: `prisma.$queryRaw\`SELECT ... ${id}\`` —
  parameterized.
- Tagged-template form with `Prisma.sql\`...\`` building a query
  fragment — also parameterized.
- `$queryRawUnsafe` with an entirely hardcoded SQL string and no
  user interpolation.
- Test files.

## Examples

True positives:
```ts
// $queryRawUnsafe with user input
const name = req.body.name;
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);

// $executeRawUnsafe with concat
await prisma.$executeRawUnsafe("DELETE FROM users WHERE id = " + req.params.id);

// $queryRaw used as function (not tagged template)
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
await prisma.$queryRaw(query);

// Prisma.raw with user-controlled string
await prisma.$queryRaw(Prisma.raw(`SELECT * FROM ${req.query.table}`));
```

False positives to skip:
```ts
// Tagged-template — parameterized
const id = req.params.id;
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;

// Fully hardcoded — no user input
await prisma.$queryRawUnsafe("VACUUM ANALYZE");

// Prisma.sql for query fragments (parameterized)
const where = Prisma.sql`WHERE id = ${id}`;
await prisma.$queryRaw`SELECT * FROM users ${where}`;
```
