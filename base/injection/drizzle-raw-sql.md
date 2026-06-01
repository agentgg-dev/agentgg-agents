---
slug: drizzle-raw-sql
name: Drizzle Raw SQL Escape Hatch
description: Drizzle ORM's sql.raw() / sql.unsafe() bypass parameterization — user-built strings reach the query engine as-is. Also flags risky concatenation inside sql`` templates. Follows imports to confirm Drizzle is in use and to trace argument sources.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: sql\.raw\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Drizzle sql.raw() escape hatch
      - regex: sql\.unsafe\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Drizzle sql.unsafe() escape hatch
      - regex: 'from\s+[''"]drizzle-orm[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: imports drizzle-orm (confirms ORM context)
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
    - regex: sql\.raw\s*\(
      label: Drizzle sql.raw() escape hatch
    - regex: sql\.unsafe\s*\(
      label: Drizzle sql.unsafe() escape hatch
    - regex: 'from\s+[''"]drizzle-orm[''"]'
      label: imports drizzle-orm (confirms ORM context)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing TypeScript source code for SQL injection through
Drizzle ORM's escape hatches. Drizzle parameterizes interpolated
expressions inside its `` sql`...` `` tagged template, but the
`sql.raw()` and `sql.unsafe()` helpers explicitly bypass this — they
insert the argument string literally into the final SQL.

**Cross-file analysis:** the candidate site may be a repository
helper that wraps `sql.raw(...)`. Follow the import chain to verify
(a) the file's `sql` import is from `drizzle-orm` (not some other
`sql` helper), and (b) the string argument actually carries user
input — `sql.raw("VACUUM ANALYZE")` is not a finding.

## Drizzle safety model

- **`` sql`SELECT * FROM users WHERE id = ${id}` ``** — safe. The
  `${id}` is auto-bound as a parameter.
- **`sql.raw("SELECT ... WHERE id = " + id)`** — unsafe. The string
  goes through as-is.
- **`sql.unsafe(...)`** — unsafe by name. Same as raw, also bypasses
  parameterization.
- **Identifier interpolation** (table or column names) cannot be
  parameterized in SQL. If you must interpolate an identifier, use
  `sql.identifier()` or validate against an allowlist.

## What to look for

**`sql.raw()` / `sql.unsafe()` with a user-built string:**
```ts
import { sql } from "drizzle-orm";

await db.execute(sql.raw(userQuery));
await db.execute(sql.unsafe(userQuery));
db.execute(sql.raw("SELECT * FROM " + tableName));
await conn.execute(sql.unsafe(`DROP TABLE ${name}`));
```

**Risky concatenation inside `` sql`` `` templates:**
The tagged template parameterizes `${...}`, but concatenation inside
the interpolation is suspicious:
```ts
await db.execute(sql`SELECT * FROM users WHERE name = ${"a" + b}`);
```
This still parameterizes the result of `"a" + b`, but flag it for
review — it usually indicates the author misunderstands the API.

**Template-in-template tricks that produce raw strings:**
```ts
const orderBy = "name";
await db.execute(sql`SELECT * FROM users ORDER BY ${`${orderBy}`}`);
```
Here the inner template literal evaluates to a plain string, which
Drizzle then parameterizes as a value — but `ORDER BY $1` is a SQL
syntax error. The author likely wants `sql.identifier(orderBy)`.

## True positive criteria

Flag when ANY of the following hold:

1. `sql.raw(...)` is called.
2. `sql.unsafe(...)` is called.
3. A user-controlled identifier (table name, column name) is
   interpolated into `` sql`` `` without `sql.identifier()` or an
   allowlist check.

For the file to be relevant, the file must import from `drizzle-orm`
or `@repo/db` (or a drizzle re-export).

## What to ignore

- `` sql`SELECT * FROM users WHERE id = ${id}` `` — values
  parameterized by the tagged template.
- `sql.identifier(allowlistedName)` — identifier-quoted via the API.
- `sql.raw(HARDCODED_STRING)` where the argument is a string literal.
- Test files.

## Examples

True positives:
```ts
// sql.raw with user input
const query = `SELECT * FROM users WHERE email = '${req.body.email}'`;
await db.execute(sql.raw(query));

// sql.unsafe with template literal
await db.execute(sql.unsafe(`SELECT * FROM ${req.query.table}`));

// Identifier interpolation without allowlist
const order = req.query.sortBy;
await db.execute(sql`SELECT * FROM users ORDER BY ${sql.raw(order)}`);
```

False positives to skip:
```ts
// Tagged template — parameterized
const rows = await db.execute(sql`SELECT * FROM users WHERE id = ${id}`);

// sql.identifier with allowlist
const SORTABLE = ["name", "email", "created_at"];
if (!SORTABLE.includes(sortBy)) throw new Error("invalid");
await db.execute(sql`SELECT * FROM users ORDER BY ${sql.identifier(sortBy)}`);

// sql.raw with hardcoded value
await db.execute(sql.raw("VACUUM ANALYZE"));
```
