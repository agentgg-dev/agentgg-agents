---
slug: js-sql-raw
name: Raw SQL Injection (JavaScript / TypeScript)
description: 'Raw SQL escape hatches across JS/TS drivers (pg, mysql2, TypeORM, Sequelize, Knex, Kysely, postgres.js, better-sqlite3) built with template literal interpolation or string concatenation. Follows query helpers to verify safe parameterization.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.(query|execute|exec|raw)\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: driver.query/execute/raw with template-literal interpolation
      - regex: '\.(query|execute|exec|raw)\s*\([^)]*\+'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: driver.query/execute/raw concatenating a string
      - regex: \.(whereRaw|orderByRaw|havingRaw)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Knex whereRaw/orderByRaw/havingRaw
      - regex: Sequelize\.literal\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Sequelize.literal escape hatch
      - regex: sql\.(raw|unsafe)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Kysely sql.raw / postgres.js sql.unsafe
      - regex: '\.prepare\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: better-sqlite3 prepare with template-literal interpolation
      - regex: '@Query\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: TypeORM @Query decorator with interpolation
  prompt: Run only if this project uses node — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
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
    - regex: '\.(query|execute|exec|raw)\s*\(\s*`[^`]*\$\{'
      label: driver.query/execute/raw with template-literal interpolation
    - regex: '\.(query|execute|exec|raw)\s*\([^)]*\+'
      label: driver.query/execute/raw concatenating a string
    - regex: \.(whereRaw|orderByRaw|havingRaw)\s*\(
      label: Knex whereRaw/orderByRaw/havingRaw
    - regex: Sequelize\.literal\s*\(
      label: Sequelize.literal escape hatch
    - regex: sql\.(raw|unsafe)\s*\(
      label: Kysely sql.raw / postgres.js sql.unsafe
    - regex: '\.prepare\s*\(\s*`[^`]*\$\{'
      label: better-sqlite3 prepare with template-literal interpolation
    - regex: '@Query\s*\(\s*`[^`]*\$\{'
      label: TypeORM @Query decorator with interpolation
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing JavaScript / TypeScript source code for SQL
injection through raw-SQL escape hatches in database drivers and
query builders — places where the SQL string is built via template
literal interpolation or `+` concatenation with user-controlled
values, bypassing the driver's parameterized-query mechanism.

**Cross-file analysis:** raw-SQL calls are commonly wrapped in
repository helpers (`db/users.ts`, `repositories/orders.ts`). When
the candidate is `userRepo.search(q)` rather than the raw driver
call, follow the import and read the helper — verify it uses
parameter binding rather than passing the argument straight into
`raw()` or a template literal.

## What to look for

**node-postgres (`pg`):**
```ts
client.query(`SELECT * FROM users WHERE id = ${id}`)
pool.query("SELECT * FROM users WHERE id = " + userId)
```
Safe form: `client.query("SELECT * FROM users WHERE id = $1", [id])`.

**mysql2 / mysql:**
```ts
conn.query(`SELECT * FROM users WHERE name = '${name}'`)
```
Safe form: `conn.query("SELECT * FROM users WHERE name = ?", [name])`.

**TypeORM:**
```ts
repo.query(`UPDATE users SET role = '${role}' WHERE id = ${id}`)
@Query(`SELECT * FROM x WHERE y = '${z}'`)
```
Safe form: `repo.query("UPDATE users SET role = ? WHERE id = ?", [role, id])`.

**Sequelize:**
```ts
sequelize.query(`SELECT * FROM t WHERE col = '${input}'`)
Sequelize.literal(`COUNT(*) FILTER (WHERE x = ${x})`)
```
Safe form: use `replacements` or `bind` option.

**Knex:**
```ts
knex.raw(`SELECT * FROM users WHERE id = ${id}`)
qb.whereRaw("col = '" + value + "'")
```
Safe form: `knex.raw("SELECT * FROM users WHERE id = ?", [id])`.

**Kysely:**
```ts
db.selectFrom("users").where(sql.raw("col = " + x))
```
Safe form: ``db.selectFrom("users").where(sql`col = ${x}`)`` (the
`sql` tagged template parameterizes interpolations).

**postgres.js / porsager:**
```ts
sql.unsafe(`SELECT * FROM x WHERE y = ${y}`)
```
Safe form: ``sql`SELECT * FROM x WHERE y = ${y}` `` (the tagged
template parameterizes).

**better-sqlite3:**
```ts
db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get()
```
Safe form: `db.prepare("SELECT * FROM users WHERE name = ?").get(name)`.

## True positive criteria

Flag when:
1. A SQL-executing function is called: `query`, `execute`, `raw`,
   `whereRaw`, `orderByRaw`, `havingRaw`, `unsafe`, `prepare`,
   `literal`, `@Query`, `selectFrom().where(sql.raw(...))`.
2. The SQL string contains template literal interpolation (`${...}`)
   or string concatenation (`+`) with a non-constant value.
3. The interpolated value originates from user input (request body,
   query params, path params, headers, cookies, or data derived from
   any of these).

## What to ignore

- Tagged-template forms of safe APIs:
  ``sql`SELECT * FROM users WHERE id = ${id}` `` (Kysely, postgres.js).
  These auto-parameterize.
- Parameterized queries that use `$1`, `?`, or named placeholders
  with a separate values array.
- Calls where all interpolated values are hardcoded constants.
- Interpolation of identifiers (table/column names) that have been
  validated against a fixed allowlist — preferred pattern.
- Test files.

## Examples

True positives:
```ts
// pg with template literal
await pool.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);

// Sequelize with literal
sequelize.query(`SELECT * FROM ${req.query.table} WHERE id = ${id}`);

// Knex raw with concat
knex.raw("SELECT * FROM products WHERE name LIKE '%" + req.query.q + "%'");

// TypeORM @Query annotation with interpolation
@Query(`SELECT * FROM users WHERE role = '${roleFromBody}'`)
```

False positives to skip:
```ts
// Parameterized — safe
await pool.query("SELECT * FROM users WHERE id = $1", [id]);

// Kysely sql tagged template — auto-parameterized
db.selectFrom("users").where(sql`name = ${name}`);

// Hardcoded SQL with no interpolation
await client.query("SELECT NOW()");

// Allowlist-validated identifier
const COLUMN = ["name", "email", "created_at"];
if (!COLUMN.includes(sortBy)) throw new Error("invalid");
await client.query(`SELECT * FROM users ORDER BY ${sortBy}`);
```
