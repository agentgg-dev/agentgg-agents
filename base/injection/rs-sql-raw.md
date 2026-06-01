---
slug: rs-sql-raw
name: Raw SQL Injection (Rust)
description: 'Rust SQL execution (sqlx runtime form with format!, diesel sql_query with format!, sea-orm Statement::from_string) with format! interpolation — note that sqlx::query!() macro is compile-time-checked and safe. Walker mode disambiguates macro vs function-call form.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'sqlx::(query|query_as)(::<[^>]+>)?\s*\(\s*&?\s*format!\s*\('
        in:
          - '**/*.rs'
        notIn:
          - '**/tests/**'
          - '**/examples/**'
          - '**/target/**'
        label: sqlx runtime form wrapping format! (not the safe macro)
      - regex: 'diesel::sql_query\s*\(\s*format!\s*\('
        in:
          - '**/*.rs'
        notIn:
          - '**/tests/**'
          - '**/examples/**'
          - '**/target/**'
        label: 'diesel::sql_query with format!'
      - regex: 'Statement::from_string\s*\([^,]*,\s*format!\s*\('
        in:
          - '**/*.rs'
        notIn:
          - '**/tests/**'
          - '**/examples/**'
          - '**/target/**'
        label: 'sea-orm Statement::from_string with format!'
      - regex: \.execute\s*\(\s*&?format!\s*\(|\.query\s*\(\s*&?format!\s*\(
        in:
          - '**/*.rs'
        notIn:
          - '**/tests/**'
          - '**/examples/**'
          - '**/target/**'
        label: rusqlite execute/query with format!
  prompt: Run only if this project uses rust — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - rs
  excludePatterns:
    - '**/tests/**'
    - '**/examples/**'
    - '**/target/**'
  preFilter:
    - regex: 'sqlx::(query|query_as)(::<[^>]+>)?\s*\(\s*&?\s*format!\s*\('
      label: sqlx runtime form wrapping format! (not the safe macro)
    - regex: 'diesel::sql_query\s*\(\s*format!\s*\('
      label: 'diesel::sql_query with format!'
    - regex: 'Statement::from_string\s*\([^,]*,\s*format!\s*\('
      label: 'sea-orm Statement::from_string with format!'
    - regex: \.execute\s*\(\s*&?format!\s*\(|\.query\s*\(\s*&?format!\s*\(
      label: rusqlite execute/query with format!
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing Rust source code for SQL injection in sqlx, diesel,
sea-orm, and rusqlite. The unsafe pattern is using `format!()` (or
`String::from(format!(...))`) to assemble the SQL string with
user-controlled values, then passing the resulting `String` to a
runtime query function.

**Walker mode advantage:** `sqlx::query!()` (macro, safe) and
`sqlx::query()` (function, unsafe with `format!`) look nearly
identical at a glance. Walker can confirm which is in use, follow the
SQL string back through helper functions, and check whether any
upstream code converts it to a properly parameterized `.bind()` form.

## Important: sqlx macros vs runtime

- **`sqlx::query!()` and `sqlx::query_as!()` macros** are compile-time
  checked and parameterize correctly. They are **safe** and not the
  target of this rule.
- **`sqlx::query()` and `sqlx::query_as::<_,T>()` functions** accept a
  runtime `&str`. They are safe when used with bind parameters
  (`.bind(x)`) but unsafe when called with `&format!(...)`.

## What to look for

**sqlx (runtime form with format!):**
```rust
sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id))
    .fetch_one(&pool).await?;
sqlx::query_as::<_, User>(&format!("SELECT * FROM users WHERE name = '{}'", name))
    .fetch_all(&pool).await?;
sqlx::query(&String::from(format!("DELETE FROM users WHERE id = {}", id)))
    .execute(&pool).await?;
```
Safe form: `sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)`.

**diesel sql_query:**
```rust
diesel::sql_query(format!("SELECT * FROM users WHERE id = {}", id))
    .load::<User>(conn)?;
```
Safe form: `diesel::sql_query("SELECT * FROM users WHERE id = $1").bind::<Integer, _>(id).load(conn)`.

**sea-orm Statement::from_string:**
```rust
Statement::from_string(DbBackend::Postgres,
    format!("SELECT * FROM x WHERE y = '{}'", y))
```
Safe form: `Statement::from_sql_and_values(DbBackend::Postgres, "...$1...", vec![y.into()])`.

**rusqlite raw execute:**
```rust
conn.execute(&format!("DELETE FROM users WHERE id = {}", id), [])?;
```
Safe form: `conn.execute("DELETE FROM users WHERE id = ?1", params![id])`.

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing runtime function is called: `sqlx::query`,
   `sqlx::query_as`, `diesel::sql_query`,
   `sea_orm::Statement::from_string`, `rusqlite::execute`,
   `rusqlite::query` (with `&str` arg).
2. The argument is `format!(...)`, `String::from(format!(...))`, or
   `+` concatenation.
3. The interpolated values include user input.

## What to ignore

- `sqlx::query!()` / `sqlx::query_as!()` macros — compile-time checked
  and parameterized.
- `sqlx::query("...").bind(x)` — runtime form with bind parameters.
- `diesel::sql_query("...").bind::<T, _>(x)`.
- `rusqlite::execute("...", params![x])`.
- Hardcoded SQL strings with no interpolation.
- Tests under `tests/` and examples under `examples/`.

## Examples

True positives:
```rust
// sqlx runtime + format!
let id: i32 = req.user_id();
let row = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id))
    .fetch_one(&pool).await?;

// diesel + format!
let id = path.into_inner();
diesel::sql_query(format!("DELETE FROM users WHERE id = {}", id))
    .execute(conn)?;

// sea-orm
let stmt = Statement::from_string(
    DbBackend::Postgres,
    format!("UPDATE users SET role = '{}' WHERE id = {}", role, id),
);
```

False positives to skip:
```rust
// sqlx macro — compile-time-checked
let row = sqlx::query!("SELECT * FROM users WHERE id = $1", id)
    .fetch_one(&pool).await?;

// sqlx runtime with bind — safe
sqlx::query("SELECT * FROM users WHERE id = $1")
    .bind(id)
    .fetch_one(&pool).await?;

// rusqlite with params
conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
```
