---
slug: go-sql-raw
name: Raw SQL Injection (Go)
description: Go SQL execution (database/sql, GORM, sqlx, pgx) with fmt.Sprintf or string concatenation in the query — bypasses parameterization. Walker mode traces the query source and any repository helpers.
version: 0.1.0
author: agentgg
mode: walker
tech: [go]
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.go"
excludePatterns:
  - "**/*_test.go"
  - "**/vendor/**"
preFilter:
  - regex: "\\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\\s*\\([^)]*\\bfmt\\.Sprintf\\b"
    label: "database/sql call wrapping fmt.Sprintf"
  - regex: "\\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\\s*\\(\\s*\"[^\"]*\"\\s*\\+"
    label: "database/sql call concatenating strings"
  - regex: "\\.(Raw|Where|Select|Get)\\s*\\([^)]*\\bfmt\\.Sprintf\\b"
    label: "GORM/sqlx call wrapping fmt.Sprintf"
  - regex: "\\.(Raw|Where)\\s*\\(\\s*\"[^\"]*\"\\s*\\+"
    label: "GORM Raw/Where concatenating strings"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing Go source code for SQL injection across
`database/sql`, GORM, sqlx, and pgx. The unsafe pattern is the SQL
string being built with `fmt.Sprintf` or `+` concatenation that
incorporates user-controlled values — both bypass the driver's
parameter binding (`?` for MySQL/SQLite, `$1` for PostgreSQL).

**Walker mode advantage:** queries are commonly assembled in a
repository function (`userRepo.FindByName(ctx, q)`) and the
`fmt.Sprintf` is several files away from the request handler. Follow
the call chain: trace where the query string comes from and whether
the value being interpolated crosses a trust boundary.

## What to look for

**`database/sql` package:**
```go
rows, err := db.Query("SELECT * FROM users WHERE id = " + userId)
db.QueryRow(fmt.Sprintf("SELECT * FROM x WHERE y = '%s'", name))
db.Exec("DELETE FROM users WHERE id = " + id)
conn.QueryRowContext(ctx, fmt.Sprintf("SELECT * FROM t WHERE id = %d", id))
```
Safe form: `db.Query("SELECT * FROM users WHERE id = $1", userId)`
or `db.Query("SELECT * FROM users WHERE id = ?", userId)`.

**GORM:**
```go
db.Raw("SELECT * FROM users WHERE id = " + id).Scan(&user)
db.Raw(fmt.Sprintf("UPDATE users SET role = '%s'", role)).Exec()
db.Where("name = '" + name + "'").First(&user)
db.Where(fmt.Sprintf("id = %d", id)).First(&u)
db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %d", id))
```
Safe form: `db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&user)`,
`db.Where("name = ?", name).First(&user)`.

**sqlx:**
```go
err := sqlxDb.Select(&users, "SELECT * FROM users WHERE name = '" + name + "'")
```
Safe form: `sqlxDb.Select(&users, "SELECT * FROM users WHERE name = $1", name)`.

**pgx:**
```go
row := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = '" + email + "'")
```
Safe form: `pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email)`.

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing call is made: `Query`, `QueryRow`, `Exec`, the
   `Context` variants, `Raw`, `Where` (with string fragment),
   `Select`, `Get` (sqlx).
2. The SQL string is built with `+` concatenation or `fmt.Sprintf`.
3. The non-constant operand comes from caller input (HTTP request,
   message queue, config supplied by an external system).

## What to ignore

- Parameterized queries with `?` or `$N` placeholders and values
  passed as additional arguments.
- GORM struct-based queries: `db.Where(&User{Name: name}).First(&u)`.
- Hardcoded SQL with no concatenation.
- Identifier interpolation against a strict allowlist.
- Tests (`_test.go`).

## Examples

True positives:
```go
// database/sql with concat
userId := r.URL.Query().Get("id")
rows, err := db.Query("SELECT * FROM users WHERE id = " + userId)

// GORM with fmt.Sprintf
db.Raw(fmt.Sprintf("DELETE FROM users WHERE email = '%s'", email)).Exec()

// pgx with concat
email := r.FormValue("email")
row := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = '" + email + "'")
```

False positives to skip:
```go
// database/sql parameterized
rows, err := db.Query("SELECT * FROM users WHERE id = $1", userId)

// GORM parameterized
db.Where("name = ?", name).First(&user)

// Struct-based GORM
db.Where(&User{Email: email}).First(&user)
```
