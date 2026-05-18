---
slug: sql-injection
name: SQL Injection
description: SQL queries built by concatenating or interpolating untrusted input into a query string instead of using parameterized queries. Walker mode follows query helpers and ORM wrappers to verify whether parameterization is actually applied.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
  - "**/*.{py,rb,go,rs,php,java,kt,cs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,rs,php,java,kt,cs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,rs,php,java,kt,cs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/.next/**"
preFilter:
  - regex: "\\.(query|execute|exec|run|raw)\\s*\\(\\s*`[^`]*\\$\\{"
    label: "SQL call with template-literal interpolation"
  - regex: "\\.(query|execute|exec|run|raw)\\s*\\([^)]*\\+\\s*(req|params|body|input|args|query|userInput)"
    label: "SQL call concatenating request data"
  - regex: "(execute|cursor|conn)\\s*\\(\\s*f['\"]"
    label: "Python SQL with f-string"
  - regex: "(execute|cursor|conn)\\s*\\([^)]*%\\s*\\("
    label: "Python SQL with %-format placeholder"
  - regex: "sqlalchemy\\.text\\s*\\(\\s*(f['\"]|.*\\+)"
    label: "SQLAlchemy text() with interpolation"
  - regex: "find_by_sql\\s*\\(.*#\\{"
    label: "ActiveRecord find_by_sql with #{} interpolation"
  - regex: "Sequel\\.lit\\s*\\(.*#\\{"
    label: "Sequel.lit with #{} interpolation"
  - regex: "fmt\\.Sprintf\\s*\\([^)]*(SELECT|INSERT|UPDATE|DELETE)"
    label: "Go fmt.Sprintf building SQL"
  - regex: "ORDER\\s+BY\\s+`?\\s*\\+|ORDER\\s+BY\\s+[\"`]?\\$\\{"
    label: "Dynamic ORDER BY built from input"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing a batch of source files for SQL injection — query
strings built from untrusted input via concatenation, template
interpolation, or unescaped substitution instead of parameter binding.

**Walker mode advantage:** SQL is frequently routed through shared
helpers (`lib/db.ts`, `repositories/users.ts`, `utils/query.ts`) and
ORM escape hatches that look safe by name. You have file-system tools
— use them. When a candidate file calls `db.run(sql)` or
`userRepo.find(q)`, read the helper before flagging: it might
parameterize correctly, or it might pass the string through unchanged.

## What to look for

- Query strings built with `+` from user-controlled values:
  `"SELECT * FROM users WHERE id=" + req.params.id`
- Template literals or f-strings interpolating request data into SQL:
  `` `SELECT * FROM t WHERE name='${name}'` `` (JS),
  `f"SELECT ... WHERE id={user_id}"` (Python).
- ORM escape hatches passed unsanitized input — for example
  `db.execute(sql)` / `db.raw(...)` / `db.query(...)` /
  `sequelize.literal(...)` / Drizzle `sql.raw(...)` /
  `sqlalchemy.text(...)` where the argument is built from request data
  rather than parameterized.
- Dynamic `ORDER BY`, `LIMIT`, table names, or column names
  substituted from request input. These often can't be parameterized
  and require an explicit allowlist; their absence is a finding.
- String formatting (`sprintf`, `String.format`, `%s`) building
  a query.

## True positive criteria

A value that came from outside the trust boundary — HTTP request body,
query string, headers, cookies, message-queue payload, third-party API
response, file the user uploaded — flows into a SQL string without
parameter binding or strict allowlisting. The query is then executed.

## What to ignore

- Parameterized queries: `db.query("SELECT ... WHERE id = $1", [id])`,
  `?` placeholders, `%s` placeholders passed to drivers that bind
  parameters, `prepare()` + `execute(params)`.
- ORM query builders that bind parameters automatically:
  `db.users.findFirst({ where: { id } })` (Prisma),
  `db.query.users.findFirst(...)` (Drizzle builder API),
  `User.where(id: id)` (ActiveRecord with hash form),
  `session.query(User).filter(User.id == id)` (SQLAlchemy ORM).
- Fully static queries built from string constants only.
- Test fixtures, seed scripts, and migration files where the input
  comes from the developer, not a user.
- Internal admin tooling that's clearly documented as
  trusted-input-only.

## Examples

True positives:
- `` db.query(`SELECT * FROM users WHERE email='${req.body.email}'`) ``
- `cursor.execute("DELETE FROM posts WHERE id=" + str(post_id))`
- `Model.find_by_sql("SELECT * FROM t WHERE name = '#{params[:name]}'")`
- A handler that builds `"... ORDER BY " + req.query.sort` with no
  allowlist on the `sort` value.

False positives to skip:
- `db.execute("SELECT * FROM users WHERE id = ?", [id])`
- `prisma.user.findUnique({ where: { id } })`
- A constant query string with no interpolation at all.

## How to investigate (use the tools)

1. **Trace the SQL value.** Is the query string built locally, or
   passed in from a caller? If passed in, read the caller to find
   the actual construction site.
2. **Read the imports.** If the file routes through `db.run(sql)` or
   `repo.findBySql(sql)`, open the wrapper. Verify it uses parameter
   binding (`?`, `$1`, `:name`) instead of concatenating the argument
   into the final string.
3. **Tagged template vs function call.** `` sql`SELECT ... ${id}` ``
   parameterizes; `sql("SELECT ..." + id)` does not. The backtick is
   load-bearing.
4. **Dynamic identifiers.** `ORDER BY`, `LIMIT`, table/column names
   cannot be parameterized — require a strict allowlist on the value.
   Its absence is a finding.

When in doubt about whether a value crosses a trust boundary, trace
back one or two callers. If the value comes from a request handler's
parameters, body, or query string, it's untrusted.
