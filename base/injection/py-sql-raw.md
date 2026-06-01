---
slug: py-sql-raw
name: Raw SQL Injection (Python)
description: 'Python SQL execution (SQLAlchemy, psycopg, pymysql, sqlite3, asyncpg, Django ORM raw) with f-string, %-format, .format(), or + concatenation in the SQL string. Traces query helpers across modules.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.(execute|executemany)\s*\(\s*f["'']'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: cursor/session execute with f-string
      - regex: '\.(execute|executemany)\s*\(\s*["''][^"'']*["'']\s*%'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: cursor/session execute with %-format
      - regex: '\.(execute|executemany)\s*\(\s*["''][^"'']*["'']\.format\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: cursor/session execute with .format()
      - regex: '\.(execute|executemany)\s*\(\s*["''][^"'']*["'']\s*\+'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: cursor/session execute with + concat
      - regex: '\btext\s*\(\s*f["'']'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: SQLAlchemy text() with f-string
      - regex: '\.objects\.(raw|extra)\s*\(\s*f["'']'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: Django objects.raw/extra with f-string
      - regex: '(await\s+)?\w+\.execute\s*\(\s*f["'']'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/migrations/**'
          - '**/__pycache__/**'
        label: asyncpg-style execute with f-string
  prompt: Run only if this project uses python — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - py
  excludePatterns:
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/migrations/**'
    - '**/__pycache__/**'
  preFilter:
    - regex: '\.(execute|executemany)\s*\(\s*f["'']'
      label: cursor/session execute with f-string
    - regex: '\.(execute|executemany)\s*\(\s*["''][^"'']*["'']\s*%'
      label: cursor/session execute with %-format
    - regex: '\.(execute|executemany)\s*\(\s*["''][^"'']*["'']\.format\s*\('
      label: cursor/session execute with .format()
    - regex: '\.(execute|executemany)\s*\(\s*["''][^"'']*["'']\s*\+'
      label: cursor/session execute with + concat
    - regex: '\btext\s*\(\s*f["'']'
      label: SQLAlchemy text() with f-string
    - regex: '\.objects\.(raw|extra)\s*\(\s*f["'']'
      label: Django objects.raw/extra with f-string
    - regex: '(await\s+)?\w+\.execute\s*\(\s*f["'']'
      label: asyncpg-style execute with f-string
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing Python source code for SQL injection via raw SQL
escape hatches across popular database drivers and ORM raw query
APIs. The danger signal is the SQL string being built from user
input via f-strings, `%`-formatting, `.format()`, or `+`
concatenation — all of which bypass the driver's parameterization.

**Cross-file analysis:** Python projects routinely centralize SQL
in `repositories/` or `services/` modules. When a view function calls
`UserRepo.search(q)`, follow the import and read the repo to verify
whether the SQL uses bind parameters. Also trace `q` to confirm it
came from `request.args` / `request.json` (untrusted) versus an
internal call (trusted).

## What to look for

**SQLAlchemy:**
```python
engine.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
session.execute(f"UPDATE users SET role = '{role}'")
text(f"SELECT id FROM users WHERE email = '{email}'")
```
Safe form: `text("SELECT * FROM users WHERE name = :name")` with
`{"name": name}` as bind parameters.

**psycopg / psycopg2 / pymysql / sqlite3 / asyncpg `cursor.execute`:**
```python
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
cursor.execute("DELETE FROM x WHERE y = '" + name + "'")
cursor.execute("SELECT * FROM t WHERE col = '{}'".format(val))
```
Safe form (psycopg): `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`.
The trailing tuple is the parameter bind, not string formatting.

**Django ORM raw:**
```python
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.extra(where=[f"name = '{name}'"])
```
Safe form: `User.objects.raw("SELECT * FROM users WHERE name = %s", [name])`.

**asyncpg connection:**
```python
await conn.execute(f"DELETE FROM users WHERE id = {user_id}")
```
Safe form: `await conn.execute("DELETE FROM users WHERE id = $1", user_id)`.

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing call is made: `cursor.execute`, `cursor.executemany`,
   `engine.execute`, `session.execute`, `connection.execute`,
   `text(...)`, `Model.objects.raw`, `Model.objects.extra`,
   `await conn.execute`, etc.
2. The SQL string is built with f-string interpolation, `%`-formatting,
   `.format()`, or `+` concatenation.
3. The interpolated value comes from user input.

## What to ignore

- `cursor.execute("...", (param,))` — string parameters as the second
  argument, NOT string-format-style.
- `text("SELECT ... WHERE x = :name")` with bind parameters supplied
  separately — safe.
- Hardcoded SQL with no interpolation.
- Identifier interpolation against a strict allowlist of column/table
  names.
- Test and migration files.

## Examples

True positives:
```python
# f-string SQL with request input
user_id = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SQLAlchemy text() with f-string
engine.execute(text(f"SELECT * FROM orders WHERE status = '{request.form['status']}'"))

# Django raw — f-string
User.objects.raw(f"SELECT * FROM users WHERE email = '{request.POST['email']}'")

# % formatting
cursor.execute("DELETE FROM users WHERE id = %s" % user_id)  # NOT a parameter — this is Python string formatting

# asyncpg with f-string
await conn.execute(f"UPDATE users SET role = '{role}'")
```

False positives to skip:
```python
# Properly parameterized
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SQLAlchemy with bind parameters
session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})

# Django raw with parameters
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])

# asyncpg with positional args
await conn.execute("DELETE FROM users WHERE id = $1", user_id)
```
