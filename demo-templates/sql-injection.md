---
slug: sql-injection
name: SQL Injection
description: SQL queries built by concatenating or interpolating untrusted input instead of using parameterized queries. Follows query helpers and ORM wrappers to confirm whether parameterization is actually applied.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: "\\.(query|execute|exec|run|raw)\\s*\\(|cursor\\s*\\(|fmt\\.Sprintf\\s*\\([^)]*(SELECT|INSERT|UPDATE|DELETE)"
        in:
          - "**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go,php,java,kt,cs}"
        notIn:
          - "**/*.{test,spec}.*"
        label: "raw SQL execution call present"
where:
  extensions: [ts, tsx, js, jsx, mjs, cjs, py, rb, go, php, java, kt, cs]
  excludePatterns:
    - "**/__tests__/**"
    - "**/*.{test,spec}.*"
    - "**/migrations/**"
  preFilter:
    - regex: "\\.(query|execute|exec|run|raw)\\s*\\(\\s*`[^`]*\\$\\{"
      label: "SQL call with template-literal interpolation"
    - regex: "\\.(query|execute|exec|run|raw)\\s*\\([^)]*\\+\\s*(req|params|body|input|args|query|userInput)"
      label: "SQL call concatenating request data"
    - regex: "(execute|cursor|conn)\\s*\\(\\s*f['\"]"
      label: "Python SQL with f-string"
    - regex: "fmt\\.Sprintf\\s*\\([^)]*(SELECT|INSERT|UPDATE|DELETE)"
      label: "Go fmt.Sprintf building SQL"
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing source code for SQL injection: queries built by
string concatenation or interpolation of untrusted input instead of
parameterized/prepared statements.

SQL is frequently routed through shared helpers. When a flagged line
calls something like `db.run(sql)`, use Read/Grep to open the helper
and confirm whether the value reaches the driver parameterized or as
raw string. Only flag when untrusted input reaches the query string
unparameterized.

## True positives

```ts
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
cursor.execute(f"SELECT * FROM t WHERE name = '{name}'")
db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))
```

## Safe — skip

```ts
db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
cursor.execute("SELECT * FROM t WHERE name = %s", (name,))
```

Dynamic `ORDER BY`/identifier interpolation against a fixed allowlist
is safe; interpolation of arbitrary request data is not. Confirm the
source of the interpolated value before flagging.
