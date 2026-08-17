---
slug: second-order-sql
name: Second-Order SQL Injection
description: 'A value previously stored in or read from the database (an ORM result or prior query row) is later concatenated/interpolated into a raw SQL string without parameterization. The source is a DB read, not a direct request param, so first-order SQLi agents miss it. Traces tainted columns back to a DB read across files.'
version: 0.1.0
author: agentgg
noiseTier: noisy
precondition:
  regex:
    patterns:
      - regex: '(query|execute|exec|raw|rawQuery|createQuery|prepareStatement)\s*\(\s*[`"''][^`"'']*(SELECT|INSERT|UPDATE|DELETE)[^`"'']*[`"'']\s*(\+|\$\{|%|\.format|f[''"])'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/*_test.go'
          - '**/spec/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Raw SQL string built with concatenation/interpolation
      - regex: '[`"''][^`"'']*(SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES)[^`"'']*[`"'']\s*(\+|\.|%)\s*\w'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/*_test.go'
          - '**/spec/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
        label: SQL keyword string joined to a variable
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - php
    - java
    - kt
    - cs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/*_test.go'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '(query|execute|exec|raw|rawQuery|createQuery|prepareStatement)\s*\(\s*[`"''][^`"'']*(SELECT|INSERT|UPDATE|DELETE)[^`"'']*[`"'']\s*(\+|\$\{|%|\.format|f[''"])'
      label: Raw SQL string built with concatenation/interpolation
    - regex: '[`"''][^`"'']*(SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES)[^`"'']*[`"'']\s*(\+|\.|%)\s*\w'
      label: SQL keyword string joined to a variable
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
---

You are reviewing source for second-order (stored) SQL injection — a
raw SQL string is built by concatenating or interpolating a value that
was *previously read from the database*, not taken directly from the
current request. Because the value already passed through a write at
some earlier point (e.g. a username chosen at signup, a profile field),
first-order SQLi checks on the immediate handler see no request param
and miss it. But the stored value is still attacker-controlled, so when
it later flows unparameterized into a query, the injection fires.

**Cross-file analysis is essential here.** The tainted value is a column
read from an ORM result or a prior query row, often in a different file
from where it was written. For every variable concatenated into a raw
query, trace it back: Where did it come from? If it is a field of a
`User`/record object, a row returned by an earlier `SELECT`, or an ORM
`findOne`/`get`/`first` result, then ask: could a user have controlled
that column at write time (signup, profile edit, import, any
INSERT/UPDATE reachable by users)? If yes, this is second-order SQLi.

## What to look for

- A value pulled from a DB read, then concatenated into a later raw
  query:
  ```js
  const user = await db.query("SELECT * FROM users WHERE id=?", [id]);
  // user.name was set by the user at signup
  await db.query("SELECT * FROM logs WHERE actor='" + user.name + "'");
  ```
- ORM result fields interpolated into raw SQL:
  ```python
  row = User.objects.get(id=uid)
  cursor.execute("UPDATE stats SET note='" + row.bio + "' WHERE ...")
  ```
- Reprocessing jobs / migrations / reports that read rows and rebuild
  queries from column values:
  ```php
  $u = $pdo->query("SELECT username FROM users")->fetch();
  $pdo->query("SELECT * FROM posts WHERE author='" . $u['username'] . "'");
  ```
- Go/Java/.NET: a struct field or `ResultSet`/`DataReader` value
  concatenated into the next `db.Query`/`Statement`/`SqlCommand` text.

## How to investigate (use the tools)

For each raw-SQL concatenation candidate:
1. Identify the interpolated variable(s).
2. Trace each one to its definition. If it is a literal, a server
   constant, or a freshly-parameterized request value, it is not this
   bug (it may be ordinary first-order SQLi — out of scope here).
3. If it is a field read from the DB (ORM object field, query row,
   `findOne`/`get`/`first`/`fetch`/`Scan` result), determine whether
   any user can influence that column via an earlier INSERT/UPDATE.
   Open the write path if needed.
4. Confirm the later query uses string building, not bound parameters.

## True positive criteria

A finding is real when a value originating from a DB read is placed
into a raw SQL string by concatenation/interpolation (not a bound
parameter) AND that DB column is one a user could have written earlier.

You must be able to say: "I am a registered user. At signup I set my
username to `x' OR '1'='1`. It is stored verbatim. Later, the reporting
query reads my username from the DB and concatenates it into raw SQL, so
my stored payload executes against the database." Name the attacker
(the user who wrote the column) and the trust boundary (the original
write path). The burden is on the code to prove either the later query
is parameterized or the column cannot be user-influenced.

## What to ignore

- Raw queries whose interpolated value comes directly from the current
  request without a DB round-trip — that is first-order SQLi, covered
  by the sql-injection agent; do not double-report it here.
- Concatenation of values that are not from a DB read: literals, enums,
  server-generated IDs, validated numeric values.
- DB-read values that are bound as parameters in the later query
  (`?`, `$1`, `:name`, `%s` with a params tuple) — parameterization
  defeats it.
- DB columns that are provably not user-writable (system-populated
  timestamps, auto-increment IDs, server-set enums) AND are not
  numerically/structurally exploitable.
- Identifiers (table/column names) chosen from a fixed allowlist even
  though they are concatenated.

## Examples

True positives:
```js
const u = await userRepo.findOne({ id });
await db.query(`SELECT * FROM orders WHERE customer = '${u.username}'`);
```
```python
acct = Account.objects.get(pk=pk)
cur.execute("DELETE FROM sessions WHERE owner='%s'" % acct.email)
```
```php
$row = $db->query("SELECT alias FROM users LIMIT 1")->fetch();
$db->query("SELECT * FROM logs WHERE who = '".$row['alias']."'");
```

False positives to skip:
```js
const u = await userRepo.findOne({ id });
await db.query("SELECT * FROM orders WHERE customer = ?", [u.username]);
```
```python
row = User.objects.get(id=uid)
cur.execute("UPDATE x SET seen=1 WHERE id=%s", (row.id,))
```
```js
await db.query(`SELECT * FROM t WHERE flag = ${req.query.f}`);
```
(the last one is first-order SQLi — let the sql-injection agent handle it)

This class is noisy: many concatenations are first-order or use
constants. Be disciplined — only flag when you have traced the value to
a DB read of a plausibly user-written column AND confirmed the later
query is not parameterized.
