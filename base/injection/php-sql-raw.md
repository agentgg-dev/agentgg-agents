---
slug: php-sql-raw
name: Raw SQL Injection (PHP)
description: 'PHP SQL execution (PDO, mysqli, Doctrine ORM/DBAL) with string concatenation in the query — including .prepare() with concatenation, which defeats parameterization. Walker mode traces SQL helpers and request sources.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '->\s*(query|exec|prepare)\s*\(\s*["''][^"'']*["'']\s*\.'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/Tests/**'
        label: PDO query/exec/prepare with .  concatenation
      - regex: 'mysqli_query\s*\([^,]+,\s*["''][^"'']*["'']\s*\.'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/Tests/**'
        label: mysqli_query with concatenation
      - regex: '->\s*(executeQuery|executeStatement|createQuery|createNativeQuery)\s*\(\s*["''][^"'']*["'']\s*\.'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/Tests/**'
        label: Doctrine query with concatenation
  prompt: Run only if this project uses php — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - php
  excludePatterns:
    - '**/vendor/**'
    - '**/tests/**'
    - '**/Tests/**'
  preFilter:
    - regex: '->\s*(query|exec|prepare)\s*\(\s*["''][^"'']*["'']\s*\.'
      label: PDO query/exec/prepare with .  concatenation
    - regex: 'mysqli_query\s*\([^,]+,\s*["''][^"'']*["'']\s*\.'
      label: mysqli_query with concatenation
    - regex: '->\s*(executeQuery|executeStatement|createQuery|createNativeQuery)\s*\(\s*["''][^"'']*["'']\s*\.'
      label: Doctrine query with concatenation
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing PHP source code for SQL injection in PDO, mysqli,
Doctrine ORM/DBAL, and Laravel raw query APIs. The unsafe pattern is
PHP string concatenation (`.`) used to build the SQL string from user
input, including `prepare()` calls — concatenation defeats
parameterization even when prepare/execute is used.

**Walker mode advantage:** Symfony/Laravel apps typically funnel SQL
through repository or service classes. The dangerous concatenation
may be one method away from the controller. Follow `use` statements
and class hierarchies to find the real execution site, and trace
whether the value came from `$_GET`/`$_POST`/`Request` without
escaping.

## What to look for

**PDO with concatenation:**
```php
$result = $pdo->query("SELECT * FROM users WHERE id = " . $id);
$pdo->exec("DELETE FROM users WHERE name = '" . $name . "'");
$stmt = $pdo->prepare("SELECT * FROM t WHERE col = '" . $col . "'");
```
Safe form: `$stmt = $pdo->prepare("SELECT * FROM t WHERE col = ?")`
then `$stmt->execute([$col])`.

**mysqli with concatenation:**
```php
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $userId);
$conn->query("DELETE FROM x WHERE y = '" . $y . "'");
```
Safe form: `mysqli_prepare` with `bind_param`.

**Doctrine DBAL / ORM with concatenation:**
```php
$conn->executeQuery("UPDATE users SET role = '" . $role . "' WHERE id = " . $id);
$conn->executeStatement("DELETE FROM users WHERE id = " . $id);
$em->createQuery("SELECT u FROM App\\User u WHERE u.name = '" . $name . "'");
$em->createNativeQuery("SELECT * FROM users WHERE id = " . $id, $rsm);
```
Safe form: `$conn->executeQuery("UPDATE users SET role = ? WHERE id = ?", [$role, $id])`.

**Building SQL strings ahead of execution:**
```php
$sql = "INSERT INTO logs (msg) VALUES ('" . $msg . "')";
$pdo->exec($sql);
```

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing call is made: `query`, `exec`, `prepare`,
   `executeQuery`, `executeStatement`, `createQuery`,
   `createNativeQuery`, `mysqli_query`.
2. The SQL string is built with PHP `.` concatenation involving a
   variable.
3. The variable's value comes from user input (`$_GET`, `$_POST`,
   `$_REQUEST`, `$_COOKIE`, Symfony request, Laravel request).

## What to ignore

- Parameterized queries: `$pdo->prepare("... = ?")->execute([$value])`,
  `$mysqli->prepare(...)` with `bind_param`, Doctrine
  `executeQuery("...", [$value])`.
- Hardcoded SQL with no variable concatenation.
- Identifier interpolation against a strict allowlist.
- Test and vendor files.

## Examples

True positives:
```php
// PDO query with concat
$id = $_GET['id'];
$result = $pdo->query("SELECT * FROM users WHERE id = " . $id);

// prepare with concat — bypasses parameterization
$col = $_POST['col'];
$stmt = $pdo->prepare("SELECT * FROM t WHERE col = '" . $col . "'");

// Doctrine native query with concat
$id = $request->get('id');
$em->createNativeQuery("SELECT * FROM users WHERE id = " . $id, $rsm);
```

False positives to skip:
```php
// Parameterized — safe
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Doctrine with parameters
$conn->executeQuery("UPDATE users SET role = ? WHERE id = ?", [$role, $id]);

// Hardcoded SQL
$pdo->query("SELECT NOW()");
```
