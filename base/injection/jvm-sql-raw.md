---
slug: jvm-sql-raw
name: Raw SQL Injection (JVM — Java / Kotlin)
description: 'JDBC, JPA/Hibernate, Spring JdbcTemplate, MyBatis, jOOQ, and Exposed raw SQL built by string concatenation or interpolation. Traces repository/service helpers across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.(executeQuery|executeUpdate)\s*\(\s*"[^"]*"\s*\+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: JDBC Statement with concatenation
      - regex: '\.prepareStatement\s*\(\s*"[^"]*"\s*\+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: prepareStatement with concatenation (defeats parameterization)
      - regex: '\.(createNativeQuery|createQuery|createSQLQuery)\s*\(\s*"[^"]*"\s*\+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: JPA/Hibernate query with concatenation
      - regex: 'jdbcTemplate\.(query|update|queryForList|queryForObject)\s*\(\s*"[^"]*"\s*\+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring JdbcTemplate with concatenation
      - regex: '@(Select|Update|Insert|Delete)\s*\(\s*"[^"]*\$\{'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: 'MyBatis annotation using ${} (use #{} instead)'
      - regex: 'DSL\.(field|condition)\s*\(\s*"[^"]*"\s*\+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: jOOQ DSL.field/condition with concatenation
      - regex: 'exec\s*\(\s*"[^"]*\$\{'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: 'Kotlin SQL exec with ${} interpolation'
      - regex: '"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}\$\{'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: SQL string literal with Kotlin interpolation (any method)
      - regex: '"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}"\s*\+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: SQL string literal followed by concatenation (any method)
  prompt: Run only if this project uses jvm — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - java
    - kt
  excludePatterns:
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: '\.(executeQuery|executeUpdate)\s*\(\s*"[^"]*"\s*\+'
      label: JDBC Statement with concatenation
    - regex: '\.prepareStatement\s*\(\s*"[^"]*"\s*\+'
      label: prepareStatement with concatenation (defeats parameterization)
    - regex: '\.(createNativeQuery|createQuery|createSQLQuery)\s*\(\s*"[^"]*"\s*\+'
      label: JPA/Hibernate query with concatenation
    - regex: 'jdbcTemplate\.(query|update|queryForList|queryForObject)\s*\(\s*"[^"]*"\s*\+'
      label: Spring JdbcTemplate with concatenation
    - regex: '@(Select|Update|Insert|Delete)\s*\(\s*"[^"]*\$\{'
      label: 'MyBatis annotation using ${} (use #{} instead)'
    - regex: 'DSL\.(field|condition)\s*\(\s*"[^"]*"\s*\+'
      label: jOOQ DSL.field/condition with concatenation
    - regex: 'exec\s*\(\s*"[^"]*\$\{'
      label: 'Kotlin SQL exec with ${} interpolation'
    - regex: '"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}\$\{'
      label: SQL string literal with Kotlin interpolation (any method)
    - regex: '"\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"]{0,400}"\s*\+'
      label: SQL string literal followed by concatenation (any method)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing JVM source code (Java / Kotlin) for SQL injection
across JDBC, JPA/Hibernate, Spring JdbcTemplate, MyBatis, jOOQ, and
Exposed. The pattern is the same in every flavor: a SQL string built
by concatenation (`+`) or Kotlin string interpolation (`${...}`) with
user-controlled values, bypassing parameterization.

**Cross-file analysis:** Spring/JEE codebases route queries through
repository or DAO classes (`UserRepository`, `OrderDao`). The
concat may live in the repo while the request handler just calls
`repo.findByName(name)`. Follow imports/extends to verify whether
parameter binding actually happens at the SQL execution site.

## What to look for

**JDBC Statement (raw, no parameterization):**
```java
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
stmt.executeUpdate("DELETE FROM users WHERE id = " + id);
```
Safe form: use `PreparedStatement` with `?` placeholders.

**`prepareStatement` with concatenated string (defeats parameterization):**
```java
conn.prepareStatement("SELECT * FROM users WHERE name = '" + name + "'");
```
Safe form: `prepareStatement("... WHERE name = ?")` then
`stmt.setString(1, name)`.

**JPA / Hibernate native and JPQL queries with concat:**
```java
em.createNativeQuery("SELECT * FROM users WHERE id = " + id);
em.createQuery("FROM User u WHERE u.name = '" + name + "'");
session.createSQLQuery("SELECT * FROM x WHERE col = '" + col + "'");
```
Safe form: `createNativeQuery("SELECT * FROM users WHERE id = :id").setParameter("id", id)`.

**Spring JdbcTemplate:**
```java
jdbcTemplate.query("SELECT * FROM users WHERE id = " + id, mapper);
jdbcTemplate.update("UPDATE users SET role = '" + role + "' WHERE id = " + id);
```
Safe form: `jdbcTemplate.query("SELECT * FROM users WHERE id = ?", new Object[]{id}, mapper)`.

**MyBatis `@Select` with `${}`:**
```java
@Select("SELECT * FROM users WHERE id = ${id}")
```
MyBatis: `${}` substitutes raw string (unsafe); `#{}` parameterizes
(safe). Always prefer `#{id}`.

**Kotlin string interpolation:**
```kotlin
val rows = exec("SELECT * FROM users WHERE name = '${name}'")
val sql = "SELECT * FROM t WHERE col = '${input}'"
```

**jOOQ unsafe dynamic field/condition:**
```java
DSL.field("a." + col);
DSL.condition("name = '" + name + "'");
```

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing call is made: `Statement.executeQuery/Update`,
   `prepareStatement` (with concat), `createNativeQuery`, `createQuery`,
   `createSQLQuery`, `jdbcTemplate.query/update/queryForList`,
   `exec`, `@Select`, `@Update`, `DSL.field`, `DSL.condition`.
2. The SQL string includes `+` concatenation or Kotlin `${}`
   interpolation with a non-constant value.
3. The value originates from user input (HTTP request, message
   queue, etc.).

## What to ignore

- `PreparedStatement` with `?` placeholders and `setString`/`setInt`
  binding the values separately.
- JPA queries with `:name` named parameters and `setParameter`.
- JdbcTemplate calls passing values as an `Object[]` after a
  parameterized SQL string.
- MyBatis `#{param}` (parameterized).
- jOOQ DSL methods with type-safe operands (`USERS.ID.eq(id)`).
- Tests (typically under `src/test/`).

## Examples

True positives:
```java
// JDBC Statement — no parameterization possible
String userId = req.getParameter("id");
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// JPA native query with concat
em.createNativeQuery("SELECT * FROM users WHERE email = '" + email + "'");

// Spring JdbcTemplate with concat
jdbcTemplate.update("DELETE FROM users WHERE id = " + req.getParameter("id"));

// MyBatis ${} — substitutes raw string
@Select("SELECT * FROM users WHERE role = '${role}'")
List<User> findByRole(@Param("role") String role);
```

```kotlin
// Kotlin interpolation
val name = call.request.queryParameters["name"]
val rows = exec("SELECT * FROM users WHERE name = '${name}'")
```

False positives to skip:
```java
// PreparedStatement — safe
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);

// JdbcTemplate with parameter array
jdbcTemplate.query("SELECT * FROM users WHERE id = ?", new Object[]{userId}, mapper);

// MyBatis #{} — parameterized
@Select("SELECT * FROM users WHERE id = #{id}")
User findById(@Param("id") Long id);
```
