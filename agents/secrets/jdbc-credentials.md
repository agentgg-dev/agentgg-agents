---
slug: jdbc-credentials
name: JDBC Connection String with Embedded Credentials
description: 'JDBC connection strings with embedded passwords, or Spring/Hibernate datasource password properties set to literal values. Direct database credentials are among the highest-severity secret exposures.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
    - '**/target/**'
    - '**/__tests__/**'
    - '**/*.test.*'
    - '**/*.spec.*'
  preFilter:
    - regex: 'jdbc:(?:mysql|postgresql|postgres|oracle|sqlserver|mariadb|db2)://[^/\s]*:[^/\s@]{3,}@[a-zA-Z0-9]'
      label: JDBC URL with embedded password (user:pass@host)
    - regex: 'jdbc:[^;]+;[Pp]assword=[^;''"\s${\s]{4,}'
      label: JDBC connection string with Password= parameter
    - regex: '(?i)(?:spring\.datasource\.password|db\.password|database\.password)\s*=\s*[^${\s][^\s]{3,}'
      label: Spring/app datasource password property with literal value
    - regex: '(?i)(?:hibernate\.connection\.password|javax\.persistence\.jdbc\.password)\s*=\s*[^${\s][^\s]{3,}'
      label: Hibernate/JPA password property with literal value
references:
  - CWE-798
  - CWE-259
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for JDBC connection strings or database configuration properties that contain hardcoded passwords. Direct database access is one of the highest-severity secret exposures.

## Vulnerable patterns

**JDBC URL with embedded credentials:**
```
jdbc:mysql://dbuser:s3cr3tP4ss@prod-db.internal:3306/myapp
jdbc:postgresql://admin:hunter2@db.example.com:5432/production
```

**JDBC URL with query parameter credentials:**
```
jdbc:sqlserver://prod-db.internal:1433;user=sa;password=Pr0dP@ssw0rd;databaseName=myapp
```

**Spring Boot / application.properties:**
```properties
spring.datasource.password=Pr0dP@ssw0rd
```

## True positive criteria

Flag when ALL hold:
1. A JDBC URL or password property contains a non-placeholder literal value
2. The host or context suggests a real database (not `localhost` test-only, not `h2:mem:testdb`)
3. The password is not a Spring placeholder (`${DB_PASSWORD}`) or env var reference

## What to ignore

- Placeholder values: `<password>`, `${DB_PASSWORD}`, `your-password-here`
- H2 in-memory test databases: `jdbc:h2:mem:testdb`
- `application-test.properties` with test credentials — lower severity, note only

## Examples

True positive:
```properties
spring.datasource.url=jdbc:postgresql://prod-db.internal:5432/myapp
spring.datasource.password=Pr0dP@ssw0rd!
```

False positive to skip:
```properties
spring.datasource.password=${POSTGRES_PASSWORD}
```

Report the database type, whether the host suggests production vs development, and what data the database likely contains.
