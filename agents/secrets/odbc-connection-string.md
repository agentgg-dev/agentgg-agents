---
slug: odbc-connection-string
name: ODBC Connection String with Credentials
description: 'ODBC connection strings containing username and password committed to source — direct database credentials enabling unauthorized data access.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(?i)(?:User\s*Id|UserId|Uid)\s*=\s*[^\s;]{3,};\s*.{0,10}(?:Password|Pwd)\s*='
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: ODBC connection string with username and password
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '(?i)(?:User|User\s*Id|UserId|Uid)\s*=\s*([^\s;]{3,100})\s*;[\ \t]*.{0,10}[\ \t]*(?:Password|Pwd)\s*=\s*([^\t\ ;]{3,100})\s*(?:[;]|$)'
      label: ODBC connection string credentials (User/Uid + Password/Pwd)
references:
  - CWE-798
  - CWE-256
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for ODBC connection strings that include database credentials.

## What an ODBC connection string looks like

```
Driver={SQL Server};Server=db.company.com;Database=prod;User Id=sa;Password=MyPass123;
Driver={PostgreSQL};Server=localhost;Database=app;Uid=admin;Pwd=secret;
```

Key fields: `User Id` / `UserId` / `Uid` and `Password` / `Pwd`.

## What leaked credentials enable

- Direct database access with the specified user's permissions
- If the user is a DBA or `sa` (SQL Server): full database control, schema modification, data extraction
- If credentials are reused elsewhere (common): lateral movement to other systems

## True positive criteria

Flag at critical:
1. `User Id=` and `Password=` both present with non-placeholder values
2. Connection string points to a production server (non-localhost, non-`.local`, production database names)
3. Password is not a placeholder like `{YOUR_PASSWORD}`, `<password>`, or `xxx`

Flag at high:
4. `Uid=` and `Pwd=` pattern with non-placeholder values even if server appears to be dev/staging

## What to ignore

- `Password=` with empty value: `Pwd=;` — no credential present
- Placeholder values: `Password={password}`, `Pwd=REPLACE_ME`
- `Integrated Security=SSPI` — uses Windows authentication, no password in the string

Report: the database type (SQL Server, PostgreSQL, MySQL, Oracle), the server hostname (to assess production vs. dev), and the username.
