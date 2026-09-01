---
slug: apache-config-audit
name: Apache HTTP Server Configuration Security Audit
description: 'Apache httpd.conf/apache2.conf security checks: directory listing enabled, TRACE method enabled, server version disclosure (ServerTokens Full, ServerSignature On), and missing security headers — common Apache hardening gaps.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)(?:ServerTokens|ServerSignature|Options\s+Indexes|TraceEnable)'
        in:
          - '**/httpd.conf'
          - '**/apache2.conf'
          - '**/apache/**/*.conf'
          - '**/sites-available/**'
          - '**/sites-enabled/**'
          - '**/.htaccess'
        notIn:
          - '**/node_modules/**'
        label: Apache configuration directives found
where:
  extensions:
    - conf
  filePatterns:
    - '**/httpd.conf'
    - '**/apache2.conf'
    - '**/apache/**/*.conf'
    - '**/sites-available/**'
    - '**/sites-enabled/**'
    - '**/.htaccess'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
  preFilter:
    - regex: '(?i)Options\s+(?:[A-Za-z]+\s+)*Indexes'
      label: Directory listing enabled (Options Indexes)
    - regex: '(?i)TraceEnable\s+On'
      label: TRACE method enabled
    - regex: '(?i)ServerTokens\s+(?:Full|OS|Minor|Major|Minimal)'
      label: ServerTokens discloses version info
    - regex: '(?i)ServerSignature\s+On'
      label: ServerSignature adds version to error pages
references:
  - CWE-16
  - CWE-200
  - CWE-693
---

You are auditing Apache HTTP Server configuration files for security hardening gaps.

## Checks to perform

### Directory listing — Options Indexes

```apache
Options Indexes FollowSymLinks  # VULNERABLE: lists directory contents when no index file
Options -Indexes FollowSymLinks # correct: directory listing disabled
```

`Options Indexes` allows attackers to browse directory contents, exposing file names, backup files, config files, and source code. Flag any `Options` directive that includes `Indexes` without a preceding `-`.

### TRACE method — TraceEnable

```apache
TraceEnable On    # high: enables HTTP TRACE — potential for cross-site tracing (XST)
TraceEnable Off   # correct
```

HTTP TRACE echoes the request back to the client, including cookies and authentication headers. Combined with XSS, enables cross-site tracing attacks.

### Server version disclosure — ServerTokens

```apache
ServerTokens Full      # high: Apache/2.4.51 (Ubuntu) in headers — reveals exact version
ServerTokens OS        # high: reveals OS
ServerTokens Minimal   # medium: Apache/2.4.51 — reveals Apache version
ServerTokens Prod      # correct: "Apache" only
```

Version disclosure helps attackers target known CVEs. Flag anything other than `Prod` or `Major`.

### Error page version disclosure — ServerSignature

```apache
ServerSignature On    # medium: adds Apache version to 404/500 error pages
ServerSignature Off   # correct
ServerSignature Email # acceptable: shows ServerAdmin email but no version
```

## True positive criteria

Flag at high:
1. `Options Indexes` in any active `<Directory>`, `<Location>`, or `<VirtualHost>` block — directory listing
2. `TraceEnable On`
3. `ServerTokens Full` or `ServerTokens OS`

Flag at medium:
4. `ServerTokens Minimal` or `ServerTokens Minor` — partial version disclosure
5. `ServerSignature On`

## What to ignore

- `Options -Indexes` — directory listing explicitly disabled (correct)
- `Options Indexes` in a context overridden by a more specific block with `-Indexes`
- Comments explaining what the directive does but not actually setting it

## Evaluation approach

Read the full config file including `<Directory>` blocks and `Include` directives. The most specific matching directive wins — a global `Options -Indexes` can be overridden by a `<Directory "/var/www/uploads"> Options Indexes </Directory>`.

Report: each misconfigured directive, its location (main config, VirtualHost, Directory block), and whether it affects the whole server or a specific path.
