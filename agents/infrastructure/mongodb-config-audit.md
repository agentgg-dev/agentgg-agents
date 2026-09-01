---
slug: mongodb-config-audit
name: MongoDB Configuration Security Audit
description: 'mongod.conf security checks: authentication disabled, SSL/TLS not required, audit logging absent, and HTTP interface enabled — misconfigurations that expose MongoDB to unauthorized access or data interception.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'operationProfiling|storage:|security:|net:|systemLog:'
        in:
          - '**/mongod.conf'
          - '**/mongodb.conf'
          - '**/mongos.conf'
        notIn:
          - '**/node_modules/**'
        label: MongoDB configuration file directives found
where:
  extensions:
    - conf
  filePatterns:
    - '**/mongod.conf'
    - '**/mongodb.conf'
    - '**/mongos.conf'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
  preFilter:
    - regex: 'storage:|operationProfiling:'
      label: MongoDB config file markers
    - regex: 'authorization:\s*(?!enabled)'
      label: authorization not enabled
    - regex: 'mode:\s*disabled'
      label: SSL mode disabled
references:
  - CWE-306
  - CWE-311
  - CWE-778
---

You are auditing MongoDB configuration files (`mongod.conf`) for security hardening gaps. Misconfigurations in MongoDB have led to mass data breaches (the "MongoDB Apocalypse" of 2017 exposed ~28,000 databases).

## Checks to perform

### Authentication — must be enabled

```yaml
security:
  authorization: enabled   # correct: requires username/password
```

If the `security` section is missing or `authorization` is not set to `enabled`, MongoDB accepts connections from any host without credentials.

**Flag when:** `authorization: enabled` is absent from the `security:` section, or the `security:` section itself is missing.

### SSL/TLS — should be required

```yaml
net:
  ssl:
    mode: requireSSL          # correct: all connections must use TLS
    PEMKeyFile: /path/to/cert
    
net:
  ssl:
    mode: disabled            # critical: plaintext connections allowed
    mode: allowSSL            # medium: TLS optional, not enforced
```

Without TLS, credentials and data are transmitted in plaintext on the network.

### Audit logging — should be enabled (for production)

```yaml
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/auditLog.json
```

Without audit logging, there is no record of who accessed what data — relevant for GDPR, SOC 2, HIPAA compliance.

**Flag when:** the `auditLog:` section is absent from a production configuration.

### HTTP interface — should be disabled

```yaml
net:
  http:
    enabled: false     # correct
    enabled: true      # critical: exposes HTTP API and REST interface
```

MongoDB's HTTP interface (port 28017) exposes server status, configuration, and in older versions a REST API — without authentication. This was the primary attack vector in the 2017 mass-exploitation.

**Note:** The HTTP interface was removed in MongoDB 3.6+. Only flag if the config explicitly enables it (indicating old MongoDB version).

## True positive criteria

Flag at critical:
1. Authentication disabled (`authorization` not set to `enabled`)
2. `net.http.enabled: true` — HTTP interface exposed

Flag at high:
3. SSL mode set to `disabled` or `allowSSL` (TLS not enforced)

Flag at medium:
4. No `auditLog` section in a production config (context-dependent — skip for development configs)

## What to ignore

- Development or test configs (watch for markers: `dev`, `test`, `local` in the file path)
- `allowSSL` in development environments where encryption is less critical

## How to distinguish production configs

Look for: non-localhost `bindIp`, production data paths (`/var/lib/mongodb`), replica set names, or explicit environment comments.

Report: each misconfigured directive, its current value, and the recommended secure value. Note the MongoDB version if discernible from the config (some directives only apply to specific versions).
