---
slug: basic-auth-url
name: Credentials in URL (Basic Auth)
description: 'URLs with embedded username:password credentials in source code or config — the password is committed in plaintext and exposed to anyone with repo access, and may appear in HTTP logs, browser history, and Referer headers.'
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
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '(?i)(https?|ftp|mongodb|postgresql|postgres|mysql|redis|amqp|amqps|smtp|smtps)://[^@\s/]{2,}:[^@\s/]{3,}@[a-zA-Z0-9]'
      label: URL with user:password@ credential
references:
  - CWE-312
  - CWE-798
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for URLs that embed credentials in the `user:password@host` form. Credentials in URLs are committed to version control in plaintext and leak through HTTP logs, browser history, Referer headers, and error messages.

## URL credential shapes

```
postgres://admin:hunter2@db.prod.internal:5432/appdb
mysql://root:S3cr3tP@ss@10.0.1.5/myapp
mongodb://appuser:realpassword@cluster0.abc123.mongodb.net/mydb
redis://:authtoken123@redis.prod.internal:6379
https://myuser:mypassword@internal-api.example.com/v1/data
amqp://worker:amqppass@rabbitmq.prod.internal:5672/vhost
smtp://noreply%40example.com:emailpassword@smtp.mailserver.com:587
ftp://ftpuser:ftppassword@files.example.com
```

## Cross-file analysis

When a credential URL is found:
1. Identify the protocol and service (Postgres, MongoDB, Redis, internal API, etc.)
2. Determine whether the host is production or staging by examining the hostname and any surrounding config
3. Look for whether the URL is also logged, printed in error messages, or passed to a monitoring tool — all of these expand the exposure

## True positive criteria

Flag when ALL hold:
1. The URL contains a `user:password@host` structure where the password is a real value
2. The value is a string literal — not read from an environment variable like `process.env.DATABASE_URL`
3. The password is not a placeholder: not `password`, `changeme`, `yourpassword`, `<password>`, `REPLACE_ME`, `xxxx`

## What to ignore

- URLs where the password portion is an environment variable substitution: `postgres://user:${DB_PASS}@host`, `mysql://user:#{DB_PASSWORD}@host`
- Documentation examples with obvious placeholder passwords: `http://user:password@example.com`, `https://admin:admin@localhost`
- Test or seed files using well-known dev passwords against `localhost` or `127.0.0.1` where the surrounding code makes clear it's only for local development
- Redis URLs with no password: `redis://localhost:6379` (no credentials embedded)
- URLs where the password field is empty: `http://user:@host`

## Common protocol risks

| Protocol | Risk when leaked |
|----------|-----------------|
| postgres/mysql/mongodb | Full database read/write |
| redis | Cache poisoning, session theft if used for sessions |
| amqp/amqps | Message queue access, potential command injection via messages |
| smtp | Send email as that account, spam |
| https/http | Depends on the API — could be admin access |
| ftp | File read/write on the FTP server |

## Examples

True positives:
```ts
const db = new Pool({ connectionString: 'postgres://admin:Hunter2!@db.prod.internal:5432/app' });
```
```yaml
REDIS_URL: redis://:r3dis_s3cr3t@redis.prod.internal:6379/0
```
```python
engine = create_engine('mysql://root:Pr0d_P@ss@10.0.1.5/myapp')
```

False positives to skip:
```ts
const db = new Pool({ connectionString: process.env.DATABASE_URL });
```
```yaml
REDIS_URL: redis://:${REDIS_PASSWORD}@redis.prod.internal:6379
```
```
# Documentation
postgres://user:password@localhost:5432/mydb
```

Report the protocol and service, the host (to assess if it's production), and whether the URL is also visible in logs or error output.
