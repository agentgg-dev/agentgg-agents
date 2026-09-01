---
slug: static-backup-exposure
name: Exposed Static / Backup Files & Directory Listings
description: 'Static-file middleware (express.static, serve-static, serve-index, Spring Resource handler, Django staticfiles) mounted over directories that contain backups, dotfiles, keys, logs, or `.git` — or that enable directory browsing (autoindex).'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
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
      - conf
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
    - conf
  filePatterns:
    - '**/nginx*.conf'
  preFilter:
    - semgrepRule: exposure/static-file-exposure
      label: express.static, serveIndex, or static file serve call
references:
  - CWE-538
  - CWE-548
  - 'OWASP-A05:2021'
---

You are reviewing source code for exposed static or backup files —
HTTP static-file handlers mounted over directories that should never be
web-reachable, OR explicitly enabled directory listing that lets a
visitor enumerate files (then download `.bak`, `.git/`, `.env`,
`*.pem`, log files, password lists).

The bug is twofold:
1. **Wrong directory mounted** — `app.use(express.static("/"))` or
   `serve("./")` exposes the whole project tree.
2. **Directory listing enabled** — `serve-index`, nginx `autoindex on;`,
   Apache `Options +Indexes` — lets the attacker discover filenames
   you didn't intend to publish.

## What to look for

**Node.js — express / connect / serve-static:**
```ts
app.use(express.static("."));
app.use(express.static(path.resolve(".")));
app.use("/files", express.static("uploads"));        // OK if uploads has only user-safe content
app.use("/keys", express.static("encryptionkeys"));  // catastrophic
app.use("/logs", express.static("logs"));
```

**Node.js — serve-index (directory browsing):**
```ts
import serveIndex from "serve-index";
app.use("/", serveIndex("public", { icons: true }));
app.use("/ftp", serveIndex("ftp", { view: "details" }));   // browseable file dump
```

**Node.js — fastify-static / koa-static / koa-mount:**
```ts
fastify.register(fastifyStatic, { root: path.resolve("."), serve: true });
```

**Python — Flask:**
```python
app = Flask(__name__, static_folder="..", static_url_path="/static")
@app.route("/files/<path:p>")
def files(p):
    return send_from_directory("/var/data", p)        # any p, no allowlist
```

**Python — Django:**
- Serving `MEDIA_ROOT` with `show_indexes=True` via `static()` in
  `urls.py`.
- `DEBUG = True` exposes `/static/` listing automatically.

**Java — Spring:**
```java
@Override
public void addResourceHandlers(ResourceHandlerRegistry r) {
    r.addResourceHandler("/files/**")
     .addResourceLocations("file:///");                 // exposes entire FS
}
```

**Nginx config:**
```nginx
location /downloads {
    autoindex on;
    alias /var/data;
}
```

**Apache config:**
```
Options +Indexes
```

**Path/directory red flags as mount targets:**
- `.`, `..`, `/`, `path.resolve(".")`, `process.cwd()`.
- `encryptionkeys`, `keys`, `secrets`, `.ssh`.
- `logs`, `log`, `support/logs`, `access.log`.
- `.git`, `.svn`, `.env`, `.well-known` (the last one is OK if scoped
  to `acme-challenge` only).
- `ftp`, `uploads` when uploads aren't sanitized.
- `backup`, `dump`, `archive`, `*.bak`, `*.sql`, `*.tar.gz`.

## True positive criteria

Flag when ANY of the following hold:

1. A static handler / autoindex is mounted over a directory that
   contains files outside the intended web-published set: secrets,
   keys, logs, backups, source, `.git`.
2. Directory listing is explicitly enabled (`serveIndex`,
   `autoindex on`, `Options +Indexes`, Django `show_indexes=True`)
   over user-reachable paths.
3. A static handler is rooted at `.`, `/`, or `process.cwd()`.

## What to ignore

- `express.static("public")` or `express.static("dist")` where the
  directory contains only built frontend assets — that's the safe
  pattern.
- `serveStatic` with an explicit `dotfiles: "ignore"` and a content
  directory that's reviewed.
- `.well-known/acme-challenge` for Let's Encrypt — limited subpath,
  required for ACME.
- Internal-only services behind a reverse proxy that strips listing
  responses (rare; don't assume this).

## Examples

True positives:
```ts
// Encryption keys directory exposed
app.use("/encryptionkeys", serveIndex("encryptionkeys", { view: "details" }));
app.use("/encryptionkeys", express.static("encryptionkeys"));

// FTP directory with arbitrary files browseable
app.use("/ftp", serveIndex("ftp", { icons: true }));
app.use("/ftp", express.static("ftp"));

// Logs served as static
app.use("/support/logs", express.static("logs"));

// Rooted at project root
app.use(express.static("."));
```
```nginx
location /backup {
    autoindex on;
    alias /opt/app/backups;
}
```

False positives to skip:
```ts
// Built frontend bundle — intended public
app.use(express.static(path.resolve("frontend/dist")));

// .well-known scoped to ACME only
app.use("/.well-known/acme-challenge", express.static("/var/acme"));

// Public marketing assets
app.use("/assets", express.static("public/assets"));
```

The pattern to internalize: `express.static(dir)` is fine when `dir`
contains only files you'd happily print on a billboard. Anything else
(keys, logs, source, configs, customer uploads without sanitization)
is a leak waiting to be discovered.
