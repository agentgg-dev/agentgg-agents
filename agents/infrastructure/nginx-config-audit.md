---
slug: nginx-config-audit
name: Nginx Configuration Security Audit
description: 'nginx.conf security checks: server_tokens on (version disclosure), missing X-XSS-Protection header, missing HSTS header, no rate limiting, and missing buffer overflow protection directives — common nginx hardening gaps.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?:server_tokens|add_header\s+X-XSS-Protection|add_header\s+Strict-Transport|limit_req_zone|client_body_buffer_size)'
        in:
          - '**/nginx.conf'
          - '**/nginx/**/*.conf'
          - '**/sites-available/**'
          - '**/sites-enabled/**'
        notIn:
          - '**/node_modules/**'
        label: nginx configuration directives found
where:
  extensions:
    - conf
  filePatterns:
    - '**/nginx.conf'
    - '**/nginx/**/*.conf'
    - '**/sites-available/**'
    - '**/sites-enabled/**'
    - '**/conf.d/**'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
  preFilter:
    - regex: 'server_tokens\s+on'
      label: server_tokens on (version disclosure)
    - regex: '^(?!.*add_header\s+X-XSS-Protection).*http\s*\{|events\s*\{'
      label: nginx config without X-XSS-Protection header
    - regex: 'http\s*\{|server\s*\{'
      label: nginx http or server block
references:
  - CWE-16
  - CWE-693
---

You are auditing nginx configuration files for security hardening gaps. These are common misconfigurations that reduce the security posture of nginx-served applications.

## Checks to perform

### server_tokens — should be "off"

```nginx
server_tokens on;   # reveals nginx version in Server header and error pages
server_tokens off;  # correct: hides version
```

Version disclosure helps attackers target known CVEs. Flag `server_tokens on` or the absence of `server_tokens off`.

### X-XSS-Protection header — should be present

```nginx
# Missing — no XSS filter hint to legacy browsers
add_header X-XSS-Protection "1; mode=block";  # correct
```

While modern browsers ignore this header in favor of CSP, it protects users on legacy browsers (IE/Edge pre-Chromium). Flag if the header is absent in the `http {}` block.

### HSTS — Strict-Transport-Security — should be present for HTTPS servers

```nginx
# Missing — browsers won't enforce HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;  # correct
```

Without HSTS, browsers won't upgrade HTTP requests to HTTPS automatically — enabling SSL stripping attacks.

### Rate limiting — should be configured

```nginx
# Missing rate limiting — vulnerable to brute-force and DoS
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # correct: define zone
limit_req zone=api burst=20 nodelay;  # correct: apply in server/location block
```

Without rate limiting, login endpoints, APIs, and authentication flows are open to brute-force and resource exhaustion.

### Buffer overflow protection — should be set

```nginx
# Missing — leaves default (large) buffer sizes that can be exploited
client_body_buffer_size 1k;      # correct
client_header_buffer_size 1k;    # correct
client_max_body_size 1k;         # correct for APIs (adjust for file uploads)
large_client_header_buffers 2 1k; # correct
```

Oversized default buffers can be exploited to cause buffer overflows in some nginx versions.

## Evaluation approach

Read the full config file. Look for the `http {}` block and all nested `server {}` blocks. A directive in the `http {}` block applies globally unless overridden in a `server {}` or `location {}` block.

Flag missing directives that have no equivalent elsewhere in the config.

## True positive criteria

Flag at high:
1. `server_tokens on` or absent `server_tokens off`
2. No `add_header Strict-Transport-Security` in HTTPS server blocks
3. No `limit_req_zone` / `limit_req` configured for any endpoint

Flag at medium:
4. No `add_header X-XSS-Protection` in http block
5. No buffer size limits (`client_body_buffer_size`, `client_header_buffer_size`)

## What to ignore

- HSTS missing for HTTP-only (port 80) server blocks — HSTS only applies to HTTPS
- Rate limiting absent on static file servers with no dynamic endpoints

Report: each missing or misconfigured directive, the block context (http/server/location), and whether a parent block might be supplying the directive (don't flag if an include directive pulls in a separate hardening config).
