---
slug: host-header-injection
name: Host Header Injection
description: 'Absolute URLs, email links, redirects, or cache keys built from the request Host / X-Forwarded-Host header without an allowlist — enabling password-reset poisoning, cache poisoning, and redirect abuse. Traces the host value from the request into the URL-building sink across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'req\.(headers\s*\[\s*[''"]x-forwarded-host[''"]\s*\]|headers\.host|hostname)|request\.headers\.host'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Node reading req host / X-Forwarded-Host
      - regex: 'request\.(get_host\s*\(|META\s*\[\s*[''"]HTTP_HOST[''"]|host\b)|HTTP_X_FORWARDED_HOST'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
        label: Python/Django/Flask reading the request host
      - regex: '\$_SERVER\s*\[\s*[''"](HTTP_HOST|SERVER_NAME|HTTP_X_FORWARDED_HOST)[''"]\s*\]'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
        label: PHP reading HTTP_HOST / SERVER_NAME
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - php
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'req\.(headers\s*\[\s*[''"]x-forwarded-host[''"]\s*\]|headers\.host|hostname)|request\.headers\.host'
      label: Node reading req host / X-Forwarded-Host
    - regex: 'request\.(get_host\s*\(|META\s*\[\s*[''"]HTTP_HOST[''"]|host\b)|HTTP_X_FORWARDED_HOST'
      label: Python/Django/Flask reading the request host
    - regex: '\$_SERVER\s*\[\s*[''"](HTTP_HOST|SERVER_NAME|HTTP_X_FORWARDED_HOST)[''"]\s*\]'
      label: PHP reading HTTP_HOST / SERVER_NAME
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-644
  - CWE-20
---

You are reviewing source for Host header injection — code that trusts
the client-supplied `Host` (or `X-Forwarded-Host`) header when building
an absolute URL, email link, redirect target, or cache key. Because the
Host header is fully attacker-controlled (it travels in the request),
an attacker can make the server emit links pointing at a host they own.
The signature impact is password-reset poisoning: the reset email links
to `https://attacker.com/reset?token=...`, and when the victim clicks,
the token leaks to the attacker.

**Cross-file analysis:** the host is usually read in one place (a
request helper, a `getBaseUrl()` util, middleware) and consumed
elsewhere (the mailer template, a redirect, a cache layer). Trace the
value: when you see `req.headers.host` captured into `baseUrl`, find
where `baseUrl` is used. The vulnerability only matters when the host
flows into a sink that the attacker benefits from poisoning.

## What to look for

- Node/Express/Next: `req.headers.host`, `req.hostname`,
  `req.headers['x-forwarded-host']` interpolated into a link:
  ```js
  const base = `https://${req.headers.host}`;
  sendMail(user.email, `${base}/reset?token=${token}`);
  ```
- Django/Flask: `request.get_host()`, `request.META['HTTP_HOST']`,
  `request.host`, `request.host_url` used to build a reset/confirm URL:
  ```python
  link = f"https://{request.get_host()}/reset/{token}"
  ```
- PHP: `$_SERVER['HTTP_HOST']` / `$_SERVER['SERVER_NAME']` in a link
  or `Location:` header:
  ```php
  $url = "https://" . $_SERVER['HTTP_HOST'] . "/reset.php?t=$token";
  ```
- Cache keys / canonical URLs / sitemap / Set-Cookie domain built from
  the host (web cache poisoning when an absolute resource URL derived
  from the host gets cached and served to other users).

## True positive criteria

A finding is real when the request Host / X-Forwarded-Host header
reaches a URL-building sink (email link, redirect, absolute link in a
response that may be cached, OAuth/callback URL) AND there is no
validation against a configured allowlist of trusted hostnames before
use.

You must be able to say: "I am an external attacker. I send the
password-reset request with `Host: evil.com` (or `X-Forwarded-Host:
evil.com`). The server emails the victim a link to `https://evil.com/
reset?token=...`; when they click it, I capture their reset token."
Name the attacker and the trust boundary (the request header). The
burden is on the code to show the host is checked against an allowlist
(Django `ALLOWED_HOSTS`, an explicit `if (host in TRUSTED)` set, or a
fixed configured base URL) before it lands in the sink.

## What to ignore

- Absolute URLs built from a configured/constant base instead of the
  request host (`process.env.APP_URL`, a settings value, a hardcoded
  domain). That is the correct fix.
- Django apps where `get_host()` is used and `ALLOWED_HOSTS` is set to
  a real list (not `['*']`) — Django validates the host against it.
- The host used only for logging, metrics, or a non-security display
  string that is never turned into a clickable/redirect/cache target.
- Reverse-proxy setups where `X-Forwarded-Host` is stripped/overwritten
  by a trusted proxy and the app reads only that sanitized value — but
  confirm the proxy actually controls it; don't assume.
- Host compared against an allowlist on the same path before use.

## Examples

True positives:
```js
const base = `https://${req.headers.host}`;
await mailer.send(user.email, resetTemplate(`${base}/reset?token=${t}`));
```
```python
reset_url = f"{request.scheme}://{request.get_host()}/reset/{token}"
send_mail("Reset", reset_url, FROM, [user.email])
```
```php
$link = "https://{$_SERVER['HTTP_HOST']}/verify.php?token=$token";
mail($email, "Verify", $link);
```

False positives to skip:
```js
const base = process.env.PUBLIC_BASE_URL;
await mailer.send(user.email, `${base}/reset?token=${t}`);
```
```python
if request.get_host() not in settings.ALLOWED_HOSTS:
    raise SuspiciousOperation()
```
```php
$host = "app.example.com";
$link = "https://$host/verify.php?token=$token";
```

If the request host flows into a reset/confirm link or redirect with no
allowlist check on the path, treat it as a finding even if exploitation
needs the victim to click — the burden is on the code to prove the host
is trusted.
