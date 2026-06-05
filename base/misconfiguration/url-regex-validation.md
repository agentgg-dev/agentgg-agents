---
slug: url-regex-validation
name: URL Validation via Bypassable Regex
description: URL safety check built with a regex that contains greedy wildcards or unanchored patterns — bypassable by adding the trusted domain as a subdomain of an attacker domain.
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
  preFilter:
    - regex: 'RegExp|regexp|preg_|Pattern\.compile|\bre\.|=~|\.match\s*\(|\.test\s*\(|[Uu]rl|[Hh]ost|[Dd]omain|[Rr]edirect'
      label: Regex usage
references:
  - CWE-1287
  - CWE-918
  - 'OWASP-A01:2021'
---

You are reviewing source code for URL validation that uses a regular
expression instead of proper URL parsing. The common failure is a
regex that "matches the trusted domain" but doesn't anchor strictly,
so `https://trusted.com.evil.com/...` passes the check.

## What to look for

**Regex literal matching a URL pattern with `.+` / `.*`:**
```ts
const re = /^https?:\/\/.+\.trusted\.com/;
if (re.test(url)) ok();

const ok = /https?:.+\.example\.com/.test(url);

const re = /https?:.*\.foo\.com/;
if (re.test(url)) good();
```

The `.+` / `.*` matches any characters, including `evil.com/?host=`.
Result: `https://evil.com/?host=.trusted.com` passes because the
regex doesn't anchor the hostname.

**`new URL(req.*)` followed by a `.host` comparison that misses
subdomain confusion:**
```ts
const u = new URL(req.query.target);
if (u.host.endsWith("trusted.com")) ok();
// Bypass: u.host = "trusted.com.evil.com" passes endsWith("trusted.com")
```

**`includes` / `startsWith` shortcuts on URL strings:**
```ts
if (url.includes("trusted.com")) ok();   // matches anything with trusted.com
```

## Safe pattern

Use `new URL()` parsing and compare the parsed origin or hostname
exactly:
```ts
try {
  const u = new URL(input);
  const ALLOWED = ["app.example.com", "cdn.example.com"];
  if (!ALLOWED.includes(u.hostname)) throw new Error("disallowed");
  // u.hostname is the exact host — no subdomain confusion
} catch {
  throw new Error("invalid URL");
}
```

## True positive criteria

Flag when ANY of the following hold:

1. A regex with `.+` / `.*` is used to validate a URL by domain.
2. `endsWith(".trusted.com")` (note: a leading dot helps but is
   still brittle; flag `endsWith("trusted.com")` without the dot).
3. `includes(domain)` used as a URL safety gate.
4. `new URL(input)` followed by no comparison at all — the URL is
   used downstream as-is.

## What to ignore

- Exact-match `u.origin === "https://trusted.example.com"` or
  `u.hostname === "trusted.example.com"` (note: hostname doesn't
  include port).
- Allowlist via `Set.has(u.origin)` or `ALLOWED.includes(u.hostname)`.
- Validation against a single hardcoded URL string with `===`.

## Examples

True positives:
```ts
// Regex with .+
const re = /^https?:\/\/.+\.trusted\.com/;
if (re.test(req.query.url)) await fetch(req.query.url);

// endsWith bypass
const u = new URL(req.query.target);
if (u.host.endsWith("example.com")) { await fetch(u); }
// Bypass: example.com.evil.com

// includes
if (callbackUrl.includes("trusted.com")) res.redirect(callbackUrl);
```

False positives to skip:
```ts
// Exact origin check
const u = new URL(input);
if (u.origin === "https://app.example.com") ok();

// Allowlist by exact hostname
const ALLOWED = new Set(["app.example.com", "admin.example.com"]);
if (!ALLOWED.has(u.hostname)) throw new Error("disallowed");
```
