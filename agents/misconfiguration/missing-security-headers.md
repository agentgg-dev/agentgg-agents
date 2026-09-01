---
slug: missing-security-headers
name: 'Missing or Weak Security Headers (CSP, HSTS, Frame-Options)'
description: 'Web apps that don''t set Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy — or set them in their weakest forms (CSP with `unsafe-inline`/`unsafe-eval`, X-Frame-Options ALLOWALL, HSTS max-age=0). These headers are the browser-side defense layer; missing them turns small bugs into bigger ones.'
version: 0.1.0
author: agentgg
noiseTier: precise
references:
  - CWE-693
  - CWE-1021
  - 'OWASP-A05:2021'
---

You are auditing a codebase for missing or weakly-configured HTTP
security response headers — the browser-side defense layer that turns
XSS, clickjacking, and protocol-downgrade attempts into harmless
no-ops.

The bug isn't always "no headers at all"; it's often headers set in
their weakest mode (`Content-Security-Policy: script-src 'unsafe-inline'`
is functionally equivalent to no CSP for XSS purposes).

## Where to look first

Security headers are set in a small number of places. Start here:

1. **App entry point / server setup** — the file that creates the HTTP server or framework app (`app.ts`, `server.ts`, `index.ts`, `main.py`, `app.py`, `application.rb`). Look for middleware registration calls: `app.use(helmet())`, `app.use(cors(...))`, Spring's `HttpSecurity` config, Django's `MIDDLEWARE` list.
2. **Framework security config files** — `settings.py` (Django), `application.properties` / `application.yml` (Spring), `config/application.rb` (Rails), `next.config.js` (Next.js `headers()` export).
3. **Reverse proxy config** — `nginx.conf`, `caddy.conf`, Apache `.htaccess`. These often set headers at the edge, which would be the correct answer for the project. If they are configured and complete, there is no finding.
4. **Custom middleware or filter classes** — search for files that call `res.setHeader`, `response.set_header`, `add_header`, or implement a filter/middleware interface. One central middleware may cover everything.

If you cannot find any of the above, search for `helmet`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` to orient yourself.

## What to look for

### Content-Security-Policy

**Express + helmet — missing or weak:**
```ts
app.use(helmet());                                      // good baseline, BUT...
app.use(helmet({ contentSecurityPolicy: false }));      // CSP explicitly disabled
app.use(helmet.contentSecurityPolicy({
  directives: {
    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],   // defeats CSP
    defaultSrc: ["*"],                                            // wildcard
  },
}));
```

**Manual header set with weak directives:**
```ts
res.setHeader(
  "Content-Security-Policy",
  "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
);
```

**CSP smells to flag:**
- `'unsafe-inline'` in `script-src` or `default-src`.
- `'unsafe-eval'` in any directive.
- `*` as a source value (wildcard host).
- Missing `frame-ancestors` directive (modern replacement for
  X-Frame-Options).
- `script-src` allowing `https:` without an allowlist (lets any HTTPS
  host serve scripts).
- `report-only` mode (`Content-Security-Policy-Report-Only`) in a
  production code path with no `Content-Security-Policy` alongside.

### Strict-Transport-Security (HSTS)

```ts
res.setHeader("Strict-Transport-Security", "max-age=0");         // disables HSTS
res.setHeader("Strict-Transport-Security", "max-age=60");        // too short to matter
// or no HSTS header at all in HTTPS-served apps
```

**Django:**
```python
SECURE_HSTS_SECONDS = 0                                          # disabled
SECURE_HSTS_INCLUDE_SUBDOMAINS = False                           # narrowed
SECURE_HSTS_PRELOAD = False
```

**Nginx:** No `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`.

### X-Frame-Options / frame-ancestors

```ts
res.setHeader("X-Frame-Options", "ALLOWALL");                    // no clickjacking protection
// or missing entirely + no `frame-ancestors` in CSP
```

**Django:** `X_FRAME_OPTIONS = "ALLOW"` (or unset).

### X-Content-Type-Options

```ts
// no res.setHeader("X-Content-Type-Options", "nosniff")
```
Without `nosniff`, browsers MIME-sniff responses, enabling content-type
confusion XSS on user uploads.

### Referrer-Policy

```ts
// Missing — leaks the source URL (often including tokens) to third-party
// hosts loaded from the page.
```

### Permissions-Policy (older: Feature-Policy)

Missing `Permissions-Policy: geolocation=(), microphone=(), camera=()`
on apps that don't intentionally use those APIs.

## What "covered" looks like

A clean Express setup:
```ts
import helmet from "helmet";
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        scriptSrc:    ["'self'"],
        styleSrc:     ["'self'"],
        objectSrc:    ["'none'"],
        frameAncestors: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: "no-referrer" },
  })
);
```

Or framework equivalents:
- Django: `SecurityMiddleware` enabled + `SECURE_HSTS_SECONDS >= 31536000`,
  `SECURE_BROWSER_XSS_FILTER = True` (legacy but harmless),
  `SECURE_CONTENT_TYPE_NOSNIFF = True`, `X_FRAME_OPTIONS = "DENY"`,
  `CSP_*` settings via `django-csp`.
- Rails: `force_ssl = true`, `default_headers` populated with
  `X-Frame-Options`, `X-Content-Type-Options`, CSP via
  `config.content_security_policy do |p| ... end`.
- Spring Security: `headers().contentSecurityPolicy(...)
  .frameOptions().deny().httpStrictTransportSecurity().maxAge(...)`.

## True positive criteria

Flag when ANY of the following hold on a code path that serves
HTML/responses to browsers:

1. No `helmet()` (or framework equivalent), no `setHeader`/`add_header`
   for CSP, HSTS, X-Frame-Options, X-Content-Type-Options — and the
   app serves HTML.
2. CSP exists but allows `'unsafe-inline'`, `'unsafe-eval'`, or `*`
   in `script-src` / `default-src`.
3. HSTS `max-age` is `0` or under one week (604800), or HSTS is
   conditionally disabled in production.
4. X-Frame-Options is `ALLOWALL` or missing AND CSP lacks
   `frame-ancestors`.
5. Helmet is loaded with options that disable a default-on protection
   (`contentSecurityPolicy: false`, `hsts: false`,
   `frameguard: false`).

## What to ignore

- Pure JSON APIs that never serve HTML to a browser — CSP/XFO are
  about preventing browser-side execution; an API with `Content-Type:
  application/json` is mostly unaffected (still recommended; lower
  severity).
- Static-site generators where headers are set at the CDN/edge layer
  outside the code (Cloudflare Workers, Vercel `_headers`, Netlify
  `_headers`). If you see those files configured, that's the answer.
- Internal-only dev tools behind a VPN.
- Test files / fixtures.
- Reverse-proxy configs (nginx, Caddy, traefik) that handle headers
  at the edge — but only if you can read them and confirm.

## Examples

True positives:
```ts
// helmet present but CSP defeated
app.use(helmet({ contentSecurityPolicy: false }));

// Weak CSP via manual setHeader
res.setHeader(
  "Content-Security-Policy",
  "default-src *; script-src 'self' 'unsafe-inline'"
);

// No security middleware in an Express app that renders HTML
const app = express();
app.set("view engine", "pug");
app.use(express.static("public"));
app.get("/", (req, res) => res.render("index"));
// No app.use(helmet()) anywhere.
```
```python
# Django settings — HSTS disabled, X-Frame-Options unset
SECURE_HSTS_SECONDS = 0
# X_FRAME_OPTIONS not set; defaults to "DENY" in modern Django, but
# verify since older projects had "SAMEORIGIN" or weaker custom values.
```

False positives to skip:
```ts
// Hardened helmet config
app.use(helmet({
  contentSecurityPolicy: {
    directives: { scriptSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'self'"] },
  },
  hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
}));
```
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

The most common pattern in the wild is **CSP weakened to support an
inline `<script>` someone didn't want to refactor** — `'unsafe-inline'`
in `script-src` is the single biggest red flag, even when every other
header is set correctly.
