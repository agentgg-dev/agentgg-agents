---
slug: open-redirect
name: Open Redirect
description: 'Redirect responses (res.redirect, Next.js redirect(), router.push, Location header) where the destination URL comes from user input with no validation, or with a validator that can be bypassed (substring match, unanchored regex, startsWith("/") that allows "//") — allows phishing via trusted domain. Follows redirect-allowlist helpers.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: res\.redirect\s*\(\s*(req|request)\.(query|body|params|headers)\.
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: res.redirect() with request-derived destination
      - regex: \bredirect\s*\(\s*(searchParams|req|request|params)\.
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Next.js redirect() / generic redirect with request data
      - regex: router\.(push|replace)\s*\(\s*(searchParams|params|location)\.
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: router.push/replace with request-derived destination
      - regex: NextResponse\.redirect\s*\(\s*new\s+URL\s*\(\s*(req|request)\.
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: NextResponse.redirect with request-derived URL
      - regex: 'Location\s*:\s*(req|request|body|searchParams)\.'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Raw Location header set from request data
      - regex: window\.location(\.href)?\s*=\s*(searchParams|new\s+URLSearchParams|location\.search)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: window.location set from URL search params
      - regex: '\b(res\.redirect|NextResponse\.redirect|router\.(push|replace))\s*\(\s*[A-Za-z_$`]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: redirect call with a variable/template destination (trace origin)
      - regex: returnUrl|redirectUrl|returnTo|redirect_uri
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: redirect destination parameter name present
      - regex: '\.startsWith\s*\(\s*["'']/["'']\s*\)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: startsWith('/') check — verify it also rejects '//'
      - regex: 'new\s+URL\s*\([^,)]+,\s*["'']https?://'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'new URL(input, base) — verify base is enforced'
      - regex: '\.includes\s*\(\s*["''][^"'']*\.[a-z]{2,}["'']'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: .includes() domain match — substring bypassable
      - regex: redirect\s*\(\s*request\.(args|GET|POST|form|values|query_params)
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: redirect() with request-derived destination
      - regex: HttpResponseRedirect\s*\(\s*request\.
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Django HttpResponseRedirect from request data
      - regex: RedirectResponse\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: FastAPI RedirectResponse
      - regex: \b(next_url|return_url|redirect_url|return_to|redirect_uri)\b
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: redirect destination parameter name
      - regex: \.startswith\s*\(\s*[\"']/[\"']\s*\)
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: startswith('/') check - verify it also rejects '//'
      - regex: urljoin\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: urljoin - verify the base is enforced
      - regex: urlparse\s*\([^)]*\)\.(netloc|hostname)\s*(==|in)\s*
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: host allowlist check on parsed URL
      - regex: \.sendRedirect\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: HttpServletResponse.sendRedirect
      - regex: "new\\s+RedirectView\\s*\\(|[\\\"']redirect:"
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring redirect view
      - regex: HttpHeaders\.LOCATION|setHeader\s*\(\s*[\"']Location[\"']
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Location header set
      - regex: \b(returnUrl|redirectUrl|returnTo|redirectUri|nextUrl)\b
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: redirect destination parameter
      - regex: \.startsWith\s*\(\s*[\"']/[\"']\s*\)
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: startsWith("/") check - verify it also rejects '//'
where:
  extensions:
    - java
    - kt
    - py
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/.venv/**'
    - '**/venv/**'
    - '**/site-packages/**'
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: res\.redirect\s*\(\s*(req|request)\.(query|body|params|headers)\.
      label: res.redirect() with request-derived destination
    - regex: \bredirect\s*\(\s*(searchParams|req|request|params)\.
      label: Next.js redirect() / generic redirect with request data
    - regex: router\.(push|replace)\s*\(\s*(searchParams|params|location)\.
      label: router.push/replace with request-derived destination
    - regex: NextResponse\.redirect\s*\(\s*new\s+URL\s*\(\s*(req|request)\.
      label: NextResponse.redirect with request-derived URL
    - regex: 'Location\s*:\s*(req|request|body|searchParams)\.'
      label: Raw Location header set from request data
    - regex: window\.location(\.href)?\s*=\s*(searchParams|new\s+URLSearchParams|location\.search)
      label: window.location set from URL search params
    - regex: '\b(res\.redirect|NextResponse\.redirect|router\.(push|replace))\s*\(\s*[A-Za-z_$`]'
      label: redirect call with a variable/template destination (trace origin)
    - regex: returnUrl|redirectUrl|returnTo|redirect_uri
      label: redirect destination parameter name present
    - regex: redirect\s*\(\s*request\.
      label: redirect() with request data
    - regex: HttpResponseRedirect\s*\(
      label: Django HttpResponseRedirect
    - regex: RedirectResponse\s*\(
      label: FastAPI RedirectResponse
    - regex: \b(next_url|return_url|redirect_url|return_to|redirect_uri)\b
      label: redirect destination parameter
    - regex: 'redirect_uri|redirect_url|returnUrl|return_url|returnTo|redirectUrl|[Rr]edirectTo|[Nn]extUrl|[Cc]allbackUrl'
      label: redirect destination identifier — validation logic likely nearby
    - regex: '\.redirect\s*\(|sendRedirect\s*\(|res\.redirect|response\.redirect|window\.location\s*[.=]|location\.href\s*=|[`"'']Location[`"'']'
      label: redirect sink — verify the destination is validated
    - regex: 'new\s+URL\s*\([^,)]+,\s*["'']https?://'
      label: 'new URL(input, base) — verify base is enforced'
    - regex: \.startswith\s*\(\s*[\"']/[\"']\s*\)
      label: startswith('/') - '//' bypassable
    - regex: urljoin\s*\(
      label: urljoin - verify base enforced
    - regex: urlparse\s*\([^)]*\)\.(netloc|hostname)
      label: parsed-URL host check
    - regex: \.sendRedirect\s*\(
      label: sendRedirect
    - regex: "new\\s+RedirectView\\s*\\(|[\\\"']redirect:"
      label: Spring redirect view
    - regex: HttpHeaders\.LOCATION|setHeader\s*\(\s*[\"']Location[\"']
      label: Location header
    - regex: \b(returnUrl|redirectUrl|returnTo|redirectUri|nextUrl)\b
      label: redirect parameter
    - regex: \.startsWith\s*\(\s*[\"']/[\"']\s*\)
      label: startsWith('/') - '//' bypassable
  maxFilesPerBatch: 5
references:
  - CWE-601
  - 'OWASP-A01:2021'

---

You are reviewing Node.js / TypeScript / React source code for open
redirect vulnerabilities — redirect responses where the destination
URL is taken from user-supplied input without validating that it
points to an allowed origin, enabling an attacker to redirect victims
from your trusted domain to a phishing or malware site.

Report two variants of the same bug: a destination with no validation
at all, and a destination whose validation exists but can be defeated
by attacker-chosen input. The impact is identical, so treat both as
findings.

**Cross-file analysis:** redirect destinations are often funneled
through a shared `safeRedirect()` or `validateReturnUrl()` helper.
Read those before flagging — verify they enforce a strict prefix
check (`/` start, no `//`, no `https?://`), an origin allowlist, or
both. The protocol-relative `//` bypass is a frequent failure mode
worth confirming the helper handles. If the helper runs but its check
is bypassable, the call site is still a finding and the helper is the
root cause.

## What to look for

**Express / Node.js:**
```ts
res.redirect(req.query.next)
res.redirect(req.body.returnUrl)
res.redirect(`${req.body.redirectUrl}/callback`)
```

**Next.js / React frameworks:**
```ts
redirect(searchParams.get("next"))        // server component / action
router.push(params.returnTo)              // client-side router
NextResponse.redirect(new URL(target, req.url))
```

**Raw `Location` header:**
```ts
return new Response(null, {
  status: 302,
  headers: { Location: req.body.next },
});
```

**`window.location` assignment (client-side):**
```ts
window.location.href = searchParams.get("returnUrl");
window.location = params.next;
```

**Common parameter names to watch:**
`next`, `returnUrl`, `returnTo`, `redirect`, `redirectUrl`,
`redirect_uri`, `destination`, `continue`, `target`, `url`, `goto`.
These frequently appear in login flows and OAuth callbacks.

## Bypassable validation

A validator that exists but can be defeated counts as no validation.
Report these the same way you report a raw unvalidated redirect, and
name the bypass in the finding.

**`startsWith("/")` alone, which allows `//evil.com`:**
```ts
if (!dest.startsWith("/")) return res.redirect("/");
res.redirect(dest);   // "//evil.com/phish" passes; browsers read it as protocol-relative
```
Safe guard: also reject any value whose second character is `/`.

**`new URL(dest, base)` with an absolute destination:**
```ts
const safeUrl = new URL(dest, "https://myapp.com");
redirect(safeUrl.toString());   // dest "https://evil.com" wins; the base is ignored
```
`new URL(absoluteUrl, base)` drops `base` entirely once the input is
already absolute. Safe guard: compare `new URL(dest).origin` against
the allowed origin.

**Unanchored prefix check (suffix attack):**
```ts
if (!dest.startsWith("https://myapp.com")) throw new Error();
res.redirect(dest);   // "https://myapp.com.evil.com/path" passes
```
Safe guard: append a trailing `/` to the allowed prefix, or compare
the parsed origin.

**Unanchored regex test on the domain:**
```ts
if (!/^https:\/\/myapp\.com/.test(redirectUri)) throw new Error();
// "https://myapp.com.evil.com/callback" passes
```
Common in OAuth `redirect_uri` validation. Safe guard: anchor the
whole origin, or match against the client's pre-registered URIs.

**`includes(domain)` substring match:**
```ts
if (!dest.includes("myapp.com")) throw new Error();
// "https://evil.com?ref=myapp.com" passes
```
`includes` matches anywhere in the string, including the query and
the fragment. The same flaw applies to a bare `indexOf(domain) !== -1`.

**Check applied before decoding:**
```ts
if (!isRelative(dest)) throw new Error();
// "%2F%2Fevil.com" passes, then decodes to "//evil.com" downstream
```
Also treat unicode lookalikes in the host and backslash variants
(`\/\/evil.com`, `/\evil.com`) as bypasses, because some parsers
normalise them to `//`.

**Python equivalents:** `dest.startswith("/")` alone, `urljoin(base,
dest)` where an absolute `dest` replaces the base, and
`urlparse(dest).netloc in ALLOWED` where `ALLOWED` is a substring
container rather than an exact host set.

## True positive criteria

Flag when ALL of the following hold:

1. A redirect is issued: `res.redirect`, `redirect()`, `router.push`,
   `router.replace`, `NextResponse.redirect`, a `Location` header,
   or `window.location` assignment.
2. The destination value comes from user input: request query string,
   request body, path parameter, HTTP header, or cookie.
3. The destination is not confined to a relative path or an allowed
   origin. This holds in two cases, and BOTH are findings:
   - **No validation at all.** The value reaches the redirect sink
     untouched.
   - **Validation is present but bypassable.** It matches one of the
     shapes under "Bypassable validation" above. Do not clear a
     finding just because a check exists; establish what input gets
     past it.

   Only these clear the finding:
   - Only relative paths accepted: `/profile`, `/dashboard` (no `://`),
     with `//` and `/\` also rejected
   - Strict allowlist of permitted full URLs or origins
   - Origin checked against a whitelist before redirect

   Say which of the two cases applies in the finding, and for a weak
   validator give the input that defeats it.

## What to ignore

- Redirects to a hardcoded URL string with no user-controlled
  component.
- Redirects where the user-supplied value is only a path segment
  (no protocol or host) AND the code verifies it begins with `/`
  and does not begin with `//` (double-slash can be treated as a
  protocol-relative URL by some parsers).
- OAuth `redirect_uri` parameters when the server validates the URI
  against the pre-registered list of allowed URIs for that client.
- `router.push` in client-side React components with a hardcoded or
  internally-derived path.
- `new URL(dest).origin === ALLOWED_ORIGIN`, a correct origin
  comparison.
- A strict allowlist of exact full URLs with no wildcards and no
  substring matching.
- Test files.

## Examples

True positives:
```ts
// Express — query param redirect
res.redirect(req.query.next);

// Next.js — login callback with returnUrl
const returnUrl = searchParams.get("returnUrl");
redirect(returnUrl);   // could be https://evil.com

// Location header from body
return new Response(null, { status: 302, headers: { Location: req.body.url } });

// Client-side — searchParam used for redirect
window.location.href = new URLSearchParams(location.search).get("goto");
```
```ts
// Weak validator: startsWith("/") lets //evil.com through
if (!next.startsWith("/")) return res.redirect("/");
res.redirect(next);

// Weak validator: new URL ignores the base for an absolute input
const url = new URL(returnTo, "https://myapp.com");
redirect(url.href);        // returnTo = "https://evil.com"

// Weak validator: unanchored prefix allows myapp.com.evil.com
if (!dest.startsWith("https://myapp.com")) throw new Error();
res.redirect(dest);

// Weak validator: substring match anywhere in the URL
if (!dest.includes("myapp.com")) throw new Error();
res.redirect(dest);        // "https://evil.com?ref=myapp.com"
```

False positives to skip:
```ts
// Hardcoded destination
res.redirect("/dashboard");

// Only path used, validated as relative
const next = req.query.next;
if (!next || next.startsWith("//") || /^https?:\/\//.test(next)) {
  return res.redirect("/");
}
res.redirect(next);

// Allowlist enforced
const ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"];
const dest = req.query.redirect;
if (!ALLOWED_ORIGINS.some(o => dest.startsWith(o))) return res.redirect("/");
res.redirect(dest);

// Correct origin check
const u = new URL(dest);
if (u.origin !== "https://myapp.com") throw new Error("disallowed");
res.redirect(dest);
```
