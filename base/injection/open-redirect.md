---
slug: open-redirect
name: Open Redirect
description: Redirect responses (res.redirect, Next.js redirect(), router.push, Location header) where the destination URL comes from user input without validation — allows phishing via trusted domain. Walker mode follows redirect-allowlist helpers.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "res\\.redirect\\s*\\(\\s*(req|request)\\.(query|body|params|headers)\\."
    label: "res.redirect() with request-derived destination"
  - regex: "\\bredirect\\s*\\(\\s*(searchParams|req|request|params)\\."
    label: "Next.js redirect() / generic redirect with request data"
  - regex: "router\\.(push|replace)\\s*\\(\\s*(searchParams|params|location)\\."
    label: "router.push/replace with request-derived destination"
  - regex: "NextResponse\\.redirect\\s*\\(\\s*new\\s+URL\\s*\\(\\s*(req|request)\\."
    label: "NextResponse.redirect with request-derived URL"
  - regex: "Location\\s*:\\s*(req|request|body|searchParams)\\."
    label: "Raw Location header set from request data"
  - regex: "window\\.location(\\.href)?\\s*=\\s*(searchParams|new\\s+URLSearchParams|location\\.search)"
    label: "window.location set from URL search params"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-601
  - OWASP-A01:2021
---

You are reviewing Node.js / TypeScript / React source code for open
redirect vulnerabilities — redirect responses where the destination
URL is taken from user-supplied input without validating that it
points to an allowed origin, enabling an attacker to redirect victims
from your trusted domain to a phishing or malware site.

**Walker mode advantage:** redirect destinations are often funneled
through a shared `safeRedirect()` or `validateReturnUrl()` helper.
Read those before flagging — verify they enforce a strict prefix
check (`/` start, no `//`, no `https?://`), an origin allowlist, or
both. The protocol-relative `//` bypass is a frequent failure mode
worth confirming the helper handles.

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

## True positive criteria

Flag when ALL of the following hold:

1. A redirect is issued: `res.redirect`, `redirect()`, `router.push`,
   `router.replace`, `NextResponse.redirect`, a `Location` header,
   or `window.location` assignment.
2. The destination value comes from user input: request query string,
   request body, path parameter, HTTP header, or cookie.
3. No validation ensures the destination is a relative path or belongs
   to an allowed origin. Safe patterns:
   - Only relative paths accepted: `/profile`, `/dashboard` (no `://`)
   - Strict allowlist of permitted full URLs or origins
   - Origin checked against a whitelist before redirect

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
```
