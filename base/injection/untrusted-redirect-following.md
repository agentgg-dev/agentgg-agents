---
slug: untrusted-redirect-following
name: Untrusted Redirect Following (SSRF via 3xx)
description: Server-side fetch follows HTTP redirects from a caller-controlled URL — the initial URL passes allowlist checks but a 302 redirect to an internal address bypasses them. Walker mode follows fetch helpers to verify redirect handling.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: fetch\s*\(\s*(targetUrl|callbackUrl|webhookUrl|redirectUrl|destinationUrl|proxyUrl|imageUrl|userUrl|companyUrl)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fetch with caller-influenced URL variable
      - regex: 'fetch\s*\([^)]*\)\s*\.then|await\s+fetch\s*\([^)]*\)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fetch call (verify redirect handling on caller-controlled URLs)
      - regex: axios\.(get|post|put|patch|delete|request)\s*\(\s*(targetUrl|callbackUrl|webhookUrl|userUrl|companyUrl|imageUrl|proxyUrl)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: axios call with caller-influenced URL variable
      - regex: got\s*\(\s*(targetUrl|callbackUrl|webhookUrl|domainUrl)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: got call with caller-influenced URL variable
where:
  extensions:
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
  preFilter:
    - regex: fetch\s*\(\s*(targetUrl|callbackUrl|webhookUrl|redirectUrl|destinationUrl|proxyUrl|imageUrl|userUrl|companyUrl)\b
      label: fetch with caller-influenced URL variable
    - regex: 'fetch\s*\([^)]*\)\s*\.then|await\s+fetch\s*\([^)]*\)'
      label: fetch call (verify redirect handling on caller-controlled URLs)
    - regex: axios\.(get|post|put|patch|delete|request)\s*\(\s*(targetUrl|callbackUrl|webhookUrl|userUrl|companyUrl|imageUrl|proxyUrl)
      label: axios call with caller-influenced URL variable
    - regex: got\s*\(\s*(targetUrl|callbackUrl|webhookUrl|domainUrl)
      label: got call with caller-influenced URL variable
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-918
  - 'OWASP-A10:2021'
---

You are reviewing server-side code for an SSRF bypass via redirect
following: the server fetches a caller-supplied URL, validates the
initial hostname (e.g., allows only `https://partner.com`), but the
target server responds with a `302 Location: http://169.254.169.254/`
and the fetch client follows it — bypassing the per-hop allowlist
check because only the first URL was validated.

**Walker mode advantage:** the fetch is often wrapped in a project
helper (`fetchExternal`, `safeFetch`) and the redirect option is set
once there. Open the helper to verify it actually sets
`redirect: "manual"` (fetch), `maxRedirects: 0` (axios), or
`followRedirect: false` (got/node-fetch) — and that the per-hop
allowlist check is reapplied after each redirect.

Default behavior: `fetch()`, `axios`, `got`, and `node-fetch` all
follow redirects automatically (`redirect: "follow"` by default).

## What to look for

**`redirect: "follow"` on a fetch with a caller-influenced URL:**
```ts
await fetch(targetUrl, { redirect: "follow" });  // explicit follow
await fetch(webhookUrl);  // default is follow — same risk
```

**Absence of `redirect: "manual"` or `redirect: "error"` when the URL
is caller-controlled:**
```ts
// No redirect option — follows by default
const res = await fetch(callbackUrl);
```

**Caller-influenced URL variable names:**
`url`, `targetUrl`, `callbackUrl`, `redirectUrl`, `webhookUrl`,
`destination`, `returnTo`, `imageUrl`, `fetchUrl`, `proxyUrl`.

**Axios — follows redirects by default:**
```ts
await axios.get(companyUrl);    // redirects followed up to maxRedirects
await axios.post(websiteUrl, body);
```

**`got` — follows redirects by default:**
```ts
await got(domainUrl);
```

## True positive criteria

Flag when ALL of the following hold:

1. A server-side HTTP client (`fetch`, `axios`, `got`, `undici`,
   `node-fetch`) makes a request.
2. The URL originates from caller input (request body, query param,
   header, or a variable named with a "URL from user" hint).
3. The call does NOT set `redirect: "manual"` or `redirect: "error"`
   (for fetch) / `maxRedirects: 0` (for axios) / `followRedirect: false`
   (for got/node-fetch).
4. No per-redirect URL re-validation is performed.

## What to ignore

- `redirect: "manual"` — the response is returned without following;
  the caller must explicitly read and re-validate the `Location`
  header before issuing a second request.
- `redirect: "error"` — throws on any redirect; safe.
- `axios` with `maxRedirects: 0`.
- `got` with `followRedirect: false`.
- Fetch calls where the URL is fully hardcoded or built from a
  server-side constant (env var / config), not from caller input.
- Test files.

## Examples

True positives:
```ts
// Default redirect following — attacker can chain to internal host
const res = await fetch(targetUrl);

// Explicit follow — same risk
await fetch(callbackUrl, { redirect: "follow" });

// Axios — attacker-supplied URL redirects to metadata service
await axios.get(webhookUrl);
```

False positives to skip:
```ts
// redirect: "manual" — not following
const res = await fetch(userUrl, { redirect: "manual" });
if (res.status >= 300) throw new Error("redirect not allowed");

// Hardcoded URL
await fetch("https://api.internal/health");

// axios with redirects disabled
await axios.get(proxyUrl, { maxRedirects: 0 });
```
