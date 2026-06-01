---
slug: ssrf
name: Server-Side Request Forgery (SSRF)
description: 'Server-side HTTP requests (fetch, axios, http.request, ky, undici) where the URL is user-controlled — allows attackers to probe internal networks, cloud metadata endpoints, or localhost services. Reads related files together to check whether URL allowlists or validation helpers cover each fetch call.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: fetch\s*\(\s*(req\.|request\.|params\.|query\.|body\.|parsed\.|searchParams)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fetch with request-derived URL
      - regex: axios\.(get|post|put|delete|patch|request)\s*\(\s*(req\.|request\.|params\.|query\.|body\.)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: axios with request-derived URL
      - regex: 'https?\.request\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: http.request with interpolated URL
      - regex: new\s+URL\s*\(\s*(req\.|request\.|params\.|query\.|body\.)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: new URL from request data
      - regex: 'fetch\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fetch with interpolated URL
      - regex: (ky|got|undici|node-fetch|phin)\.(get|post|put|delete|patch|request)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: alt HTTP client call
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
    - regex: fetch\s*\(\s*(req\.|request\.|params\.|query\.|body\.|parsed\.|searchParams)
      label: fetch with request-derived URL
    - regex: axios\.(get|post|put|delete|patch|request)\s*\(\s*(req\.|request\.|params\.|query\.|body\.)
      label: axios with request-derived URL
    - regex: 'https?\.request\s*\(\s*`[^`]*\$\{'
      label: http.request with interpolated URL
    - regex: new\s+URL\s*\(\s*(req\.|request\.|params\.|query\.|body\.)
      label: new URL from request data
    - regex: 'fetch\s*\(\s*`[^`]*\$\{'
      label: fetch with interpolated URL
    - regex: (ky|got|undici|node-fetch|phin)\.(get|post|put|delete|patch|request)\s*\(
      label: alt HTTP client call
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-918
  - 'OWASP-A10:2021'
---

You are reviewing a batch of Node.js / TypeScript files for
Server-Side Request Forgery (SSRF) — server-side HTTP calls whose
URLs are influenced by user input, letting an attacker make the
server issue requests to arbitrary internal hosts, cloud metadata
endpoints, or localhost services.

**Cross-file analysis:** the URL allowlist / validator helper is
almost always in a shared module (e.g., `lib/url.ts`,
`utils/safeFetch.ts`, `config/allowed-hosts.ts`). You have file-system
tools available — use them. When you find a `fetch(...)` candidate
in one file, read the imported helpers it routes through before
deciding whether to flag.

## What to look for

**Direct fetch / HTTP client calls with caller-controlled URLs:**
```ts
// JS/TS HTTP clients
const res = await fetch(req.body.url);
await axios.get(req.query.target);
await axios.post(req.body.endpoint, payload);
const r = await ky.get(params.url);
http.request(`https://api/${req.body.host}`);
https.get(new URL(req.query.target));
```

**Template-literal URLs with interpolated user values:**
```ts
const res = await fetch(`${baseFromUser}/api/data`);
const r = await fetch(`https://${tenant}.api.example.com/v1/me`);
```

**`new URL(userInput)` followed by a fetch:**
```ts
const u = new URL(req.body.callback);
await fetch(u);
```

**HTTP clients that follow redirects by default:**
The Fetch API defaults to `redirect: "follow"`. If the validation
checks only the initial URL, a 30x to `169.254.169.254` (AWS
metadata) or `localhost` bypasses the check. Flag fetches of
caller-influenced URLs that don't set `redirect: "manual"` or
re-validate after redirects.

**SDK wrappers:**
```ts
// Webhook delivery, image fetcher, link unfurler, OG-tag scraper —
// any pattern where the URL comes from a record the user wrote.
await unfurl(post.linkUrl);
await fetchImage(profile.avatarUrl);
```

## How to investigate (use the tools)

For each candidate found in this batch:

1. **Trace the URL value.** Is it a request param, a database field
   the user wrote earlier, or a transitively user-controlled value?
   If it's purely internal (a hardcoded URL, a server-derived ID,
   an env-var endpoint), it's not SSRF.

2. **Read the imports.** If the file imports a wrapper like
   `import { safeFetch } from "@/lib/safe-fetch"` or
   `import { allowedHost } from "@/lib/url"`, read that file to
   verify the wrapper performs:
   - Hostname allowlist (`ALLOWED.has(u.hostname)`)
   - DNS resolution + private-IP block (`172.16/12`, `10/8`,
     `192.168/16`, `127/8`, `169.254/16`, `fc00::/7`, `fe80::/10`)
   - `redirect: "manual"` and per-hop re-validation

3. **Check for caller-controlled host in template literals.** A
   URL like `` `https://${host}/api` `` is fine if `host` is from
   a fixed allowlist; SSRF if `host` is from `req.body`.

4. **Match against env-var base URLs.** A URL like
   `` `${process.env.UPSTREAM_URL}/v1/${id}` `` is generally safe;
   the upstream is operator-controlled and `id` becomes a path
   segment, not a destination host. Only flag if the env value
   itself comes from user input (rare).

## True positive criteria

Flag when ALL of the following hold:

1. An HTTP client call (`fetch`, `axios.*`, `http.request`,
   `https.request`, `ky.*`, `undici.fetch`, `node-fetch`, `got`,
   `phin`) is made.
2. The URL argument includes a value transitively derived from
   request input, a database field written by users, or a
   third-party API response.
3. No host allowlist / private-IP block check appears on the path
   from the input to the fetch — either inline or via an imported
   helper you've inspected.

## What to ignore

- Fetches to a constant URL or to an env-var base URL with the
  user-controlled segment used only as a path / query string.
- Client-side `fetch` calls (e.g., inside `"use client"` files,
  browser code). SSRF is server-side only.
- Test fixtures, mock servers, MSW handlers.
- Calls that route through a vetted helper (e.g., `safeFetch`)
  whose body you've confirmed validates host + blocks private
  ranges + handles redirects.

## Examples

True positives:
```ts
// User-supplied URL fetched directly
export async function POST(req: Request) {
  const { url } = await req.json();
  const data = await fetch(url).then(r => r.json());
  return Response.json(data);
}

// Avatar URL from a profile record, no validation
const avatar = await fetch(user.avatarUrl);

// Template literal with caller-controlled host
const target = `${req.body.tenant}.api.example.com`;
await fetch(`https://${target}/internal`);
```

False positives to skip:
```ts
// Goes through safeFetch — helper validates host allowlist + blocks private IPs
import { safeFetch } from "@/lib/safe-fetch";
const data = await safeFetch(req.body.url);

// Env-var base, validated path segment
const ID = /^[a-z0-9-]+$/;
if (!ID.test(id)) throw new Error("invalid");
await fetch(`${process.env.UPSTREAM_URL}/v1/${id}`);

// Constant URL
await fetch("https://api.stripe.com/v1/charges", { ... });
```

Read the helpers before you flag. If `safeFetch` exists in the repo
and the call routes through it, that's the answer — but only if
its body actually does the validation. Don't trust the name alone.
