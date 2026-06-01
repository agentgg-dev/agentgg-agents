---
slug: csrf
name: Missing CSRF Protection
description: 'State-changing endpoints reachable via cookie-based auth without CSRF token verification, SameSite cookies, or origin/referer checks. Reads the app entry point and shared middleware to confirm whether csurf / equivalent is mounted globally before flagging.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: (app|router|api|fastify)\.(post|put|patch|delete)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: JS state-changing route registration
      - regex: '@(Post|Put|Patch|Delete)\s*\('
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Nest/Spring state-changing decorator
      - regex: '@csrf_exempt'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Django CSRF exempt
      - regex: 'skip_before_action\s*:?\s*:?verify_authenticity_token'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Rails CSRF skip
      - regex: 'sameSite\s*:\s*[''"](none|lax)[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Permissive SameSite cookie
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
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
    - '**/node_modules/**'
    - '**/dist/**'
  preFilter:
    - regex: (app|router|api|fastify)\.(post|put|patch|delete)\s*\(
      label: JS state-changing route registration
    - regex: '@(Post|Put|Patch|Delete)\s*\('
      label: Nest/Spring state-changing decorator
    - regex: '@csrf_exempt'
      label: Django CSRF exempt
    - regex: 'skip_before_action\s*:?\s*:?verify_authenticity_token'
      label: Rails CSRF skip
    - regex: 'sameSite\s*:\s*[''"](none|lax)[''"]'
      label: Permissive SameSite cookie
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-352
  - 'OWASP-A01:2021'
---

You are reviewing HTTP route handlers for missing Cross-Site Request
Forgery (CSRF) protection — state-changing endpoints that authenticate
the caller via cookies but do not require an additional unguessable
token, a strict SameSite cookie, or an origin/referer check.

**Cross-file analysis:** CSRF middleware is almost always wired up
once in `app.ts`/`server.ts`/`middleware.ts` and applies to the whole
router. Before flagging a handler in `routes/...`, Read the app
entrypoint and any router-factory file to check whether `csurf()`,
`csrf-csrf`, `doubleCsrf`, `lusca.csrf()`, Django CSRF middleware, or
Rails `protect_from_forgery` is in scope. Likewise check whether the
session cookie is set with `sameSite: "strict"`.

If the session cookie is sent automatically by the browser and the
endpoint accepts a content type the browser will send cross-origin
(form-encoded, plain text, simple JSON without a custom header), an
attacker page can trigger the request in the victim's session.

## What to look for

**State-changing routes** (`POST`, `PUT`, `PATCH`, `DELETE`) that:

1. Read session/identity from a **cookie** (not a `Bearer` header).
2. Mutate server state — write to DB, send money, change settings,
   post on behalf of the user.
3. Have none of: CSRF token middleware, custom-required header check,
   strict SameSite cookie, or origin/referer allowlist.

**Express / Koa / Fastify:**
```ts
app.post("/transfer", requireSession, (req, res) => {
  doTransfer(req.session.userId, req.body.amount, req.body.to);
});
```
No `csurf`/`csrf-csrf`/equivalent middleware in scope, no custom
header check, cookie likely `SameSite=Lax` or `None`.

**Django / Flask / Rails:**
- Django: `@csrf_exempt` on a state-changing view, or middleware
  removed from `MIDDLEWARE`.
- Flask: route that mutates state without Flask-WTF / Flask-SeaSurf.
- Rails: `protect_from_forgery` skipped via
  `skip_before_action :verify_authenticity_token`.

**SameSite indicator on cookie config:**
```ts
res.cookie("session", token, { sameSite: "none" });   // wide-open to CSRF
res.cookie("session", token);                          // no SameSite set
```

**Indicators of protection that, if PRESENT, mean the endpoint is
likely safe:**
- `csurf()` / `doubleCsrf()` / `csrf-csrf` middleware applied.
- A required custom header on the request (e.g.,
  `req.headers['x-requested-with']` checked) — a browser cross-origin
  form post can't add this.
- Auth via `Authorization: Bearer ...` only (no cookie) — browsers
  don't auto-attach this cross-origin.
- `sameSite: "strict"` on the session cookie, with no separate flow
  that opens it up.
- Origin / referer allowlist check.

## True positive criteria

Flag when ALL of the following hold:

1. Handler mutates server state (DB write, mail send, payment,
   permission change, file upload, etc.).
2. Caller identity is established via a cookie set by the same app.
3. No CSRF middleware, custom-header requirement, strict SameSite, or
   origin check appears in the request path.

## What to ignore

- Pure read endpoints (`GET`, `HEAD`) — CSRF on a read is rarely
  meaningful unless it has side effects.
- APIs authenticated exclusively via `Authorization: Bearer` /
  signed-request schemes (no cookies).
- Webhooks with their own signature verification — flag separately
  under `webhook-handler` / `slack-signing-verification`.
- Login, signup, password-reset-request endpoints — pre-auth, no
  session yet to forge.
- GraphQL endpoints behind a custom-header requirement
  (`X-Apollo-Operation-Name`, etc.).
- Endpoints already wrapped in CSRF middleware at the router level.

## Examples

True positives:
```ts
// Express — cookie session, no CSRF token
app.post("/api/profile", requireSession, async (req, res) => {
  await db.user.update({ where: { id: req.session.userId }, data: req.body });
  res.json({ ok: true });
});

// Rails — explicitly disabled
class TransfersController < ApplicationController
  skip_before_action :verify_authenticity_token
  def create
    Transfer.create!(user: current_user, amount: params[:amount])
  end
end

// Django — csrf_exempt on a write
@csrf_exempt
def update_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
```

False positives to skip:
```ts
// Bearer-only auth — not cookie-driven, browser won't auto-attach
app.post("/api/transfer", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  // ...
});

// CSRF middleware in scope
app.use(csurf());
app.post("/api/transfer", ...);

// Custom-header gate
if (req.headers["x-requested-with"] !== "fetch") return res.sendStatus(403);
```

When SameSite mode is set on the session cookie elsewhere in the
codebase and is `strict`, that's a partial mitigation — note the gap
but only flag if there's also a known exception (cross-subdomain
flow, top-level POST redirect, etc.).
