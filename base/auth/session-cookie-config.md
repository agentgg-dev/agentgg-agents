---
slug: session-cookie-config
name: Session Cookie Configuration
description: 'Session/auth cookies set without httpOnly, secure, or sameSite — exposed to XSS theft, insecure HTTP transit, or CSRF. Follows cookie-setter helpers and library configs.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'cookies\s*\(\s*\)\.set\s*\(|\.cookie\s*\(\s*["''](session|auth|token|sid|jwt|access)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Cookie set for session/auth name
      - regex: 'setHeader\s*\(\s*["'']Set-Cookie["'']'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Raw Set-Cookie header construction
      - regex: '(sessionCookie|cookieOptions)\s*:'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Library session/cookie config block
      - regex: setSessionCookie\s*\(|setAuthCookie\s*\(|writeSession\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Project-defined cookie helper
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
    - regex: 'cookies\s*\(\s*\)\.set\s*\(|\.cookie\s*\(\s*["''](session|auth|token|sid|jwt|access)'
      label: Cookie set for session/auth name
    - regex: 'setHeader\s*\(\s*["'']Set-Cookie["'']'
      label: Raw Set-Cookie header construction
    - regex: '(sessionCookie|cookieOptions)\s*:'
      label: Library session/cookie config block
    - regex: setSessionCookie\s*\(|setAuthCookie\s*\(|writeSession\s*\(
      label: Project-defined cookie helper
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-1004
  - CWE-614
  - CWE-1275
  - 'OWASP-A05:2021'
---

You are reviewing source code for session / authentication cookies
set without the security attributes needed to protect them from XSS
theft, insecure transit, and CSRF.

**Cross-file analysis:** projects usually centralize cookie writes
in a `setSession` / `setAuthCookie` helper or a session library
config. When the candidate calls such a helper, open it and verify
the cookie options at the source. For library configs (NextAuth,
Lucia, iron-session, Better Auth), follow the config object's
import chain to find all attributes — they may be split between
defaults and overrides.

## Required cookie attributes for session/auth cookies

- **`httpOnly: true`** — prevents JavaScript on the page from
  reading the cookie via `document.cookie`. Mitigates XSS token
  theft.
- **`secure: true`** — cookie is only sent over HTTPS. Prevents
  network sniffers from capturing the token on plain HTTP.
- **`sameSite: "lax"` or `"strict"`** — cookie is not sent on
  cross-site requests, mitigating CSRF. `"none"` requires `secure`.
- **`maxAge` / `expires`** — bounded lifetime so a stolen cookie
  is not perpetually valid.

## What to look for

**`cookies().set` / `res.cookie` for an auth/session cookie:**
```ts
import { cookies } from "next/headers";
cookies().set("session", token, { httpOnly: true });
// Missing secure + sameSite
```
```ts
res.cookie("auth", token);   // no options at all
res.cookie("auth", token, { httpOnly: true });   // missing secure / sameSite
```

**Raw `Set-Cookie` header construction:**
```ts
res.setHeader("Set-Cookie", `session=${token}; HttpOnly`);
// Missing Secure and SameSite
```

**iron-session / Lucia / NextAuth / Better Auth options:**
Check the library config for `cookieOptions` / `sessionCookie`:
```ts
betterAuth({
  cookieOptions: { secure: true, httpOnly: true },  // missing sameSite
});

new Lucia(adapter, {
  sessionCookie: { attributes: { secure: false } },  // explicit unsafe
});
```

## True positive criteria

Flag a cookie write as a finding when:
1. The cookie name suggests a session/auth token: `session`, `auth`,
   `token`, `sid`, `jwt`, anything containing "session" or "auth".
2. Any of `httpOnly`, `secure`, or `sameSite` is missing or set to
   an unsafe value (`secure: false`, `sameSite: "none"` without
   `secure: true`, `httpOnly: false`).

For library configurations: flag missing or unsafe values in
`cookieOptions`, `sessionCookie.attributes`, or equivalent.

## What to ignore

- Non-auth cookies: theme, locale, CSRF token (the CSRF token cookie
  itself does not need `httpOnly`), analytics consent.
- Local development overrides clearly gated on a dev-only env var:
  `secure: process.env.NODE_ENV === "production"`.
- Test files.

## Examples

True positives:
```ts
// Missing all three
cookies().set("session", token);

// Only httpOnly
res.cookie("auth_token", token, { httpOnly: true });

// secure: false explicitly
new Lucia(adapter, {
  sessionCookie: { attributes: { secure: false, httpOnly: true } },
});

// Raw Set-Cookie missing Secure
res.setHeader("Set-Cookie", `auth=${jwt}; HttpOnly; SameSite=Lax`);
```

False positives to skip:
```ts
// All three present
cookies().set("session", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 60 * 60 * 24,
});

// Dev override pattern
res.cookie("session", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
});

// CSRF token cookie — not auth, httpOnly intentionally false
res.cookie("csrf_token", token, { secure: true, sameSite: "strict" });
```
