---
slug: unsafe-redirect
name: Unsafe Redirect (Allowlist Bypass)
description: Redirect destination that passes a superficial validation check but can still be bypassed — URL parsing inconsistencies, double-slash, unicode, open redirect_uri matching. Walker mode reads validation helpers to check for known bypass patterns.
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
  - regex: "\\.startsWith\\s*\\(\\s*[\"']/[\"']\\s*\\)"
    label: "startsWith('/') check — verify it also rejects '//'"
  - regex: "new\\s+URL\\s*\\([^,)]+,\\s*[\"']https?://"
    label: "new URL(input, base) — verify base is enforced"
  - regex: "\\.includes\\s*\\(\\s*[\"'][^\"']*\\.[a-z]{2,}[\"']"
    label: ".includes() domain match — substring bypassable"
  - regex: "redirect_uri|returnUrl|returnTo|redirectUrl"
    label: "redirect_uri / returnUrl identifier — validation logic likely nearby"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-601
  - OWASP-A01:2021
---

You are reviewing source code for redirect validation that appears to
restrict the destination but can be bypassed by an attacker. This is
distinct from the `open-redirect` agent (which finds completely
unvalidated redirects) — this agent focuses on validation logic that
exists but is incomplete or bypassable.

**Walker mode advantage:** the validator is typically a shared helper
(`isAllowedRedirect`, `validateReturnUrl`, `safeNext`). Open it and
look specifically for the bypass patterns: `startsWith("/")` without
also rejecting `//`; `new URL(input, base)` without re-checking the
resolved origin; `.includes(domain)` instead of a proper origin
comparison; missing URL decoding before the check.

## Bypass patterns to look for

**Double-slash (`//`) treated as protocol-relative:**
```ts
// Attacker supplies: //evil.com/phish
if (!dest.startsWith("/")) throw error;   // passes — starts with /
res.redirect(dest);   // browser treats // as https://evil.com
```
Safe guard: reject any value where the second character is also `/`.

**`new URL(dest, base)` with an absolute destination:**
```ts
const safeUrl = new URL(dest, "https://myapp.com");
// Attacker supplies: https://evil.com — the base is ignored
// safeUrl.origin === "https://evil.com"
redirect(safeUrl.toString());
```
`new URL(absoluteUrl, base)` ignores `base` entirely when
`absoluteUrl` is already absolute.

**`startsWith` check that doesn't anchor the path:**
```ts
const ALLOWED = "https://myapp.com";
if (!dest.startsWith(ALLOWED)) throw error;  // passes
// Attacker: https://myapp.com.evil.com/path
res.redirect(dest);
```
Safe guard: check `new URL(dest).origin === ALLOWED_ORIGIN` or
append a trailing `/` to the allowed prefix.

**Regex matching `redirect_uri` in OAuth flows:**
```ts
// Client's redirect_uri validated with a loose regex
if (!/^https:\/\/myapp\.com/.test(redirectUri)) throw error;
// Attacker: https://myapp.com.evil.com/callback — passes the regex
```

**`includes` instead of `startsWith` or `endsWith`:**
```ts
if (!dest.includes("myapp.com")) throw error;
// Attacker: https://evil.com?ref=myapp.com — includes matches
```

**Unicode / encoded bypass:**
```ts
if (!isRelative(dest)) throw error;
// Attacker: %2F%2Fevil.com (decoded: //evil.com) after server decodes
```

## True positive criteria

Flag when ALL of the following hold:

1. A redirect destination is validated before use.
2. The validation has an identifiable bypass: `startsWith("/")` alone,
   `new URL(input, base)` without checking the resolved origin,
   `includes(domain)`, a regex anchored on domain but not full origin,
   or missing decoding before the check.
3. The redirect is issued with the insufficiently-validated value.

## What to ignore

- `startsWith("/")` AND `!startsWith("//")` — this combination is
  actually safe for relative-path-only redirects.
- `new URL(dest).origin === ALLOWED_ORIGIN` — correct origin check.
- A strict allowlist of exact full URLs with no wildcards or
  substring matching.
- Test files.

## Examples

True positives:
```ts
// Double-slash bypass
if (!next.startsWith("/")) return res.redirect("/");
res.redirect(next);   // //evil.com passes

// new URL ignores base when input is absolute
const url = new URL(returnTo, "https://myapp.com");
redirect(url.href);   // returnTo = "https://evil.com" → redirects there

// startsWith without trailing slash
if (!dest.startsWith("https://myapp.com")) throw new Error();
res.redirect(dest);   // https://myapp.com.evil.com passes
```

False positives to skip:
```ts
// Correct relative-only check
if (next.startsWith("//") || /^https?:\/\//i.test(next)) return res.redirect("/");
res.redirect(next);

// Correct origin check
const u = new URL(dest);
if (u.origin !== "https://myapp.com") throw new Error("disallowed");
res.redirect(dest);
```
