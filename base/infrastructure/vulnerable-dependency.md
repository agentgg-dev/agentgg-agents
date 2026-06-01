---
slug: vulnerable-dependency
name: Vulnerable or Suspicious Dependency
description: 'package.json / requirements.txt / Gemfile / pom.xml / go.mod entries that pin known-CVE versions, abandoned packages, or typosquat-shaped names ("expres", "loadsh", "moment-js"). Catches risky supply-chain surface before `npm audit` runs.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    files:
      - '**/package.json'
      - '**/package-lock.json'
      - '**/yarn.lock'
      - '**/pnpm-lock.yaml'
      - '**/requirements*.txt'
      - '**/Pipfile'
      - '**/Pipfile.lock'
      - '**/pyproject.toml'
      - '**/Gemfile'
      - '**/Gemfile.lock'
      - '**/go.mod'
      - '**/pom.xml'
      - '**/build.gradle'
      - '**/build.gradle.kts'
      - '**/composer.json'
where:
  filePatterns:
    - '**/package.json'
    - '**/package-lock.json'
    - '**/yarn.lock'
    - '**/pnpm-lock.yaml'
    - '**/requirements*.txt'
    - '**/Pipfile'
    - '**/Pipfile.lock'
    - '**/pyproject.toml'
    - '**/Gemfile'
    - '**/Gemfile.lock'
    - '**/go.mod'
    - '**/pom.xml'
    - '**/build.gradle'
    - '**/build.gradle.kts'
    - '**/composer.json'
references:
  - CWE-1395
  - CWE-1357
  - 'OWASP-A06:2021'
---

You are reviewing a dependency manifest for **risky supply-chain
surface** — package entries that look like one of:

1. A version pinned to a release with a publicly known CVE.
2. A package whose name is a likely typosquat of a popular package.
3. A package abandoned (last release years ago) where a maintained
   replacement is the norm.
4. A package with a release tag indicating known security risk
   (`*-rc`, `*-alpha`, `0.0.x` in production, or git/file URLs
   pointing to unreviewed sources).

This is closer to SCA than classic SAST, but it's tractable as a
manifest review: the answer is in the version string.

## What to look for

**Known-CVE version pins (examples, non-exhaustive — your training
knows others):**
- `jsonwebtoken` versions `<= 8.5.1` (algorithm-confusion CVE).
- `lodash` versions `< 4.17.21` (prototype pollution chain).
- `event-stream` any pin (compromised 2018 — should not appear).
- `node-ipc` `10.1.1` / `10.1.2` (protestware sabotage).
- `colors` `1.4.44-liberty-2` (protestware infinite loop).
- `marsdb` (abandoned + known issues; flag any pin).
- `juicy-evil-wasp` / `epilogue-js` / `marsdb` / `express-jwt < 6.0` —
  illustrative.

**Typosquat-shaped names:** look for one-letter edits from popular
packages or transposed words:
- `expres`, `expresss`, `expres-js`, `experss`
- `loadsh`, `lodaash`, `lodahs`
- `momnt`, `moment-js` (the real one is `moment`)
- `axioss`, `axois`
- `reactjs`, `react-js` (the real one is `react`)
- `crypt-js`, `crypto-js-pure`
- `js-jquery`

**Suspicious version patterns:**
- `"foo": "*"` or `"foo": "latest"` — unbounded, opens to malicious
  releases.
- `"foo": "0.0.x"` — pre-release in production.
- `"foo": "git+https://github.com/randoperson/foo.git"` — direct git
  install, no registry review.
- `"foo": "file:../../private-fork"` — local override that may carry
  forked vulnerabilities.

**Lockfile-specific:**
- `package-lock.json` with `"resolved"` pointing to a non-default
  registry (`registry.npmjs.org`) — possible scope confusion.
- `yarn.lock` with integrity hashes missing.

## True positive criteria

Flag when ANY of the following hold:

1. A pinned version matches a CVE you can identify by name + version
   range (high confidence — don't guess at version numbers; if you're
   unsure, lean false-positive).
2. The package name is within edit-distance 1–2 of a popular package
   AND not the popular package itself (typosquat).
3. The version specifier is unbounded (`*`, `latest`) or points to a
   non-registry source (`git+`, `file:`) without an inline justifying
   comment.
4. The package is in a public abandoned-or-malicious roster (e.g.,
   `event-stream`, `flatmap-stream`, `colors@1.4.44-liberty-2`,
   `marsdb` for production data).

## What to ignore

- Major frameworks at supported LTS versions (React 18, Express 4.x,
  Django 4.x, etc.).
- DevDependencies in test/build-only context, unless the dep itself
  runs in CI with secrets.
- Internal monorepo workspace references (`"workspace:*"`,
  `"@scope/internal-pkg": "*"`) where the source is part of the same
  repo.
- Lockfile-only entries that don't appear in the top-level manifest
  (transitive, will get updated when a top-level upgrades).

## Examples

True positives:
```json
{
  "dependencies": {
    "jsonwebtoken": "^7.4.3",
    "lodash": "4.17.4",
    "event-stream": "^3.3.4",
    "expres": "^1.0.0",
    "crypto-js-pure": "*",
    "private-thing": "git+https://github.com/randomuser/private-thing.git"
  }
}
```
Each line is its own finding: outdated JWT, vulnerable lodash,
compromised event-stream, typosquat of express, unbounded version,
unreviewed git source.

False positives to skip:
```json
{
  "dependencies": {
    "express": "^4.21.0",
    "react": "^18.3.1",
    "jsonwebtoken": "^9.0.2",
    "@my-org/internal-utils": "workspace:*"
  }
}
```

When in doubt about a CVE pin, prefer to flag with low confidence and
recommend `npm audit` / `pip-audit` / `bundler-audit` rather than
fabricating a CVE identifier. The goal here is "surface candidates
worth a human look", not "produce an authoritative CVE list".
