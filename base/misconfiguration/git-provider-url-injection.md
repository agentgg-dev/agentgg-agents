---
slug: git-provider-url-injection
name: Git Provider URL Built from User Input
description: GitHub / GitLab / Bitbucket API URLs constructed via template literal interpolation of caller-supplied org / repo / user values — webhook configuration or repo clone URLs can be aimed at attacker-controlled endpoints. Walker mode traces validators across files.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
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
  - regex: "`https?://(api\\.)?github\\.com[^`]*\\$\\{"
    label: "GitHub URL with template-literal interpolation"
  - regex: "`https?://(api\\.)?gitlab\\.com[^`]*\\$\\{|`https?://[^`]*gitlab[^`]*\\$\\{"
    label: "GitLab URL with template-literal interpolation"
  - regex: "`https?://(api\\.)?bitbucket\\.org[^`]*\\$\\{"
    label: "Bitbucket URL with template-literal interpolation"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-918
  - CWE-20
  - OWASP-A10:2021
---

You are reviewing source code that builds URLs for Git providers
(GitHub, GitLab, Bitbucket, self-hosted Git) by interpolating
caller-supplied values into the URL.

**Walker mode advantage:** repositories often validate org/repo
values in a shared `isValidGitRef()` / `assertValidRepoName()`
helper. Open it and verify the regex matches the provider's actual
identifier spec (e.g., GitHub usernames are `/^[a-z0-9-]{1,39}$/i`).
A loose or missing validator turns the URL builder into an SSRF
sink. Failure modes:

1. **SSRF via crafted repo name:** the caller supplies an org or repo
   value that escapes the intended URL structure with `..`, `?`, or
   `@`, redirecting the fetch to attacker-controlled hosts.
2. **Webhook / clone URL pointed at attacker host:** if the URL is
   used to configure a webhook target or to clone a repo, the
   attacker can drive the integration toward their own server.

## What to look for

**GitHub API URL with interpolation:**
```ts
const url = `https://api.github.com/repos/${owner}/${repo}`;
await fetch(`https://api.github.com/orgs/${org}/members`);
const link = `https://github.com/${user}/${repo}/commits`;
```

**GitLab / Bitbucket:**
```ts
const url = `https://gitlab.com/api/v4/projects/${id}`;
const url = `https://bitbucket.org/api/2.0/repositories/${slug}`;
```

**Self-hosted Git:**
```ts
const u = `https://git.example.com/repos/${slug}`;
```

## Required validation

The interpolated values should be validated before use:
```ts
const OWNER = /^[a-z0-9-]{1,39}$/i;     // GitHub username spec
const REPO  = /^[a-zA-Z0-9._-]{1,100}$/;
if (!OWNER.test(owner) || !REPO.test(repo)) throw new Error("invalid");
```

## True positive criteria

Flag when BOTH of the following hold:

1. A template literal builds a URL whose host is a Git provider
   (`api.github.com`, `github.com`, `gitlab.com`, `bitbucket.org`,
   self-hosted Git domain).
2. The interpolated value comes from user input and is not validated
   against a strict character allowlist.

## What to ignore

- URLs built from internal identifiers (validated DB rows, session
  values).
- URLs where the interpolated value is validated upstream against
  a strict regex.
- Test files.

## Examples

True positives:
```ts
// Owner / repo from request, no validation
const owner = req.body.owner;
const repo = req.body.repo;
const data = await fetch(`https://api.github.com/repos/${owner}/${repo}`);

// User-supplied slug
const url = `https://gitlab.com/api/v4/projects/${req.query.slug}`;
```

False positives to skip:
```ts
// Validated input
const OWNER = /^[a-z0-9-]{1,39}$/i;
const REPO = /^[a-zA-Z0-9._-]{1,100}$/;
if (!OWNER.test(owner) || !REPO.test(repo)) throw new Error("invalid");
const url = `https://api.github.com/repos/${owner}/${repo}`;
```
