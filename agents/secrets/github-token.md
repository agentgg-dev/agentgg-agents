---
slug: github-token
name: GitHub Token Exposure
description: 'Hardcoded GitHub tokens (personal access ghp_, OAuth gho_, app ghu_/ghs_, refresh ghr_) in source code or config. A leaked token can read private repos, push code, manage secrets, and trigger CI/CD pipelines.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\b(ghp_[a-zA-Z0-9]{36})\b'
      label: GitHub personal access token (ghp_)
    - regex: '\b(gho_[a-zA-Z0-9]{36})\b'
      label: GitHub OAuth access token (gho_)
    - regex: '\b((?:ghu|ghs)_[a-zA-Z0-9]{36})\b'
      label: GitHub app user/server token (ghu_/ghs_)
    - regex: '\b(ghr_[a-zA-Z0-9]{76})\b'
      label: GitHub refresh token (ghr_)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded GitHub API tokens. All modern GitHub tokens use a typed-prefix format introduced in 2021, making them unambiguous when found in code.

## Token types

| Prefix | Type | Risk |
|--------|------|------|
| `ghp_` | Personal Access Token (classic or fine-grained) | High — scoped to whatever the user authorized |
| `gho_` | OAuth App access token | High — acts as the authorizing user |
| `ghu_` | GitHub App user-to-server token | High — app acting as a specific user |
| `ghs_` | GitHub App server-to-server token | High — app's own permissions |
| `ghr_` | Refresh token | Medium — used to obtain a new access token |

All have 36 characters of random alphanumeric after the prefix (ghr_ has 76).

## Cross-file analysis

When a token is found, check:
1. How the token is used: API calls to repos, actions, secrets, packages, or admin endpoints — determines what an attacker can do
2. Whether the token appears in CI/CD config (`.github/workflows/`, `.travis.yml`, `Jenkinsfile`) — often indicates a service account token with elevated permissions
3. Whether `GITHUB_TOKEN` is being passed to an external service or logged

## True positive criteria

Flag when ALL hold:
1. The value matches the exact prefix+length pattern
2. It is a string literal (not a variable reference like `process.env.GITHUB_TOKEN` or `${{ secrets.GITHUB_TOKEN }}`)
3. It does not look like a placeholder: all same character, `ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`, etc.

## What to ignore

- GitHub Actions built-in `${{ secrets.GITHUB_TOKEN }}` or `${{ github.token }}` — these are ephemeral tokens injected at runtime, not hardcoded
- Environment variable references: `process.env.GITHUB_TOKEN`, `os.environ.get('GITHUB_TOKEN')`
- Clearly redacted strings or documentation examples

## Examples

True positives:
```yaml
# In .github/workflows/deploy.yml — hardcoded instead of using secrets
env:
  GITHUB_TOKEN: ghp_<36-char-token>
```
```ts
const octokit = new Octokit({ auth: 'ghp_<36-char-token>' });
```

False positives to skip:
```yaml
- uses: actions/checkout@v4
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
```
```ts
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
```

Report the token prefix, the file and line number, how the token is used (what API calls it makes), and whether the token appears to belong to a user account or a service account.
