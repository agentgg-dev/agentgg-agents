---
slug: github-workflow-security
name: GitHub Actions Workflow Security
description: "GitHub Actions workflows with pull_request_target on untrusted PR code, ${{ github.event.* }} interpolated into run: shell, unpinned action versions, or persist-credentials with write-permission."
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/.github/workflows/*.{yml,yaml}"
  - "**/.gitea/workflows/*.{yml,yaml}"
references:
  - CWE-94
  - CWE-1357
  - OWASP-A06:2021
---

You are reviewing GitHub Actions workflow YAML files for the standard
set of severe misconfigurations.

## What to look for

**`pull_request_target` running untrusted PR code:**
```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test     # runs PR's code with repo secrets
```
`pull_request_target` runs in the context of the base branch with
secrets — but checking out the PR's HEAD and running its scripts is
RCE-with-secrets. Use `pull_request` for untrusted code, reserve
`pull_request_target` for cases that strictly do not run PR code.

**`${{ github.event.* }}` interpolated into a `run:` script:**
```yaml
- run: echo "Title: ${{ github.event.pull_request.title }}"
- run: |
    if [ "${{ github.event.issue.title }}" = "foo" ]; then ...; fi
```
PR/issue titles, comment bodies, branch names, and other event
fields are attacker-controlled. Substituting them into shell
scripts is shell injection. Pass them through env vars instead:
```yaml
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $TITLE"
```

**Unpinned third-party actions:**
```yaml
- uses: some-org/some-action@main
- uses: some-org/some-action@v1
```
Pin to a SHA: `uses: some-org/some-action@abc123def456...`. Major
version tags are mutable.

**Permissions too broad:**
```yaml
permissions: write-all
# or implicit (no top-level permissions = inherited default, often write)
```
Set `permissions: read-all` at the top level, then bump specific
jobs that need writes.

**`persist-credentials: true` with broad permissions:**
```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: true   # leaves GITHUB_TOKEN in .git/config
```
If a later step runs untrusted code, it can use the token.

## True positive criteria

Flag when ANY of the following hold:

1. `on: pull_request_target` workflow checks out the PR's HEAD
   (`ref: ${{ github.event.pull_request.head.sha|ref }}`) AND runs
   scripts/builds from the PR's code.
2. A `run:` script directly contains `${{ github.event.* }}`,
   `${{ inputs.* }}` from `workflow_dispatch`, `${{ steps.*.outputs.* }}`
   without source vetting.
3. A `uses:` line for a third-party action references a mutable
   tag (`@main`, `@master`, `@v1`, `@latest`).
4. Top-level `permissions: write-all` or absent permissions with a
   default of write.

## What to ignore

- Workflows triggered only by trusted events (`push` to a protected
  branch, `schedule`, manual `workflow_dispatch` by maintainers).
- `uses:` references to official `actions/*` or `github/*` actions
  on a major version tag (lower risk, but pinning to SHA is still
  recommended).
- Test workflows / examples in docs.

## Examples

True positives:
```yaml
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          echo "Reviewing: ${{ github.event.pull_request.title }}"
          npm test
```

```yaml
- uses: example-org/some-action@main
```

False positives to skip:
```yaml
on: pull_request    # safe — runs in fork context, no secrets
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "Title: $TITLE"

      - uses: example-org/action@abc123def456789abcdef...   # SHA-pinned
```
