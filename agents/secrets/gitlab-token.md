---
slug: gitlab-token
name: GitLab Token Exposure
description: 'Hardcoded GitLab personal access (glpat-), pipeline (glptt-), and runner registration (GR1348941) tokens in source or config. A leaked token can read private repos, push code, or register unauthorized CI runners.'
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
    - regex: '\b(glpat-[0-9a-zA-Z_-]{20})(?:\b|$)'
      label: GitLab personal access token (glpat-)
    - regex: '\b(glptt-[0-9a-f]{40})\b'
      label: GitLab pipeline trigger token (glptt-)
    - regex: '\b(GR1348941[0-9a-zA-Z_-]{20})(?:\b|$)'
      label: GitLab runner registration token (GR1348941)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded GitLab API tokens.

## Token types

**Personal Access Token (PAT):** prefix `glpat-` followed by 20 alphanumeric/dash/underscore characters. Authenticates as a GitLab user; permissions depend on the scopes granted (`api`, `read_repository`, `write_repository`, `sudo`). A PAT with `api` scope is nearly equivalent to full user access.

**Pipeline Trigger Token:** prefix `glptt-` followed by 40 hex characters. Triggers CI/CD pipelines via the GitLab API. Attacker can kick off arbitrary pipelines, potentially exfiltrating secrets injected at pipeline runtime.

**Runner Registration Token:** prefix `GR1348941` followed by 20 alphanumeric characters. Registers a new CI runner against a GitLab instance. Attacker can add a malicious runner to intercept and modify pipeline jobs.

## Cross-file analysis

When a token is found, check:
1. The `glpat-` scopes — look for `.gitlab-ci.yml`, Terraform GitLab provider config, or API call targets to determine what access was granted
2. For `glptt-` tokens, look at which project pipeline they target and what secrets the pipeline injects
3. Whether the token appears in a `.gitlab-ci.yml` variable block vs. a runtime secrets manager

## True positive criteria

Flag when ALL hold:
1. The value matches the exact prefix format
2. It is a literal string value, not a variable reference (`$CI_JOB_TOKEN`, `$GITLAB_TOKEN`, `process.env.GITLAB_TOKEN`)
3. It is not a placeholder or all-same-character string

## What to ignore

- GitLab CI built-in variables: `$CI_JOB_TOKEN`, `$CI_REGISTRY_PASSWORD` — runtime-injected
- Environment variable references in code
- Masked or redacted values in CI config
- Test fixtures that clearly use fake values

## Examples

True positives:
```yaml
# Hardcoded in .gitlab-ci.yml
variables:
  DEPLOY_TOKEN: glpat-<20-char-token>
```
```py
gl = gitlab.Gitlab('https://gitlab.com', private_token='glpat-<20-char-token>')
```

False positives to skip:
```yaml
variables:
  DEPLOY_TOKEN: $GITLAB_DEPLOY_TOKEN
```
```py
gl = gitlab.Gitlab('https://gitlab.com', private_token=os.environ['GITLAB_TOKEN'])
```

Note the token type found, the file and line, and what the code does with the token (API scope, project target, pipeline name) to assess the blast radius.
