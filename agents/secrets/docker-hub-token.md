---
slug: docker-hub-token
name: Docker Hub Access Token Exposure
description: 'Hardcoded Docker Hub personal access tokens (dckr_pat_[27 chars]) in source or config. A leaked token can pull private images, push malicious images to repositories, and access organization membership.'
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
    - regex: '\b(dckr_pat_[a-zA-Z0-9_-]{27})(?:$|[^a-zA-Z0-9_-])'
      label: Docker Hub personal access token (dckr_pat_)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Docker Hub personal access tokens.

## Token format

Docker Hub personal access tokens (introduced 2021) begin with `dckr_pat_` followed by 27 alphanumeric, dash, or underscore characters.

## Risk

An attacker with a Docker Hub token can, depending on the token's permissions:
- **Read:** Pull all private images in the account and any organizations the account belongs to — exposes proprietary code, configuration, and secrets baked into images
- **Read/Write:** Push modified images to existing repositories — enables supply chain attacks for every system that pulls those images
- **Read/Write/Delete:** Delete image tags, overwrite production images, cause service outages

Docker image supply chain attacks are high severity: a malicious image pushed to a CI/CD pipeline's base image can compromise every build and every runtime environment pulling that image.

## Cross-file analysis

When a token is found, look for:
1. Docker Hub username alongside the token — confirms which account is exposed
2. `docker push` commands and image names in CI/CD files — determines which images the token can write
3. Images being used as base images (`FROM ...`) — if those can be overwritten, every downstream consumer is at risk
4. `docker-compose.yml` files that pull private images — determines what proprietary code is exposed

## True positive criteria

Flag when ALL hold:
1. The value matches `dckr_pat_[a-zA-Z0-9_-]{27}`
2. It is a string literal, not a variable reference (`$DOCKER_TOKEN`, `process.env.DOCKER_HUB_TOKEN`, `${{ secrets.DOCKER_TOKEN }}`)
3. It is not a placeholder value

## What to ignore

- Environment variable references in CI config: `$DOCKER_TOKEN`, `${{ secrets.DOCKERHUB_TOKEN }}`
- Password fields that contain a password hash rather than a PAT (different format)
- Redacted or masked values

## Examples

True positives:
```yaml
# .github/workflows/publish.yml — hardcoded
- uses: docker/login-action@v2
  with:
    username: mycompany
    password: dckr_pat_<27-char-token>
```
```sh
echo "dckr_pat_<27-char-token>" | docker login --username mycompany --password-stdin
```

False positives to skip:
```yaml
- uses: docker/login-action@v2
  with:
    username: ${{ secrets.DOCKERHUB_USERNAME }}
    password: ${{ secrets.DOCKERHUB_TOKEN }}
```

Note which Docker Hub repositories the code pushes to or pulls from, to determine if images could be poisoned or exfiltrated.
