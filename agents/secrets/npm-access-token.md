---
slug: npm-access-token
name: npm Access Token Exposure
description: 'Hardcoded npm fine-grained access tokens (npm_[A-Za-z0-9]{36}) in source or config. A leaked token can publish malicious packages to the npm registry or modify existing package versions, enabling supply chain attacks.'
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
    - regex: '\b(npm_[A-Za-z0-9]{36})\b'
      label: npm fine-grained access token (npm_)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded npm access tokens.

## Token format

Modern npm fine-grained access tokens begin with `npm_` followed by 36 alphanumeric characters: `npm_[A-Za-z0-9]{36}`. These were introduced in 2022 and replaced the legacy UUID-format tokens.

Classic/legacy npm tokens are UUIDs (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) — those may also be found but are less distinctive.

## Risk

An attacker with an npm access token can, depending on the token's scope:
- **Publish:** Push malicious code to packages the token can publish — a supply chain attack affecting every downstream consumer of the package
- **Read:** Access private package contents, including proprietary code or internal tooling
- **Write (without publish):** Modify package metadata, deprecation notices, or dist-tags
- **Automation tokens:** Often have write access to all packages in an organization

npm supply chain attacks are extremely high severity because a single compromised publish token can inject malicious code into thousands of dependent projects.

## Cross-file analysis

When a token is found, look for:
1. `.npmrc` files — tokens are commonly stored there (`//registry.npmjs.org/:_authToken=npm_...`)
2. CI/CD workflow files (`.github/workflows/`, `.travis.yml`, `Jenkinsfile`) — publish steps often embed tokens
3. `package.json` scripts that call `npm publish` — determines which packages could be compromised
4. The `publishConfig.registry` setting — indicates if a private registry is also at risk

## True positive criteria

Flag when ALL hold:
1. The value matches `npm_[A-Za-z0-9]{36}` or is a UUID in an npm authentication context (`.npmrc` `_authToken`, `NPM_TOKEN` env var value, etc.)
2. It is a literal string, not a variable reference (`$NPM_TOKEN`, `process.env.NPM_TOKEN`, `${{ secrets.NPM_TOKEN }}`)
3. It is not a placeholder: all same character, `npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

## What to ignore

- Environment variable references in `.npmrc`: `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`
- GitHub Actions: `${{ secrets.NPM_TOKEN }}`
- Clearly placeholder values in documentation or template `.npmrc` files

## Examples

True positives:
```
# .npmrc
//registry.npmjs.org/:_authToken=npm_<36-char-token>
```
```yaml
# GitHub Actions — hardcoded instead of using secrets
env:
  NPM_TOKEN: npm_<36-char-token>
```

False positives to skip:
```
# .npmrc — safe: runtime variable
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```
```yaml
# Safe: GitHub Actions secret reference
env:
  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Note which packages the token has publish access to (check `package.json` name and the token's scope) — a token scoped to a widely-downloaded package is critical severity.
