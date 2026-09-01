---
slug: cratesio-api-key
name: crates.io API Token Exposure
description: 'Hardcoded crates.io API tokens committed to source. Allows publishing or yanking Rust crates under the associated account — a supply chain risk affecting downstream Rust projects.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(?i)(?:crates.io|CARGO_REGISTRY_TOKEN|crates_token).{0,30}[=:"''\s]+[a-zA-Z0-9_\-]{32,64}\b'
        in:
          - '**/*'
          - '**/.cargo/credentials.toml'
          - '**/Cargo.toml'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/target/**'
        label: crates.io API token near crates keyword or cargo registry
where:
  filePatterns:
    - '**/*'
    - '**/.cargo/**'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/target/**'
    - '**/dist/**'
  preFilter:
    - regex: '(?i)CARGO_REGISTRY_TOKEN\s*=\s*[''"]?[a-zA-Z0-9_\-]{32,64}'
      label: CARGO_REGISTRY_TOKEN assignment
    - regex: 'token\s*=\s*"[a-zA-Z0-9_\-]{32,64}"'
      label: Cargo token in credentials.toml format
    - regex: '(?i)cratesio.{0,20}token|crates\.io.{0,20}api.{0,20}key'
      label: crates.io token variable name
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded crates.io API tokens.

## Token format

crates.io API tokens: alphanumeric strings, 32-64 chars. Generated at crates.io/settings/tokens. Also stored in `~/.cargo/credentials.toml`:

```toml
[registry]
token = "your-token-here"
```

## What a leaked token enables

- Publish new versions of any crate owned by the token's account — supply chain attack vector
- Yank (invalidate) existing crate versions — denial of service to downstream users
- Invite or remove collaborators from crate ownership
- If the crate is widely used (transitive dependency in many Rust projects): a malicious publish reaches all downstream consumers on next `cargo update`

## True positive criteria

Flag at critical:
1. `CARGO_REGISTRY_TOKEN=<value>` in a CI configuration with a literal token value
2. `~/.cargo/credentials.toml` committed to the repository (contains the token in plaintext)
3. Token value found near `crates.io` or `cargo publish` commands

## What to ignore

- `${{ secrets.CARGO_REGISTRY_TOKEN }}` — safe GitHub Actions secret reference
- `$CARGO_REGISTRY_TOKEN` in shell scripts — safe env reference
- `token = "YOUR_TOKEN_HERE"` — placeholder value

## Context

crates.io tokens are commonly found committed in:
- GitHub Actions workflows (`.github/workflows/publish.yml`) with hardcoded values
- `~/.cargo/credentials.toml` files accidentally committed with dotfiles

Report: any crate names associated with the token (visible from `Cargo.toml` or `cargo publish` commands nearby), the weekly download count if visible (indicates blast radius), and where the token appears (CI config, credentials file, etc.).
