---
slug: tf-module-unpinned
name: Terraform Module Source Not Version-Pinned
description: Terraform module references using a Git URL or registry without a version constraint or commit SHA pin — supply-chain risk because upstream changes affect the build silently.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - tf
      - tf.json
where:
  extensions:
    - tf
    - tf.json
  preFilter:
    - semgrepRule: infrastructure/tf-module-version
      label: Terraform module block for version pin review
    - regex: 'module\s+"[^"]+"\s*\{'
      label: Terraform module block
    - regex: 'source\s*=\s*"(git::|github\.com/|registry\.terraform\.io/)'
      label: External module source
references:
  - CWE-1357
  - 'OWASP-A06:2021'
---

You are reviewing Terraform module declarations for missing version
pinning. An unpinned module reference re-fetches on every plan,
exposing the build to upstream changes — including malicious
publication if the upstream is compromised.

## What to look for

**Registry source without `version =`:**
```hcl
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # No version constraint
}
```

**Git URL without `?ref=<commit-sha>`:**
```hcl
module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git"
}

module "vpc" {
  source = "github.com/example/module"
}

module "vpc" {
  source = "git::https://github.com/example/module.git?ref=main"
  # main is mutable
}
```

**Loose version range:**
```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 3.0.0"   # accepts every future major
}
```

## Safe patterns

**Registry with exact version:**
```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.3"
}
```

**Git with commit SHA:**
```hcl
module "vpc" {
  source = "git::https://github.com/example/module.git?ref=abc123def456..."
}
```

**Pessimistic constraint (acceptable):**
```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"   # any 5.x but not 6.0
}
```

## True positive criteria

Flag when:
1. A `module` block has `source =` pointing to a registry module
   and no `version =` argument.
2. A `module` block has `source = "git::..."` or
   `source = "github.com/..."` without `?ref=<commit-sha>` (a 40-char
   hex) — ref-to-tag or ref-to-branch is mutable.
3. A `version =` constraint uses `>=`, `>`, or `*` without an upper
   bound.

## What to ignore

- Modules with `version = "X.Y.Z"` (exact pin).
- Modules with `version = "~> X.Y"` (pessimistic, acceptable).
- Git modules pinned with `?ref=<40-char-hex>` (commit SHA).
- Local modules (`source = "./modules/..."`) — already in your repo.

## Examples

True positives:
```hcl
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

module "iam" {
  source = "git::https://github.com/example/iam.git?ref=main"
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = ">= 4.0.0"
}
```

False positives to skip:
```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.3"
}

module "iam" {
  source = "git::https://github.com/example/iam.git?ref=abc123def456789abcdef0123456789abcdef012"
}

module "internal" {
  source = "./modules/internal"
}
```
