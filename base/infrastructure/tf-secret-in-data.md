---
slug: tf-secret-in-data
name: Terraform Plaintext Secret in Variable / Data / tfvars
description: 'Terraform variables, data sources, or .tfvars files containing plaintext passwords, API keys, or tokens — committed to source and stored in Terraform state.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - tf
      - tf.json
      - tfvars
      - tfvars.json
where:
  extensions:
    - tf
    - tf.json
    - tfvars
    - tfvars.json
  filePatterns:
    - '**/terraform.tfvars*'
references:
  - CWE-798
  - 'OWASP-A02:2021'
---

You are reviewing Terraform configuration for plaintext secrets in
variables, data sources, locals, or .tfvars files. These get
committed to source control and stored in Terraform state — both
serious exposures.

## What to look for

**`default = "..."` on a secret-shaped variable:**
```hcl
variable "db_password" {
  default = "P@ssw0rd!"     # committed to source
}

variable "api_key" {
  default = "sk_live_..."
}
```

**Locals with secrets:**
```hcl
locals {
  jwt_secret = "supersecret"
}
```

**Inline `password = "..."` on a resource:**
```hcl
resource "aws_db_instance" "db" {
  username = "admin"
  password = "P@ssw0rd!"     # ends up in state
}
```

**`.tfvars` containing secret values:**
```
db_password = "P@ssw0rd!"
api_key     = "sk_live_..."
```

**Variable name patterns that hint at secrets:**
`*password*`, `*secret*`, `*token*`, `*key*` (but not `key_id`,
`public_key`), `*credential*`, `*private_key*`.

## Safe patterns

- Use `variable {}` declarations without `default`, and supply
  values via env (`TF_VAR_*`) or a secret manager.
- Use `data "aws_secretsmanager_secret_version" "x" {}` to fetch
  at apply time.
- Use Terraform Cloud / Spacelift / Atlantis "sensitive" variables.
- Mark variables as `sensitive = true` (this only hides them from
  CLI output — still in state).

## True positive criteria

Flag when:
1. A `variable` block has `default = "..."` where the variable name
   suggests a secret and the value is a non-placeholder.
2. A `locals` declaration includes a secret-named key with a
   non-placeholder value.
3. A resource argument like `password`, `secret_key`, `auth_token`,
   `api_key` is set to an inline string literal.
4. A `.tfvars` file contains key-value pairs matching the secret
   name patterns above with non-placeholder values.

## What to ignore

- Variables fetched from data sources at apply time.
- Variables with `default = null` / `""` / a placeholder
  (`"REPLACE_ME"`).
- Public keys, ARNs of KMS keys, etc. (these aren't secrets).
- Test fixtures and examples.

## Examples

True positives:
```hcl
variable "stripe_secret_key" {
  default = "sk_live_realsecret"
}

resource "aws_db_instance" "db" {
  password = "P@ssw0rd!"
}
```

```
# terraform.tfvars
db_password = "P@ssw0rd!"
```

False positives to skip:
```hcl
variable "stripe_secret_key" {
  description = "Stripe secret key, supplied via TF_VAR_stripe_secret_key"
  type        = string
  sensitive   = true
}

resource "aws_db_instance" "db" {
  password = data.aws_secretsmanager_secret_version.db.secret_string
}
```
