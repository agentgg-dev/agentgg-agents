---
slug: digitalocean-token
name: DigitalOcean Token Exposure
description: 'Hardcoded DigitalOcean personal access tokens (dop_v1_ prefix) in source or config. These tokens grant full API access to the DigitalOcean account: Droplets, databases, Kubernetes clusters, DNS, and networking.'
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
    - regex: '\bdop_v1_[a-f0-9]{64}\b'
      label: DigitalOcean personal access token (dop_v1_ prefix)
    - regex: '(?i)(?:digitalocean|do_token|DIGITALOCEAN_TOKEN).{0,20}[=:"''\s]+[a-f0-9]{64}\b'
      label: DigitalOcean token in config variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded DigitalOcean personal access tokens. DigitalOcean tokens are long-lived credentials that grant complete API access to cloud infrastructure.

## Token format

DigitalOcean personal access tokens follow the format:
```
dop_v1_<64 lowercase hex characters>
```
Total length: 71 characters.

They are created in the DigitalOcean control panel under API > Personal Access Tokens and can be scoped as read-only or read-write.

## What a leaked token enables

**Read-write token:**
- Create, delete, or resize Droplets (VMs)
- Access Droplet console and SSH via API
- Modify DNS records (domain hijacking)
- Access managed databases (connection strings, passwords)
- Manage Kubernetes clusters and retrieve `kubeconfig`
- Modify load balancers and firewalls
- Read and write Spaces (object storage, similar to S3)
- Incur billing charges

**Read-only token:** enumerate all resources, read database connection details, retrieve kubeconfigs — still significant for reconnaissance and data access.

## Cross-file analysis

When a token is found:
1. Look at what DigitalOcean API operations the code performs — determines blast radius
2. Check if the token appears in Terraform state (`terraform.tfstate`) or Terraform provider config — if it's a `digitalocean` Terraform provider token, it controls all infrastructure-as-code resources
3. Look for `SPACES_ACCESS_KEY` and `SPACES_SECRET_KEY` nearby — these are separate object storage credentials but often committed alongside the main token

## True positive criteria

Flag when ALL hold:
1. The value matches `dop_v1_[a-f0-9]{64}` exactly
2. It is a string literal, not an environment variable reference
3. It is not a placeholder (64 zeros, `dop_v1_yourtokenhere`)

## What to ignore

- Environment variable references: `DIGITALOCEAN_TOKEN=${DO_TOKEN}`, `token = var.do_token`
- DigitalOcean App Platform environment variable configurations where the token is referenced but not embedded
- Legacy token format (pre-`dop_v1_` tokens, which were 64 raw hex chars) — flag these only if they appear directly next to "digitalocean" context

## Examples

True positives:
```yaml
# terraform/main.tf
provider "digitalocean" {
  token = "dop_v1_abc123def456..."
}
```
```env
DIGITALOCEAN_TOKEN=dop_v1_abc123def456...
DO_TOKEN=dop_v1_abc123def456...
```

False positives to skip:
```yaml
provider "digitalocean" {
  token = var.do_token
}
```
```env
DIGITALOCEAN_TOKEN=${DO_TOKEN}
```

Report whether the token is read-write or read-only (check variable name or nearby comments), what infrastructure resources the code manages with it, and whether it appears in Terraform config (indicates it controls IaC-managed infrastructure).
