---
slug: tf-public-ingress
name: Terraform Public Ingress on Sensitive Port
description: 'aws_security_group / aws_security_group_rule / google_compute_firewall with 0.0.0.0/0 ingress on sensitive ports (22, 3306, 5432, 6379, 27017, RDP) — service is exposed to the open internet.'
version: 0.1.0
author: agentgg
noiseTier: normal
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
    - semgrepRule: infrastructure/tf-public-access
      label: Terraform 0.0.0.0/0 CIDR or public access setting
references:
  - CWE-668
  - 'OWASP-A05:2021'
---

You are reviewing Terraform configuration for security groups or
firewall rules that allow public internet access (0.0.0.0/0) to
sensitive ports.

## Sensitive ports (almost never public)

- 22 (SSH)
- 23 (Telnet)
- 3389 (RDP)
- 3306 (MySQL)
- 5432 (PostgreSQL)
- 1521 (Oracle)
- 1433 (MSSQL)
- 6379 (Redis)
- 11211 (memcached)
- 27017 (MongoDB)
- 9200 / 9300 (Elasticsearch)
- 2375 / 2376 (Docker daemon)
- 8500 (Consul)
- 8086 (InfluxDB)
- 5601 (Kibana)
- 9092 (Kafka)
- 2049 (NFS)
- 445 (SMB)

## What to look for

**AWS security group with public CIDR on sensitive port:**
```hcl
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}
```

**Inline `ingress {}` block on `aws_security_group`:**
```hcl
ingress {
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```

**GCP firewall:**
```hcl
resource "google_compute_firewall" "db" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}
```

**Azure NSG:**
```hcl
resource "azurerm_network_security_rule" "ssh" {
  source_address_prefix   = "*"
  destination_port_range  = "22"
}
```

**IPv6 wildcard equivalents:**
- `::/0` is the IPv6 wildcard, equivalent to `0.0.0.0/0`.

## True positive criteria

Flag when ANY of the following hold:

1. `cidr_blocks` / `cidr_ipv6` / `source_ranges` /
   `source_address_prefix` includes `0.0.0.0/0`, `::/0`, or `"*"`.
2. The rule's port range includes one of the sensitive ports.
3. The rule's `type`/`direction` is `ingress` / `INGRESS`.

## What to ignore

- Public ports 80 / 443 (HTTP/HTTPS) — those are intended to be
  public.
- Egress rules (outbound traffic to the internet is usually fine).
- Bastion / VPN endpoints documented as public access points (still
  worth a review).
- Test / dev environments clearly labeled and behind no production
  data.

## Examples

True positives:
```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "mysql" {
  source_ranges = ["0.0.0.0/0"]
  allow { protocol = "tcp" ports = ["3306"] }
}
```

False positives to skip:
```hcl
ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]   # HTTPS — intended public
}

ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]   # Internal only
}
```
