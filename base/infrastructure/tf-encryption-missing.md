---
slug: tf-encryption-missing
name: Terraform Resource Missing Encryption at Rest
description: Terraform S3 buckets, RDS instances, EBS volumes, EFS, SQS queues, DynamoDB tables, etc. without encryption_at_rest / kms_key_id / sse_algorithm configured.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.tf"
  - "**/*.tf.json"
references:
  - CWE-311
  - OWASP-A02:2021
---

You are reviewing Terraform configuration for storage resources
created without encryption at rest. Many AWS / GCP / Azure services
support and recommend KMS-managed encryption; omitting it leaves data
unencrypted (or encrypted only with the cloud provider's default
key, which is less auditable).

## What to look for (AWS)

**S3 bucket without `server_side_encryption_configuration`:**
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  # No encryption block
}
```
Modern AWS encrypts S3 by default with SSE-S3, but explicit KMS is
the recommended posture. Flag missing `aws_s3_bucket_server_side_encryption_configuration`.

**RDS without `storage_encrypted`:**
```hcl
resource "aws_db_instance" "db" {
  engine = "postgres"
  # storage_encrypted not set — defaults false
}
```

**EBS volume without `encrypted`:**
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted defaults to false
}
```

**SQS queue without `kms_master_key_id`:**
```hcl
resource "aws_sqs_queue" "events" {
  name = "events"
  # No kms_master_key_id
}
```

**DynamoDB table without `server_side_encryption`:**
```hcl
resource "aws_dynamodb_table" "users" {
  name = "users"
  # Default encryption uses AWS-owned key, not customer-managed
}
```

**EFS without `encrypted`:**
```hcl
resource "aws_efs_file_system" "shared" {
  # encrypted defaults to false
}
```

## GCP

```hcl
resource "google_storage_bucket" "data" {
  # No encryption block — uses Google-managed key
}
```

## Azure

```hcl
resource "azurerm_storage_account" "data" {
  # encryption_enforce_https not set
  # min_tls_version unset
}
```

## True positive criteria

Flag when:
1. A resource (S3, RDS, EBS, EFS, SQS, DynamoDB, GCS, ASA, etc.)
   is declared without an explicit encryption configuration block
   (`encrypted`, `storage_encrypted`, `server_side_encryption`,
   `kms_key_id`, `encryption`, `sse_algorithm`).

## What to ignore

- Resources whose encryption is enforced by a higher-level policy
  (Organization SCP, Cloud Custodian, AWS Config rule) — flag for
  review but lower urgency.
- Public-data resources where encryption-at-rest provides no real
  benefit (publicly readable CDN buckets).
- Test / sandbox resources clearly labeled.

## Examples

True positives:
```hcl
resource "aws_db_instance" "db" {
  engine            = "postgres"
  username          = "admin"
  password          = "..."
  allocated_storage = 20
  # No storage_encrypted = true
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}
# No companion aws_s3_bucket_server_side_encryption_configuration
```

False positives to skip:
```hcl
resource "aws_db_instance" "db" {
  engine            = "postgres"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}
```
