---
slug: tf-iac-surface
name: Terraform Public-Facing Infrastructure Surface
description: 'Terraform resources that create publicly accessible surfaces — API Gateway, ALB without auth, S3 public buckets, Lambda function URLs, CloudFront, RDS publicly_accessible — flagged for auth/exposure review.'
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
    - semgrepRule: infrastructure/tf-public-access
      label: Terraform public CIDR, no-auth, or publicly_accessible resource
references:
  - CWE-285
  - 'OWASP-A05:2021'
---

You are reviewing Terraform configuration for resources that create
public internet surfaces. Each is a review point: does the surface
have appropriate auth, throttling, and access logging?

## What to look for

**API Gateway with no authorizer:**
```hcl
resource "aws_apigatewayv2_route" "default" {
  route_key          = "ANY /{proxy+}"
  authorization_type = "NONE"   # or omitted
}
```

**ALB / NLB internet-facing without WAF:**
```hcl
resource "aws_lb" "public" {
  internal = false    # internet-facing
  # No associated aws_wafv2_web_acl_association
}
```

**Lambda function URL with `authorization_type = "NONE"`:**
```hcl
resource "aws_lambda_function_url" "url" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "NONE"
}
```

**S3 bucket with public ACL:**
```hcl
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
# or missing aws_s3_bucket_public_access_block
```

**RDS publicly accessible:**
```hcl
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
```

**ElastiCache / OpenSearch / Elasticsearch with public endpoint:**
```hcl
resource "aws_elasticache_cluster" "redis" {
  # No subnet_group_name pointing to private subnets
}
```

**Cloud Run / App Engine with `--allow-unauthenticated`:**
```hcl
resource "google_cloud_run_v2_service" "api" {
  ingress = "INGRESS_TRAFFIC_ALL"   # internet-facing
}
resource "google_cloud_run_service_iam_member" "public" {
  member = "allUsers"   # public
}
```

## True positive criteria

Flag when ANY of the following hold:

1. An AWS API Gateway route has `authorization_type = "NONE"` or
   omits the field with no `aws_apigatewayv2_authorizer`.
2. An ALB / NLB has `internal = false` and no WAF association.
3. A Lambda function URL has `authorization_type = "NONE"`.
4. An S3 bucket has a public ACL or no public-access-block.
5. RDS / DocumentDB / Aurora has `publicly_accessible = true`.
6. Cloud Run / App Engine / GCS allows `allUsers` IAM.

## What to ignore

- Resources intentionally public (CDN origins for static assets,
  documented public APIs).
- Internal load balancers (`internal = true`).
- Resources behind documented WAF/Cloudflare in another Terraform
  module.

## Examples

True positives:
```hcl
resource "aws_lambda_function_url" "fn" {
  function_name      = aws_lambda_function.handler.function_name
  authorization_type = "NONE"
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
}

resource "google_cloud_run_service_iam_member" "public" {
  service  = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
```

False positives to skip:
```hcl
resource "aws_apigatewayv2_route" "secure" {
  route_key          = "GET /items"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_db_instance" "db" {
  publicly_accessible = false
}
```
