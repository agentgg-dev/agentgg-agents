---
slug: iam-permissions
name: Cloud IAM Permissions Review
description: 'IAM role / policy / service-account assignments with overly broad actions, wildcard resources, AWS-managed broad policies, or cross-account trust without conditions.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - tf
      - yaml
      - yml
      - json
where:
  extensions:
    - tf
    - yaml
    - yml
    - json
  preFilter:
    - semgrepRule: cloud/iam-wildcard
      label: IAM wildcard Action/Resource or admin policy attachment
references:
  - CWE-732
  - 'OWASP-A01:2021'
---

You are reviewing IAM resource definitions for overly broad
permissions: wildcards, AWS-managed admin policies, and trust
policies that allow cross-account access without conditions.

This agent overlaps with `tf-iam-wildcard` but covers IAM expressed
in any source format (Terraform, CloudFormation, SAM, Kubernetes
manifests with GCP/Azure annotations, raw JSON policies).

## What to look for

**Wildcards in Action / Resource:**
```json
{ "Effect": "Allow", "Action": "*", "Resource": "*" }
{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }
```

**AWS-managed admin / power-user policies:**
- `arn:aws:iam::aws:policy/AdministratorAccess`
- `arn:aws:iam::aws:policy/PowerUserAccess`
- `arn:aws:iam::aws:policy/IAMFullAccess`

**Cross-account trust without conditions:**
```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::222233334444:root" },
  "Action": "sts:AssumeRole"
}
```

**`Principal: "*"` on a resource policy:**
```json
{ "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject" }
```
Public access — sometimes intentional, but should be explicit.

**GCP IAM bindings with `allUsers` or `allAuthenticatedUsers`:**
```hcl
google_project_iam_member.public {
  member = "allUsers"
  role   = "roles/storage.admin"
}
```

**Azure RBAC with subscription-wide `Owner` / `Contributor` on
service principals.**

## Required checks

For service principals / roles:
- Granted only the actions needed (least privilege).
- Resource ARNs are scoped to specific resources, not `*`.
- Trust relationships include `Condition` with `sts:ExternalId` for
  cross-account, or `aws:SourceArn` for AWS service principals.

## True positive criteria

Flag when ANY of the following hold:

1. An IAM policy statement has `Action: "*"` or `Resource: "*"`
   (with `Effect: Allow`).
2. A role is attached to `AdministratorAccess`, `PowerUserAccess`,
   or `IAMFullAccess`.
3. A trust policy permits `Principal: { "AWS": "<other-account>" }`
   or `Principal: "*"` without a `Condition` block.
4. A GCP IAM binding grants any role to `allUsers` /
   `allAuthenticatedUsers`.
5. An IAM resource policy on S3 / Lambda / SNS / SQS allows
   `Principal: "*"`.

## What to ignore

- Genuinely admin roles documented as such.
- AWS SCPs that DENY broadly (Deny is protective).
- Bucket policies on intentionally public CDN buckets (with
  documented review).

## Examples

True positives:
```hcl
resource "aws_iam_role_policy_attachment" "lambda" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_permission" "public" {
  principal = "*"
  action    = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn.arn
}
```

False positives to skip:
```hcl
resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda_logs.arn   # custom, scoped
}
```
