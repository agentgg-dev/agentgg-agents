---
slug: iam-permissions
name: Cloud IAM Permissions Review
description: 'IAM role / policy / service-account assignments with overly broad actions, wildcard resources, NotAction / NotResource inversions, AWS-managed broad policies, or cross-account trust without conditions. Covers Terraform, CloudFormation, and raw JSON policy documents.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - tf
      - tf.json
      - tfvars
      - yaml
      - yml
      - json
where:
  extensions:
    - tf
    - tf.json
    - tfvars
    - yaml
    - yml
    - json
  preFilter:
    - semgrepRule: cloud/iam-wildcard
      label: IAM wildcard Action/Resource or admin policy attachment
    - regex: resource\s+"aws_iam_(policy|role_policy|user_policy|group_policy)"
      label: Terraform inline IAM policy document
    - regex: (Action|Resource)\s*=\s*\[?\s*"[a-z0-9-]*:?\*"
      label: HCL IAM policy with wildcard Action or Resource
    - regex: \bNot(Action|Resource)\b
      label: IAM policy inversion via NotAction / NotResource
references:
  - CWE-732
  - 'OWASP-A01:2021'
---

You are reviewing IAM resource definitions for overly broad
permissions: wildcards, AWS-managed admin policies, and trust
policies that allow cross-account access without conditions.

Cover IAM expressed in any source format: Terraform (`.tf`,
`.tf.json`, `.tfvars`), CloudFormation, SAM, Kubernetes manifests
with GCP/Azure annotations, and raw JSON policies. In Terraform the
policy body is usually a `jsonencode({...})` block inside
`aws_iam_policy`, `aws_iam_role_policy`, or `aws_iam_user_policy`, so
read inside the encoded document rather than stopping at the resource
attributes.

## What to look for

**Wildcards in Action / Resource:**
```json
{ "Effect": "Allow", "Action": "*", "Resource": "*" }
{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }
```

**Terraform inline policy documents:**
```hcl
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
```
`Resource = "*"` with a service wildcard such as `Action = "s3:*"`
grants that service on every resource in the account, including
resources created later. A service wildcard scoped to one ARN is
narrower but still worth review.

**`NotAction` / `NotResource` inversion:**
```hcl
Statement = [{
  Effect    = "Allow"
  NotAction = "iam:DeleteRole"
  Resource  = "*"
}]
```
An inverted statement grants everything except what it names, so this
is admin minus one call. The trap also runs the other way: a `Deny`
statement written with `NotAction` or `NotResource` denies everything
outside the named set, which usually means the author intended to
restrict a few actions and instead restricted all the others while
leaving the named ones wide open. Read the `Effect` before judging
which way the inversion falls, and flag either shape.

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
6. `NotAction` or `NotResource` appears in a policy statement.
7. An inline `aws_iam_policy`, `aws_iam_role_policy`, or
   `aws_iam_user_policy` document grants admin-equivalent
   permissions.

## What to ignore

- Genuinely admin roles documented as such.
- AWS SCPs that DENY broadly (Deny is protective).
- Bucket policies on intentionally public CDN buckets (with
  documented review).
- Break-glass roles (`role/Admin`, root) where the wildcard is
  intentional and documented in the file.
- Policies that scope a wildcard action to a single resource ARN
  matching the role's stated purpose.

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

resource "aws_iam_role_policy" "ec2" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy" "ci" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      NotAction = "iam:DeleteRole"
      Resource  = "*"
    }]
  })
}
```

False positives to skip:
```hcl
resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda_logs.arn   # custom, scoped
}

resource "aws_iam_role_policy" "read_logs" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/my-fn:*"
    }]
  })
}
```
