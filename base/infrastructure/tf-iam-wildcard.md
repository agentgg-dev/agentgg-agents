---
slug: tf-iam-wildcard
name: Terraform IAM Policy with Wildcard Action or Resource
description: "Terraform aws_iam_policy / aws_iam_role_policy with Action: \"*\" or Resource: \"*\" — overly broad permissions that turn the principal into an admin."
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.tf"
  - "**/*.tf.json"
  - "**/*.tfvars"
references:
  - CWE-732
  - OWASP-A01:2021
---

You are reviewing Terraform configuration for IAM policies that use
wildcards (`*`) for Actions or Resources, granting overly broad
permissions.

## What to look for

**`Action: "*"` (any action):**
```hcl
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }]
  })
}
```
This is an "administrator" policy. Almost always wrong unless this
is genuinely the admin role.

**`Resource: "*"` (every resource of the action):**
```hcl
Statement = [{
  Effect = "Allow"
  Action = "s3:*"
  Resource = "*"
}]
```
Grants `s3:*` on every bucket in the account — including future
buckets.

**Service-wildcard actions on specific resources (slightly better
but still broad):**
```hcl
Action = "s3:*"
Resource = "arn:aws:s3:::my-bucket"
```
Often okay for the bucket-owning role; flag for review.

**`NotAction` / `NotResource` (inversion traps):**
```hcl
NotAction = "iam:DeleteRole"
Resource = "*"
```
This grants every action *except* `iam:DeleteRole` on every
resource — a near-admin. `NotAction` is almost always a mistake.

## Safe pattern

Specific actions on specific resources:
```hcl
Statement = [{
  Effect = "Allow"
  Action = [
    "s3:GetObject",
    "s3:PutObject",
  ]
  Resource = [
    "arn:aws:s3:::my-bucket/*",
  ]
}]
```

## True positive criteria

Flag when ANY of the following hold:

1. `Action: "*"` or `Action: ["*"]` appears in an IAM policy
   statement.
2. `Resource: "*"` AND the Action is a service wildcard (`s3:*`,
   `ec2:*`, etc.) or `"*"`.
3. `NotAction` or `NotResource` is used.
4. An inline `aws_iam_role_policy`, `aws_iam_user_policy`, or
   `aws_iam_policy` document grants admin-equivalent permissions.

## What to ignore

- Policies for genuinely administrative roles (`role/Admin`, root,
  break-glass) where wildcards are intentional and documented.
- Service-control policies (SCPs) that deny actions broadly — Deny
  wildcards are protective.
- Policies that scope `*` actions to a single resource ARN in a
  controlled way that matches the role's purpose.

## Examples

True positives:
```hcl
resource "aws_iam_policy" "lambda" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
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
```

False positives to skip:
```hcl
resource "aws_iam_role_policy" "read_logs" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/my-fn:*"
    }]
  })
}
```
