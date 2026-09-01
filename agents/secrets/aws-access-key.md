---
slug: aws-access-key
name: AWS Access Key ID Exposure
description: 'Hardcoded AWS IAM access key IDs (AKIA*, AGPA*, AROA*, AIPA*, ANPA*, ANVA*, ASIA*) in source code or config files. Combined with a nearby secret key the credential grants direct AWS API access.'
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
    - regex: '\b(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'
      label: AWS IAM access key ID prefix
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded AWS IAM access key IDs. An access key ID alone is not directly exploitable, but a nearby secret access key makes the pair immediately usable for AWS API calls.

## Key format

AWS access key IDs are always 20 characters: a 4-character prefix + 16 uppercase alphanumeric characters.

Prefixes and what they represent:
- `AKIA` — Long-term IAM user credential. Never expires unless manually rotated. Most dangerous.
- `ASIA` — Temporary STS credential. Shorter-lived but still dangerous while active.
- `AGPA`, `AROA`, `AIPA`, `ANPA`, `ANVA` — IAM group, role, instance profile, managed policy, virtual MFA. Context-dependent risk.

## Cross-file analysis

When you spot a key ID, look nearby (same file, `.env` sibling, adjacent config) for:
1. The secret access key: 40-character base64-like string under `AWS_SECRET_ACCESS_KEY`, `secret_key`, `aws_secret`, `secretAccessKey`
2. AWS region (`us-east-1`, etc.) and the services being called — determines blast radius

## True positive criteria

Flag when ALL hold:
1. The value matches the pattern and is 20 characters — not a comment, not a variable name
2. It is a string literal embedded in code or a config value — not a reference like `process.env.AWS_ACCESS_KEY_ID` or `${AWS_ACCESS_KEY_ID}`
3. It is not a documented placeholder: `AKIAIOSFODNN7EXAMPLE`, `AKIAXXXXXXXXXXXXXXXX`, `YOUR_ACCESS_KEY`, all-same-character runs, obviously fake values

If a matching secret access key appears nearby, note it — the pair is immediately exploitable.

## What to ignore

- Environment variable references: `process.env.AWS_ACCESS_KEY_ID`, `os.environ['AWS_ACCESS_KEY_ID']`, `$AWS_ACCESS_KEY_ID`
- The official AWS documentation example key `AKIAIOSFODNN7EXAMPLE`
- Redacted values: `AKIA***`, `AKIA[REDACTED]`
- Values clearly generated for unit tests with mock AWS SDK libraries
- Code comments describing the format without embedding a real value

## Examples

True positives:
```yaml
AWS_ACCESS_KEY_ID: AKIA<16-char-key>
AWS_SECRET_ACCESS_KEY: <aws-secret-access-key>
```
```ts
const s3 = new AWS.S3({
  accessKeyId: 'AKIA<16-char-key>',
  secretAccessKey: '<aws-secret-access-key>',
});
```

False positives to skip:
```ts
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});
```
```yaml
# Example only
# aws_access_key_id: AKIAIOSFODNN7EXAMPLE
```

Assess severity by: (1) whether the secret key is also present, (2) IAM permissions discernible from the code's AWS API calls, (3) production vs. test context.
