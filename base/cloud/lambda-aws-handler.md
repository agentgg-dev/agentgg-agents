---
slug: lambda-aws-handler
name: AWS Lambda Handler Security
description: AWS Lambda handler code review — function URL auth, input validation, secrets in env vars, execution role least privilege, response body content type. Walker mode correlates handler with SAM/CDK/Terraform deploy config and IAM role.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/lambda/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,rs}"
  - "**/handler*.{ts,tsx,js,jsx,mjs,cjs,py,go,rs}"
  - "**/lambdas/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,rs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs,py,go,rs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
preFilter:
  - regex: "export\\s+const\\s+handler\\s*=|exports\\.handler\\s*="
    label: "Lambda handler export"
  - regex: "APIGatewayProxyEvent|LambdaFunctionURLEvent|APIGatewayEvent"
    label: "Lambda event type annotation"
  - regex: "def\\s+(handler|lambda_handler)\\s*\\("
    label: "Python Lambda handler"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-285
  - OWASP-A05:2021
---

You are reviewing AWS Lambda handler implementations for the standard
set of security issues specific to Lambda.

**Walker mode advantage:** the handler's auth posture depends on its
deployment context (Function URL `AuthType`, API Gateway authorizer,
IAM role). Look for sibling files: `template.yaml`, `serverless.yml`,
`*.tf`, CDK constructs. Open them and verify the auth setup. Also
trace secret access: `process.env.X` may be backed by Secrets Manager
in deploy config (good) or just an env-var literal (less good).

## What to look for

**Function URL with `AuthType: NONE` and sensitive operation:**
Lambda function URLs can be configured with `AWS_IAM` or `NONE`. If
the deployment uses `NONE` and the handler performs sensitive
operations without checking a custom auth header, the function is
publicly invokable.

**Missing input validation in the handler:**
```ts
export const handler = async (event: APIGatewayProxyEvent) => {
  const userId = event.queryStringParameters?.userId;
  const user = await getUserById(userId);
  return { statusCode: 200, body: JSON.stringify(user) };
};
```
No auth check, no input validation, returns arbitrary user data.

**Secrets read from env vars:**
Lambda env vars are encrypted at rest and decrypted at runtime, but
visible to anyone who can `lambda:GetFunctionConfiguration`. Prefer
AWS Secrets Manager / Parameter Store.

**Overly broad execution role:**
Look for `IAMFullAccess`, `AdministratorAccess`, or `*` actions on
the role assumed by the Lambda. Lambda should have only the
permissions needed for its job.

**Response body content type & headers:**
```ts
return {
  statusCode: 200,
  body: html,
  headers: { "Content-Type": "text/html" },
};
```
If `html` is from user input, this is XSS. Default to JSON unless
HTML is explicitly intentional.

**`event.body` deserialization without validation:**
```ts
const body = JSON.parse(event.body);   // any shape accepted
await db.user.update({ where: { id }, data: body });
```

**API Gateway proxy event with path-param without validation:**
```ts
const id = event.pathParameters.id;
await db.user.delete({ where: { id } });   // no auth, no validation
```

## True positive criteria

Flag when reviewing a Lambda handler if:
1. The handler returns data based on `event.queryStringParameters`,
   `event.pathParameters`, or `event.body` without an auth check
   appropriate to the function's deployment context.
2. The handler reads secrets directly from `process.env` (vs.
   Secrets Manager).
3. JSON.parse on `event.body` with no schema validation, then write
   to DB.
4. HTML returned with user content interpolated.

## What to ignore

- Lambda handlers behind API Gateway with `AWS_IAM` /
  `COGNITO_USER_POOLS` / custom authorizers properly configured.
- Handlers that validate input with Zod / Joi / Yup before use.
- Handlers in test directories.

## Examples

True positives:
```ts
// Function URL with AuthType NONE, no in-handler auth
export const handler = async (event: any) => {
  const userId = event.queryStringParameters.userId;
  const user = await db.users.findUnique({ where: { id: userId } });
  return { statusCode: 200, body: JSON.stringify(user) };
};

// JSON.parse without validation
export const handler = async (event: APIGatewayProxyEvent) => {
  const body = JSON.parse(event.body ?? "{}");
  await db.users.update({ where: { id: body.id }, data: body });
  return { statusCode: 204, body: "" };
};
```

False positives to skip:
```ts
// Authorizer-protected, validated input
export const handler = async (event: APIGatewayProxyEvent) => {
  const claims = event.requestContext.authorizer.claims;
  const input = updateUserSchema.parse(JSON.parse(event.body ?? "{}"));
  if (input.id !== claims.sub) {
    return { statusCode: 403, body: "forbidden" };
  }
  await db.users.update({ where: { id: input.id }, data: input });
  return { statusCode: 204, body: "" };
};
```
