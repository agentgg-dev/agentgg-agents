---
slug: gcp-cloud-function
name: GCP Cloud Function Security
description: 'GCP Cloud Functions (1st and 2nd gen) — unauthenticated invocation, missing trigger validation, IAM bindings for allUsers, secrets in env vars. Correlates handler with Terraform IAM bindings.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: (google_cloudfunctions(2)?_function_iam_member|google_cloud_run_service_iam_member)
        in:
          - '**/functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/cloud-functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/*.tf'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: GCP function/run IAM binding resource
      - regex: 'member\s*=\s*["'']allUsers["'']'
        in:
          - '**/functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/cloud-functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/*.tf'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: IAM binding to allUsers
      - regex: HttpFunction|@google-cloud/functions-framework
        in:
          - '**/functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/cloud-functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/*.tf'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: GCP HTTP function handler
      - regex: functions_framework\.http|functions_framework\.cloud_event
        in:
          - '**/functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/cloud-functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
          - '**/*.tf'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Python functions-framework decorator
  prompt: Run only if this project uses gcp-cloud-functions — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - tf
  filePatterns:
    - '**/functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
    - '**/cloud-functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java}'
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,py,go}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
  preFilter:
    - regex: (google_cloudfunctions(2)?_function_iam_member|google_cloud_run_service_iam_member)
      label: GCP function/run IAM binding resource
    - regex: 'member\s*=\s*["'']allUsers["'']'
      label: IAM binding to allUsers
    - regex: HttpFunction|@google-cloud/functions-framework
      label: GCP HTTP function handler
    - regex: functions_framework\.http|functions_framework\.cloud_event
      label: Python functions-framework decorator
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-285
  - 'OWASP-A05:2021'
---

You are reviewing Google Cloud Function implementations and their
deployment configuration for the standard set of security issues.

**Cross-file analysis:** the function's auth posture spans code
(handler) and infrastructure (Terraform IAM bindings, ingress
settings). When you see an unauthenticated-looking handler, search
sibling `.tf` files for the function's IAM bindings — `allUsers` is
the critical signal. Conversely, a handler that does its own auth
check may have been deployed with `allUsers`, which is still flag-
worthy if the in-handler auth is fragile.

## What to look for

**Function deployed with `allUsers` IAM binding:**
```hcl
resource "google_cloudfunctions_function_iam_member" "public" {
  member = "allUsers"
  role   = "roles/cloudfunctions.invoker"
}

resource "google_cloud_run_service_iam_member" "public" {
  member = "allUsers"
}
```
This makes the function publicly invokable. Almost always wrong
unless it's a webhook or a documented public API.

**HTTP function handler with no auth check:**
```ts
import type { HttpFunction } from "@google-cloud/functions-framework";

export const handler: HttpFunction = async (req, res) => {
  const user = await db.users.findUnique({ where: { id: req.query.userId } });
  res.json(user);
};
```
No auth, no input validation.

**Pub/Sub-triggered function without validating message source:**
A function triggered by Pub/Sub receives messages from whichever
topic it subscribes to. If the topic accepts publishes from
unverified sources, the message body can be hostile.

**Storage-triggered function processing untrusted objects:**
GCS event triggers fire on every object write. If the bucket
accepts uploads from untrusted users (signed URLs to anyone, or a
public bucket), the function handles attacker-controlled content.

**Secrets in env vars (not Secret Manager):**
Cloud Function env vars are visible to anyone with
`cloudfunctions.functions.get`. Prefer Secret Manager.

## True positive criteria

Flag when:
1. IAM bindings grant `roles/cloudfunctions.invoker` or
   `roles/run.invoker` to `allUsers` / `allAuthenticatedUsers`.
2. An HTTP function handler returns data or performs writes without
   authenticating the caller.
3. Pub/Sub / Storage triggers process untrusted input without
   validation.
4. Secrets are read from `process.env.*` or `os.environ` for
   sensitive values rather than Secret Manager.

## What to ignore

- Functions explicitly intended as public webhooks with their own
  signature verification (Stripe, GitHub).
- Functions behind Cloud Run with `INGRESS_INTERNAL_ONLY` or
  `INGRESS_INTERNAL_AND_CLOUD_LOAD_BALANCING`.
- Test files.

## Examples

True positives:
```ts
// Public HTTP function with no auth
export const handler: HttpFunction = async (req, res) => {
  await db.users.delete({ where: { id: req.body.id } });
  res.send("ok");
};
```

```hcl
resource "google_cloudfunctions_function_iam_member" "invoke" {
  member = "allUsers"
  role   = "roles/cloudfunctions.invoker"
}
```

False positives to skip:
```ts
export const handler: HttpFunction = async (req, res) => {
  const token = req.get("Authorization")?.replace("Bearer ", "");
  const user = await verifyToken(token);
  if (!user) return res.status(401).send("unauthorized");
  // ...
};
```
