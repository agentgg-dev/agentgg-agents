---
slug: slack-signing-verification
name: Slack Webhook Handler Missing Signing Verification
description: 'Slack command/action/event/view/shortcut handlers (raw Next.js route handlers, not @slack/bolt receivers) without HMAC signing secret verification or replay protection. Walker mode follows verifier helpers across files.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'from\s+[''"]@slack/(bolt|web-api|events-api)[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Imports @slack/* SDK
      - regex: x-slack-(signature|request-timestamp)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Slack signature/timestamp header reference
      - regex: verifySlackSignature|verifyRequestSignature|createEventAdapter
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Slack-specific verifier call
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'from\s+[''"]@slack/(bolt|web-api|events-api)[''"]'
      label: Imports @slack/* SDK
    - regex: x-slack-(signature|request-timestamp)
      label: Slack signature/timestamp header reference
    - regex: verifySlackSignature|verifyRequestSignature|createEventAdapter
      label: Slack-specific verifier call
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-345
  - 'OWASP-A08:2021'
---

You are reviewing Slack integration endpoints for missing signing
verification. Slack signs every request to your handler with an HMAC
using the app's signing secret; without verifying, anyone can forge
requests to trigger slash commands, button actions, or workflow
modals.

**Walker mode advantage:** verification may live in a shared
`lib/slack.ts` (`verifySlackRequest`, `assertSlackSignature`) — open
it and verify it does HMAC SHA-256 on `v0:timestamp:body`, constant-
time-compares against the header, AND enforces the 5-minute timestamp
window for replay protection. A verifier that skips the timestamp
check is a partial finding.

## Slack signing requirements

Slack sends two headers:
- `X-Slack-Request-Timestamp` — Unix timestamp of the request
- `X-Slack-Signature` — `v0=<hex HMAC-SHA256>`

The verification is:
```
basestring = "v0:" + timestamp + ":" + raw_body
expected_signature = "v0=" + HMAC_SHA256(signing_secret, basestring)
expected_signature === X-Slack-Signature (constant-time compare)
```

Plus replay protection: reject if `|now - timestamp| > 300` seconds.

## What to look for

**`@slack/bolt` `App` used WITHOUT its receivers (raw Next.js route):**
```ts
import { App } from "@slack/bolt";
export async function POST(req: Request) {
  return new Response("ok");
}
```
If you create an `App` but expose handlers via Next.js route handlers
(`export async function POST`), Bolt's automatic verification doesn't
run — the route must verify manually.

**Slack handlers (`app.command`, `app.action`, `app.event`,
`app.view`, `app.shortcut`) inside a custom route:**
```ts
import { App } from "@slack/bolt";
const app = new App({ signingSecret: process.env.SLACK_SIGNING_SECRET });
app.command("/hello", async ({ ack }) => { await ack(); });
// If this is mounted via custom routing, verify the route layer signs
```

**Verification only AFTER side effects:**
```ts
export async function POST(req: Request) {
  await dispatchCommand(req);           // already ran
  if (!verifySlackSignature(req)) return new Response("401");   // too late
}
```

## True positive criteria

Flag when ALL of the following hold:

1. The file imports from `@slack/bolt`, `@slack/web-api`, or
   contains Slack-specific shapes (`payload`, `team_id`,
   `channel_id`, `command`, `interactivity` keys).
2. The file exports an HTTP handler (Next.js route, Express route).
3. No call to `verifySlackSignature`, `slack.verifyRequestSignature`,
   `createEventAdapter().requestVerification`, or equivalent appears
   before the handler's side effects.

## What to ignore

- Files that use `@slack/bolt`'s `ExpressReceiver`,
  `AwsLambdaReceiver`, or framework-provided receiver — these
  verify automatically.
- Test / fixture files.

## Examples

True positives:
```ts
// Raw Next.js handler, no verification
import { App } from "@slack/bolt";
export async function POST(req: Request) {
  const { command, user_id } = await req.json();
  return handleCommand(command, user_id);
}
```

False positives to skip:
```ts
// ExpressReceiver — Bolt verifies
import { App, ExpressReceiver } from "@slack/bolt";
const receiver = new ExpressReceiver({ signingSecret: process.env.SLACK_SIGNING_SECRET });
const app = new App({ token: process.env.SLACK_TOKEN, receiver });

// Manual verification before dispatch
export async function POST(req: Request) {
  const ok = await verifySlackSignature(req, process.env.SLACK_SIGNING_SECRET);
  if (!ok) return new Response("unauthorized", { status: 401 });
  return dispatchCommand(await req.json());
}
```
