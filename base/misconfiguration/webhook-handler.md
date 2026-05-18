---
slug: webhook-handler
name: Webhook Endpoint Missing Signature Verification
description: Inbound webhook handlers (Stripe, GitHub, Linear, Sentry, custom integrations) without HMAC / signature / shared-secret verification — anyone on the internet can forge events. Walker mode follows verifier helpers across files.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*webhook*/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/*hook*/**/route.{ts,js}"
  - "**/api/**/route.{ts,tsx,js,mjs}"
  - "**/services/**/src/**/*.ts"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "export\\s+(async\\s+function|const)\\s+POST\\b"
    label: "POST handler in webhook-shaped path"
  - regex: "stripe-signature|x-hub-signature|x-slack-signature|x-linear-signature|x-svix-signature|x-shopify-hmac"
    label: "Provider signature header reference"
  - regex: "(constructEvent|verifyAndReceive|verifyWebhook|verifySignature)\\s*\\("
    label: "Webhook verification helper call"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-345
  - CWE-306
  - OWASP-A08:2021
---

You are reviewing inbound webhook handlers for missing signature
verification. Webhooks are HTTP endpoints exposed to receive events
from third parties — Stripe, GitHub, Slack, Linear, Sentry, custom
integrations. Without a signature check, attackers can craft fake
events.

**Walker mode advantage:** verification is often centralized in a
helper (`verifyStripe`, `verifyGitHubWebhook`, `assertWebhookHMAC`).
When the handler calls such a helper, open it and confirm it
performs a `crypto.timingSafeEqual` (or equivalent) against a real
secret — not a stub. Also verify the helper actually throws on
mismatch rather than just returning false silently.

## What to look for

**Webhook route with no signature check:**
```ts
// app/api/webhooks/stripe/route.ts
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await fulfillOrder(event.data.object);
  }
  return new Response("ok");
}
```
No `stripe.webhooks.constructEvent(...)` call — any caller can post
fake events.

**Common provider verification calls (presence = good):**
- Stripe: `stripe.webhooks.constructEvent(rawBody, signature, secret)`
- GitHub: `verify(rawBody, signature, secret)` using `@octokit/webhooks`
- Slack: `verifySlackSignature` (see `slack-signing-verification`)
- Linear: `verifyLinearWebhook` / signature header
- Sentry: signature header verify
- Custom: HMAC-SHA256 comparison against `X-Webhook-Signature`

**Generic patterns to flag:**
- Handler reads `req.body` and acts on it without first comparing
  a header to an HMAC.
- Webhook secret stored but never used (`process.env.WEBHOOK_SECRET`
  exists but `crypto.timingSafeEqual` or `hmac` never appears).

## True positive criteria

Flag when ALL of the following hold:

1. The file path contains `webhook` or `hook`, OR the handler
   parses request bodies in a shape matching a known provider
   webhook (Stripe `type`/`data.object`, GitHub `repository`/`sender`).
2. No signature verification call appears before side effects.

## What to ignore

- Outbound webhook senders (this agent is for inbound).
- Tests / mocks.
- Files where verification is delegated to a library that handles
  it (`Inngest`, `Trigger.dev` `serve()` exports).
- Webhook handlers that immediately enqueue and rely on a downstream
  consumer to verify — flag for review but lower priority.

## Examples

True positives:
```ts
// Stripe webhook, no constructEvent
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "invoice.paid") await markPaid(event.data.object.customer);
  return new Response("ok");
}

// GitHub webhook, no signature check
export async function POST(req: Request) {
  const payload = await req.json();
  if (payload.action === "opened") await onIssueOpened(payload);
  return new Response("ok");
}
```

False positives to skip:
```ts
// Stripe verification
const sig = req.headers.get("stripe-signature");
const rawBody = await req.text();
const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);

// GitHub via @octokit/webhooks
import { Webhooks } from "@octokit/webhooks";
const webhooks = new Webhooks({ secret: process.env.GITHUB_WEBHOOK_SECRET });
await webhooks.verifyAndReceive({ id, name, signature, payload });
```
