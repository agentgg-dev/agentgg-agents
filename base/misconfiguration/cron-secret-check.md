---
slug: cron-secret-check
name: Cron / Scheduler Endpoint Missing Secret Check
description: Cron route handlers (Vercel Cron, custom scheduler endpoints) that lack a CRON_SECRET / scheduler-signature check — anyone on the internet can trigger the job. Walker mode follows verifier helpers and scheduler library wrappers.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/cron/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/crons/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/api/cron*/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/app/api/**/route.{ts,tsx,js,mjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "export\\s+(async\\s+function|const)\\s+(GET|POST)\\b"
    label: "HTTP handler in cron-shaped path"
  - regex: "CRON_SECRET|x-cron-secret"
    label: "CRON secret reference"
  - regex: "inngest\\.serve\\s*\\(|trigger\\.dev|serve\\s*\\(\\s*\\{\\s*client"
    label: "Scheduler library serve() wrapper"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-306
  - OWASP-A01:2021
---

You are reviewing cron / scheduled-job endpoints (Vercel Cron, custom
schedulers, Inngest) that should only be triggered by the scheduler
service — never by external callers. Without a secret check or
signature verification, any unauthenticated request triggers the job
(potentially repeatedly, multiplying load and side effects).

**Walker mode advantage:** the secret check may live in a shared
`verifyCron()` helper or middleware. When the candidate handler is
bare, look for an HOF wrapper or imported guard. For scheduler-
library exports (`inngest.serve(...)`), confirm the library actually
performs auth — read the library version/config if uncertain.

## What to look for

**Cron route with no secret verification:**
```ts
// app/api/cron/cleanup/route.ts
export async function GET() {
  await cleanupOldRecords();
  return new Response("ok");
}
```
Anyone hitting `/api/cron/cleanup` runs the job.

**Vercel Cron pattern — CRON_SECRET expected:**
Vercel sets `Authorization: Bearer <CRON_SECRET>` on cron requests.
The route must verify it:
```ts
export async function GET(req: Request) {
  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response("unauthorized", { status: 401 });
  }
  return runJob();
}
```

**Custom `x-cron-secret` header (some setups):**
```ts
if (req.headers.get("x-cron-secret") !== process.env.CRON_SECRET) {
  return new Response("nope", { status: 401 });
}
```

**Inngest / Trigger.dev signed payloads:**
These libraries do signature verification internally — flag custom
handlers that don't go through the library.

## True positive criteria

Flag when ALL of the following hold:

1. The file path indicates a cron / scheduler endpoint (`/cron/`,
   `/crons/`, `/api/cron*`, named after a scheduled job).
2. The handler body and any wrapping HOF / middleware do not check
   a secret header against `process.env.CRON_SECRET` (or
   equivalent) before performing side effects.
3. The job is not invoked solely through a vetted scheduler library
   (Inngest, Trigger.dev, BullMQ) that handles auth.

## What to ignore

- Handlers that include a CRON_SECRET check.
- Cron files that are pure exports for a scheduler library
  (`export const { GET, POST } = inngest.serve({...})`).
- Test files.

## Examples

True positives:
```ts
// app/api/cron/digest/route.ts — no secret check
export async function GET() {
  await sendDailyDigest();
  return new Response("ok");
}

// Vercel cron path, no auth
// /api/cron/cleanup-stale-records/route.ts
export const POST = async () => {
  await db.records.deleteMany({ where: { staleAt: { lt: new Date() } } });
  return Response.json({ ok: true });
};
```

False positives to skip:
```ts
// CRON_SECRET checked
export async function GET(req: Request) {
  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response("unauthorized", { status: 401 });
  }
  await runJob();
  return new Response("ok");
}

// Inngest-served handler
export const { GET, POST, PUT } = inngest.serve({ client: inngest, functions: [...] });
```
