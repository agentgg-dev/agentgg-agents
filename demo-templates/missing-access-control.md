---
slug: missing-access-control
name: Missing Access Control
description: Authenticated endpoints that read or modify a resource without verifying the requester owns it — IDOR / horizontal privilege escalation.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  prompt: |
    Run only if this project exposes authenticated HTTP endpoints (a web
    API, backend service, or server-rendered app with sessions) that read
    or mutate per-user or per-tenant resources. Skip pure CLIs, static
    sites, and libraries with no request handlers.
where:
  extensions: [ts, tsx, js, jsx, mjs, cjs, py, rb, go, php, java, kt, cs]
  excludePatterns:
    - "**/*.{test,spec}.*"
    - "**/__tests__/**"
  preFilter:
    - regex: "\\.(get|post|put|patch|delete|all)\\s*\\(\\s*['\"]"
      label: "HTTP route handler (Express / Fastify / router)"
    - regex: "@(Get|Post|Put|Patch|Delete|Controller|RequestMapping|GetMapping|PostMapping)\\s*\\("
      label: "controller route decorator / annotation"
    - regex: "Route::(get|post|put|patch|delete|resource|apiResource)\\s*\\("
      label: "Laravel route definition"
    - regex: "@(app|router|blueprint)\\.(route|get|post|put|patch|delete)\\s*\\(|def \\w+\\s*\\([^)]*request"
      label: "Python view (Flask / Django / FastAPI)"
references:
  - CWE-862
  - CWE-639
  - OWASP-A01:2021
---

You are reviewing route handlers for missing access-control checks —
endpoints that act on a resource identified by the request without
verifying the caller is allowed to act on THAT resource.

You are seeded with the files that define route handlers / controllers
(the scanner anchored the handler definitions). For each handler that
loads or mutates a resource by an id from the request, use Read/Grep to
follow what it does and confirm whether an ownership/authorization check
runs before the data access.

## Method

1. For each flagged handler that takes a resource identifier (`id`,
   `slug`, `uuid`) from the path, query, or body, read the handler body.
2. Trace the data access: does an ownership/authorization check run
   first — middleware, a policy/guard call, or a query scoped to the
   caller (`where: { userId: session.userId }`)? Read the middleware,
   policy, or model files via tools to confirm.
3. A finding requires: authentication is present (there's a session /
   user), but the specific resource is fetched or mutated without
   confirming it belongs to that user / tenant.

## Ignore

- Handlers that scope the query to the caller (`userId` in the WHERE
  clause, an ownership policy/guard).
- Genuinely public / global resources by design.
- Admin-only routes already gated by a role check that covers the action.

Report the handler, the resource access, and the exact missing check. If
a handler looked suspicious but is actually scoped safely, say so — don't
pad with low-confidence findings.
