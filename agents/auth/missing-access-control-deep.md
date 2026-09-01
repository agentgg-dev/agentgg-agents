---
slug: missing-access-control-deep
name: Missing Access Control (Deep)
description: 'Broad-net pass for missing access control: reads every authenticated route handler and traces ownership/scoping across middleware and services. High coverage, high file count. The fast, strict variant is `missing-access-control` in base.'
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
    - semgrepRule: shared/http-endpoints
      label: HTTP endpoint handler or route registration
    - { regex: "\\.(get|post|put|patch|delete|all)\\s*\\(\\s*['\"]", label: "HTTP route handler (Express / Fastify / router)" }
    - { regex: "@(Get|Post|Put|Patch|Delete|Controller|RequestMapping|GetMapping|PostMapping)\\s*\\(", label: "controller route decorator / annotation" }
    - { regex: "Route::(get|post|put|patch|delete|resource|apiResource)\\s*\\(", label: "Laravel route definition" }
    - { regex: "@(app|router|blueprint)\\.(route|get|post|put|patch|delete)\\s*\\(|def \\w+\\s*\\([^)]*request", label: "Python view (Flask / Django / FastAPI)" }
references:
  - CWE-862
  - CWE-639
  - 'OWASP-A01:2021'
---

You are hunting for missing access-control checks across this
repository.

## What this bug looks like

An authenticated endpoint takes a resource identifier from the request
(URL param like `/api/users/:id` or `/api/orgs/:orgId/...`, body
field, query string) and reads or modifies that resource WITHOUT
verifying the authenticated user is allowed to access THAT specific
resource.

Concretely:

- The handler authenticates ("is the request signed in?") but does
  NOT authorize ("does this user own / have access to this resource?").
- The query scopes by the URL/body parameter alone, not by
  `session.user.id` / `req.user.id` / equivalent.
- An attacker with any valid session can rewrite the id and read or
  modify resources belonging to other users.

## What is NOT this bug (skip these)

- **Public read endpoints** — a blog post fetched by ID is intentionally
  readable by anyone.
- **Admin-only routes** wrapped in an explicit admin check like
  `auth.has("admin", ...)` or `requireRole("admin")`.
- **Routes that scope by an owned namespace** — e.g.
  `/api/orgs/:orgId/posts` where the handler enforces the user
  belongs to `orgId` via middleware. Trace the middleware before
  reporting.
- **Self-only routes** that scope by the session user (`SELECT * FROM
  notes WHERE user_id = ?` with `user_id` from session, not the URL).

## Strategy

1. **Find every route handler.** Grep for route registrations:
   `app.(get|post|put|delete|patch)`,
   `router.(get|post|put|delete|patch)`,
   Express/Fastify/Koa/Hono shapes; `@Get`/`@Post`/`@Controller`
   decorators for Nest, etc.

2. **For each handler that takes a resource id parameter**, Read the
   handler body and trace what query/mutation runs.

3. **Verify the scoping.** Does the query/mutation filter by something
   the user owns? Or does it trust the id from the URL?

4. **Follow imports.** If the handler delegates to a service or helper,
   Read that to verify scoping happens there. Likewise, check
   middleware applied to the route — auth.guard, requireAuth, etc.
   Don't false-positive on indirect scoping you didn't trace.

## Boundaries

- This is about *missing* checks, not weak ones. An over-permissive
  RBAC role is a different bug class — out of scope here.
- Race conditions in access checks (TOCTOU) are out of scope here.
- Mass-assignment that bypasses field-level access control is a
  different bug class — out of scope.

## Output

For each real finding, report the file and line range where the
unsafe handler lives. Be precise — point to the exact route, not the
file in general. Include the query/mutation that lacks scoping in the
`details` section, and a concrete HTTP request that exploits it in
the `poc` section.

If you found nothing real, return an empty findings array — don't
fabricate to fill space.
