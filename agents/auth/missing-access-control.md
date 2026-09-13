---
slug: missing-access-control
name: Missing Access Control
description: 'Authenticated endpoints that read or modify a resource without verifying the requester owns it (IDOR, horizontal privilege escalation). Anchors on resource-id path parameters and on request handlers declared by file position (Next.js App Router, Remix) or registered on a router.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: "['\"][^'\"]*/[^'\"]*[:{<]\\s*(id|pk|[A-Za-z]+Id|[A-Za-z]+[_-](id|pk))\\b"
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/spec/**'
          - '**/*.{test,spec}.*'
          - '**/*_test.{py,go}'
          - '**/test_*.py'
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
          - '**/build/**'
          - '**/target/**'
          - '**/*.min.js'
        label: Route with a resource-id path parameter
      - regex: "@(PathVariable|PathParam)\\b"
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/test/**'
          - '**/tests/**'
          - '**/target/**'
        label: Spring / JAX-RS path-parameter binding
      - regex: "export\\s+(async\\s+)?function\\s+(GET|POST|PUT|PATCH|DELETE)\\b"
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.{test,spec}.*'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/build/**'
        label: Handler declared by file position (Next.js App Router, Remix), where the id is in the directory name
where:
  extensions: [ts, tsx, js, jsx, mjs, cjs, py, rb, go, php, java, kt, cs]
  excludePatterns:
    - "**/*.{test,spec}.*"
    - "**/__tests__/**"
    - "**/test/**"
    - "**/tests/**"
    - "**/spec/**"
    - "**/*_test.{py,go}"
    - "**/test_*.py"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/target/**"
    - "**/*.min.js"
  preFilter:
    - { regex: "['\"][^'\"]*/[^'\"]*[:{<]\\s*(id|pk|[A-Za-z]+Id|[A-Za-z]+[_-](id|pk))\\b", label: "Route path with a resource-id path parameter (IDOR-shaped)" }
    - { regex: "@(PathVariable|PathParam)\\b", label: "Spring / JAX-RS path-parameter binding" }
    - { semgrepRule: "shared/http-endpoints", label: "HTTP request handler (route declared by file position, not by a path string)" }
references:
  - CWE-862
  - CWE-639
  - 'OWASP-A01:2021'
---

You are hunting for missing access-control checks across this
repository.

**Scope of this check.** Anchor on handlers whose route declares a
resource-id path parameter (`/users/:id`, `{id}`, `<int:pk>`, a
Spring/JAX-RS `@PathVariable`), and on any handler the scanner anchored
as a request entry point, including one whose id sits in the directory
name rather than in a path string. The id also arrives in the request
body, in the query string, through a namespace-scoped route and through
a resource-style route table. Treat all of those the same way. Within a
candidate file, follow imports and middleware to confirm scoping.

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
