---
slug: unverified-lookup
name: Unverified ID Lookup (IDOR)
description: DB lookup by ID (getProjectById, findById, findUnique by id) where the result is returned to the caller without verifying ownership — classic Insecure Direct Object Reference. Walker mode follows repo helpers to verify scoping.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/services/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/apps/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/app/api/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/pages/api/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/routes/**/*.{ts,tsx,js,jsx,mjs}"
  - "**/src/**/*.{ts,tsx,js,jsx,mjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "(get|find|fetch)[A-Z][a-zA-Z]+By(Id|Uid|Slug)\\s*\\("
    label: "getXById / findXBySlug helper call"
  - regex: "\\.(findUnique|findFirst|findOne)\\s*\\(\\s*\\{\\s*where\\s*:\\s*\\{\\s*id\\s*:"
    label: "ORM findUnique/findFirst with where: { id }"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-639
  - CWE-862
  - OWASP-A01:2021
---

You are reviewing source code for Insecure Direct Object Reference
(IDOR) — endpoints that fetch a record by ID and return it without
checking whether the authenticated user owns or has access to that
record.

**Walker mode advantage:** the ownership check may live in the helper
itself. Open `getProjectById` — does it accept the session user and
scope the query, or does it just look up by id? Some repos have two
flavors (`getProjectById` raw vs. `getProjectForUser` scoped); the
finding depends on which the candidate calls.

This agent overlaps with `cross-tenant-id` but focuses on the
record-level pattern (project, deployment, document, file, ticket,
etc.), not just multi-tenant.

## What to look for

**Lookup-by-ID followed by return-to-caller, no ownership check:**
```ts
const project = await getProjectById(projectId);
return Response.json(project);

const deployment = await getDeploymentById(id);
return Response.json(deployment);

const data = await db.project.findUnique({ where: { id } });
return Response.json(data);
```

**ID coming from request input:**
The `id`, `projectId`, `deploymentId`, etc. is from `req.params`,
`req.body`, `req.query`, or a parsed equivalent.

**Common helper names:**
`getProjectById`, `getDeploymentById`, `getInstallationById`,
`getUserById`, `getTeamById`, `findById`, `findOneById`, `findByUid`,
`findFirst({ where: { id } })`, `findUnique({ where: { id } })`.

## Required check

Before returning the record, the code must verify the authenticated
user is allowed to access it:
```ts
const project = await getProjectById(projectId);
if (project.ownerId !== session.userId) {
  return new Response("forbidden", { status: 403 });
}
return Response.json(project);
```
Better: scope the query so it returns null for non-owners:
```ts
const project = await db.project.findFirst({
  where: { id: projectId, ownerId: session.userId },
});
if (!project) return new Response("not found", { status: 404 });
```

## True positive criteria

Flag when ALL of the following hold:

1. A lookup function with `*ById` / `*ByUid` / `findUnique` /
   `findFirst({ where: { id } })` shape is called.
2. The ID argument originates from request input.
3. The result is returned to the caller (or used in a subsequent
   mutation reachable by the response) without an ownership check
   on the same code path.

## What to ignore

- Lookup followed by an explicit ownership check before returning:
  `if (record.userId !== session.userId) throw forbidden()`.
- Queries that scope by both the ID and the session user:
  `findFirst({ where: { id, ownerId: session.userId } })`.
- Lookup of a record that is intentionally public: blog posts,
  marketplace listings, published content.
- Test files.

## Examples

True positives:
```ts
// project returned without ownership check
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const project = await getProjectById(params.id);
  return Response.json(project);
}

// deployment fetched, then used in a mutation
const deployment = await getDeploymentById(req.body.deploymentId);
await deleteDeployment(deployment);   // no check on deployment.ownerId
```

False positives to skip:
```ts
// Ownership check
const project = await getProjectById(params.id);
if (project.userId !== session.userId) {
  return new Response("forbidden", { status: 403 });
}
return Response.json(project);

// Scoped query
const project = await db.project.findFirst({
  where: { id: params.id, ownerId: session.userId },
});
if (!project) return new Response(null, { status: 404 });

// Public record by design
const post = await getPublishedPostBySlug(params.slug);
return Response.json(post);
```
