---
slug: unverified-lookup
name: Unverified ID Lookup (IDOR)
description: 'DB lookup by ID (getProjectById, findById, findUnique by id) where the result is returned to the caller without verifying ownership — classic Insecure Direct Object Reference. Follows repo helpers to verify scoping. Also covers tenant, team and org IDs from the request used in a read or write without a membership check.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(get|find|fetch)[A-Z][a-zA-Z]+By(Id|Uid|Slug)\s*\('
        in:
          - '**/services/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/apps/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/src/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: getXById / findXBySlug helper call
      - regex: '\.(findUnique|findFirst|findOne)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:'
        in:
          - '**/services/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/apps/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/src/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'ORM findUnique/findFirst with where: { id }'
      - regex: '(update|delete)[A-Z][a-zA-Z]+By(Id|Uid|Slug)\s*\('
        in:
          - '**/services/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/apps/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/src/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: updateXById / deleteXById helper call
      - regex: '\.(update|delete)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:'
        in:
          - '**/services/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/apps/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/src/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'ORM update/delete with where: { id }'
      - regex: \b(teamId|ownerId|orgId|tenantId|installationId|configurationId|integrationConfigurationId|customerId|workspaceId|accountId)\b
        in:
          - '**/services/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/apps/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
          - '**/src/**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: tenant-shaped identifier
      - regex: \.objects\.(get|filter)\s*\(\s*(pk|id)\s*=
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Django by-id lookup
      - regex: \.filter_by\s*\(\s*id\s*=
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: SQLAlchemy filter_by(id=)
      - regex: def\s+(get|find|fetch|load)_\w+_by_(id|uid|slug)\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: get_x_by_id / find_x_by_slug helper
      - regex: \.query\s*\([^)]*\)\.get\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: SQLAlchemy query(...).get lookup
      - regex: \b(team_id|owner_id|org_id|tenant_id|installation_id|customer_id|workspace_id|account_id)\b
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: snake_case tenant-shaped identifier
      - regex: \.findById\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring Data findById
      - regex: \.(getOne|getReferenceById)\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: JPA getOne/getReferenceById
      - regex: entityManager\.find\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: EntityManager.find
      - regex: \.findBy[A-Z]\w*\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: derived findByX query
      - regex: \b(teamId|ownerId|orgId|tenantId|installationId|configurationId|integrationConfigurationId|customerId|workspaceId|accountId)\b
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Java/Kotlin tenant-shaped identifier
      - regex: '@RequestParam\s*(\([^)]*\))?\s*\w*\s+\w*[Ii]d\b'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: id bound from @RequestParam
where:
  filePatterns:
    - '**/services/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/apps/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/app/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/src/**/*.{ts,tsx,js,jsx,mjs}'
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/.venv/**'
    - '**/venv/**'
    - '**/site-packages/**'
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: '(get|find|fetch)[A-Z][a-zA-Z]+By(Id|Uid|Slug)\s*\('
      label: getXById / findXBySlug helper call
    - regex: '\.(findUnique|findFirst|findOne)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:'
      label: 'ORM findUnique/findFirst with where: { id }'
    - regex: '(update|delete)[A-Z][a-zA-Z]+By(Id|Uid|Slug)\s*\('
      label: updateXById / deleteXById helper call
    - regex: '\.(update|delete)\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:'
      label: 'ORM update/delete with where: { id }'
    - regex: \.objects\.(get|filter)\s*\(\s*(pk|id)\s*=
      label: Django by-id lookup
    - regex: \.filter_by\s*\(\s*id\s*=
      label: SQLAlchemy filter_by(id=)
    - regex: def\s+(get|find|fetch|load)_\w+_by_(id|uid|slug)\s*\(
      label: by-id lookup helper
    - regex: \.query\s*\([^)]*\)\.get\s*\(
      label: SQLAlchemy query(...).get lookup
    - regex: \.findById\s*\(
      label: findById
    - regex: \.(getOne|getReferenceById)\s*\(
      label: getOne/getReferenceById
    - regex: entityManager\.find\s*\(
      label: EntityManager.find
    - regex: \.findBy[A-Z]\w*\s*\(
      label: derived findByX query
    - regex: \b(teamId|ownerId|orgId|tenantId|installationId|configurationId|integrationConfigurationId|customerId|workspaceId|accountId)\b
      label: tenant-shaped identifier
    - regex: \b(team_id|owner_id|org_id|tenant_id|installation_id|customer_id|workspace_id|account_id)\b
      label: snake_case tenant-shaped identifier
    - regex: '@RequestParam'
      label: request-bound parameter
  maxFilesPerBatch: 5
  extensions:
    - java
    - kt
    - py
references:
  - CWE-639
  - CWE-862
  - 'OWASP-A01:2021'

---

You are reviewing source code for Insecure Direct Object Reference
(IDOR) — endpoints that fetch a record by ID and return it without
checking whether the authenticated user owns or has access to that
record.

**Cross-file analysis:** the ownership check may live in the helper
itself. Open `getProjectById` — does it accept the session user and
scope the query, or does it just look up by id? Some repos have two
flavors (`getProjectById` raw vs. `getProjectForUser` scoped); the
finding depends on which the candidate calls.

Tenant IDs are the multi-tenant variant. The handler is authenticated
but checks "this user is logged in" instead of "this user belongs to
this tenant". Membership checks often live in a helper
(`getTeamForUser`, `requireTeamMember`, `assertOrgAccess`) or in
middleware that scopes by tenant. Open them before flagging.

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
In Spring, IDs bound with `@RequestParam` or `@PathVariable` are
request input.

**Common helper names:**
`getProjectById`, `getDeploymentById`, `getInstallationById`,
`getUserById`, `getTeamById`, `findById`, `findOneById`, `findByUid`,
`findFirst({ where: { id } })`, `findUnique({ where: { id } })`.

**Tenant ID from request used in a DB write:**
```ts
const orgId = req.params.orgId;
await db.org.update({ where: { id: orgId }, data: req.body });
```
Worse than a read: the caller can mutate any org.

**Tenant ID propagated from a record lookup:**
```ts
const installation = await getInstallationByUid(parsed.body.installationUid);
const team = await getTeamById(installation.teamId);
```
If the first lookup is not scoped, the tenant ID it yields is
attacker-chosen. Flag the chain unless membership is re-checked.

**Tenant-shaped IDs to watch:**
`teamId`, `ownerId`, `orgId`, `tenantId`, `installationId`,
`configurationId`, `integrationConfigurationId`, `customerId`,
`workspaceId`, `accountId`, and snake_case forms (`team_id`,
`owner_id`, `org_id`, `tenant_id`, `installation_id`, `customer_id`,
`workspace_id`, `account_id`).

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
For a tenant ID, verify the authenticated user belongs to that tenant
before using the ID in any read or write:
```ts
const { teamId } = req.body;
const member = await db.teamMember.findFirst({
  where: { teamId, userId: session.userId },
});
if (!member) return new Response("forbidden", { status: 403 });
const team = await getTeamById(teamId);
```
Or scope the lookup by membership:
```ts
const team = await db.team.findFirst({
  where: { id: req.body.teamId, members: { some: { userId: session.userId } } },
});
```

## True positive criteria

Flag when ALL of the following hold:

1. A lookup function with `*ById` / `*ByUid` / `findUnique` /
   `findFirst({ where: { id } })` shape is called.
2. The ID argument originates from request input.
3. The result is returned to the caller (or used in a subsequent
   mutation reachable by the response) without an ownership check
   on the same code path.

Also flag a tenant ID when ALL of the following hold:

1. A tenant-shaped ID is taken from request input (`req.body.*`,
   `req.params.*`, `req.query.*`, a validator's parsed body,
   `@RequestParam`), or from a record returned by an unscoped lookup.
2. The ID is used in a DB read or write (`getTeamById`, `findById`,
   `findUnique`, `findFirst`, `update`, `delete` with a
   `where: { id: tenantId }` clause).
3. No membership check appears between the request parse and the
   DB call.

## What to ignore

- Lookup followed by an explicit ownership check before returning:
  `if (record.userId !== session.userId) throw forbidden()`.
- Queries that scope by both the ID and the session user:
  `findFirst({ where: { id, ownerId: session.userId } })`.
- Lookup of a record that is intentionally public: blog posts,
  marketplace listings, published content.
- Tenant ID derived server-side from the session:
  `const teamId = session.activeTeamId;`.
- Membership check before the DB call:
  `assertUserBelongsToTeam(userId, teamId)`, `requireTeamMember(...)`.
- Queries that scope by both the tenant ID and the user:
  `where: { id: teamId, members: { some: { userId } } }`.
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

// team ID from request body, no membership check
export async function POST(req: Request) {
  const { teamId } = await req.json();
  const team = await getTeamById(teamId);
  return Response.json(team);
}

// org ID from URL param, written without membership check
export async function PATCH(req: Request, { params }: { params: { orgId: string } }) {
  await db.org.update({ where: { id: params.orgId }, data: await req.json() });
  return Response.json({ ok: true });
}
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

// Tenant ID from session
const teamId = session.activeTeamId;
const team = await getTeamById(teamId);

// Membership check before DB call
await assertTeamMember(session.userId, req.body.teamId);
const team = await getTeamById(req.body.teamId);

// Query scoped by membership
const team = await db.team.findFirst({
  where: { id: req.body.teamId, members: { some: { userId: session.userId } } },
});
```
