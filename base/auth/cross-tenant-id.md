---
slug: cross-tenant-id
name: Cross-Tenant ID Access
description: Tenant/team/org ID taken from request input and used in a DB lookup without verifying the authenticated user belongs to that tenant — allows reading or modifying other tenants' data. Walker mode follows DB helpers to verify scoping.
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
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "\\b(teamId|ownerId|orgId|tenantId|installationId|configurationId|integrationConfigurationId|customerId|workspaceId|accountId)\\b"
    label: "Tenant-shaped identifier"
  - regex: "(get|find|update|delete)[A-Z][a-zA-Z]+By(Id|Uid|Slug)\\s*\\("
    label: "Repository getByX/findByX/updateByX call"
  - regex: "\\.(findUnique|findFirst|findOne|update|delete)\\s*\\(\\s*\\{\\s*where\\s*:\\s*\\{\\s*id\\s*:"
    label: "ORM where: { id } lookup"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-639
  - CWE-862
  - OWASP-A01:2021
---

You are reviewing source code for cross-tenant ID access — patterns
where a multi-tenant application accepts a tenant/team/org/owner ID
from the request and uses it directly in a database query without
checking that the authenticated user belongs to that tenant.

**Walker mode advantage:** ownership scoping often happens in a
repository helper (`getTeamForUser`, `requireTeamMember`,
`assertOrgAccess`). When a candidate file calls `getTeamById(id)`,
open the helper and verify whether it also takes the session user
and enforces membership — or whether it's a bare ID lookup. Also
check for middleware that scopes by tenant.

This is the multi-tenant variant of IDOR. The handler is
authenticated, but it authorizes "this user is logged in" instead of
"this user owns/has access to this specific tenant".

## What to look for

**Tenant ID from request used in DB lookup:**
```ts
const teamId = req.body.teamId;
const team = await getTeamById(teamId);
return Response.json(team);
```
The user supplies `teamId`. Without an ownership check, they can
read any team.

**Tenant ID from request used in DB write:**
```ts
const orgId = req.params.orgId;
await db.org.update({ where: { id: orgId }, data: req.body });
```
Same issue, but worse — the user can mutate any org.

**Tenant ID propagated from a record lookup without ownership check:**
```ts
const installation = await getInstallationByUid(parsed.body.installationUid);
const team = await getTeamById(installation.teamId);
```
The `installation` lookup itself may be cross-tenant; the team
lookup chains the issue.

**Common tenant-shaped IDs to watch:**
`teamId`, `ownerId`, `orgId`, `tenantId`, `installationId`,
`configurationId`, `integrationConfigurationId`, `customerId`,
`workspaceId`, `accountId`.

## Required check (what the safe pattern looks like)

After fetching the tenant or scoping the query, the code must verify
the authenticated user has access:
```ts
const teamId = req.body.teamId;
const team = await getTeamById(teamId);
const member = await db.teamMember.findFirst({
  where: { teamId, userId: session.userId },
});
if (!member) return new Response("forbidden", { status: 403 });
```
Or scope the lookup by the session user's tenant:
```ts
const team = await db.team.findFirst({
  where: { id: req.body.teamId, members: { some: { userId: session.userId } } },
});
```

## True positive criteria

Flag when ALL of the following hold:

1. A tenant-shaped ID (see list above) is extracted from request
   input (`req.body.*`, `req.params.*`, `req.query.*`, parsed body
   from a validator).
2. That ID is used in a DB lookup or write (`getTeamById`,
   `findById`, `findUnique`, `findFirst`, `update`, `delete` with a
   `where: { id: tenantId }` clause).
3. No ownership/membership check appears between the request parse
   and the DB call.

## What to ignore

- Endpoints where the tenant ID is derived server-side from the
  session: `const teamId = session.activeTeamId;`.
- Endpoints that perform a membership check before the DB call:
  `assertUserBelongsToTeam(userId, teamId)`, `requireTeamMember(...)`.
- Queries that scope by both the tenant ID AND the user ID in a
  single `where` clause: `where: { id: teamId, members: { some: { userId } } }`.
- Test files.

## Examples

True positives:
```ts
// Team ID from request body, no membership check
export async function POST(req: Request) {
  const { teamId } = await req.json();
  const team = await getTeamById(teamId);
  return Response.json(team);
}

// Org ID from URL param, mass assignment + cross-tenant
export async function PATCH(req: Request, { params }: { params: { orgId: string } }) {
  await db.org.update({ where: { id: params.orgId }, data: await req.json() });
  return Response.json({ ok: true });
}
```

False positives to skip:
```ts
// Tenant ID from session
const teamId = session.activeTeamId;
const team = await getTeamById(teamId);

// Membership check before DB call
const member = await assertTeamMember(session.userId, req.body.teamId);
const team = await getTeamById(req.body.teamId);

// Query scopes by user
const team = await db.team.findFirst({
  where: { id: req.body.teamId, members: { some: { userId: session.userId } } },
});
```
