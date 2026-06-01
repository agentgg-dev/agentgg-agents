---
slug: soql-injection
name: SOQL Injection (Salesforce)
description: Salesforce SOQL queries built by string concatenation or template literal interpolation via jsforce / @jsforce/jsforce-node — allows operators and SOQL clauses to be injected. Confirms jsforce/salesforce context and traces query helpers.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '\.(query|queryAll|queryMore)\s*\(\s*`[^`]*SELECT[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Salesforce-style query() with template-literal SOQL interpolation
      - regex: '\.(query|queryAll|queryMore)\s*\(\s*"[^"]*SELECT[^"]*"\s*\+'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Salesforce-style query() with concatenated SOQL
      - regex: 'tooling\.query\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Tooling API query() with template-literal interpolation
      - regex: 'from\s+[''"](jsforce|@jsforce/jsforce-node|@salesforce/)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: imports jsforce / @salesforce/* (confirms context)
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '\.(query|queryAll|queryMore)\s*\(\s*`[^`]*SELECT[^`]*\$\{'
      label: Salesforce-style query() with template-literal SOQL interpolation
    - regex: '\.(query|queryAll|queryMore)\s*\(\s*"[^"]*SELECT[^"]*"\s*\+'
      label: Salesforce-style query() with concatenated SOQL
    - regex: 'tooling\.query\s*\(\s*`[^`]*\$\{'
      label: Tooling API query() with template-literal interpolation
    - regex: 'from\s+[''"](jsforce|@jsforce/jsforce-node|@salesforce/)'
      label: imports jsforce / @salesforce/* (confirms context)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing TypeScript / JavaScript source code for Salesforce
Object Query Language (SOQL) injection — SOQL strings built by
string concatenation or template literal interpolation of user-
controlled values, allowing an attacker to append SOQL clauses and
exfiltrate or modify records they should not access.

**Cross-file analysis:** confirm the import is jsforce /
`@salesforce/*` — `.query()` is a common method name on many SDKs
that aren't SOQL. Then follow the SOQL string back through any helper
to find the construction site, and verify whether interpolated values
came from request input or from a trusted server-side source.

## What to look for

**`conn.query()` / `conn.queryAll()` with template literal:**
```ts
await conn.query(`SELECT Id FROM Account WHERE Name = '${name}'`);
await conn.queryAll(`SELECT Id FROM Lead WHERE Email = '${email}'`);
```

**String concatenation:**
```ts
await conn.query("SELECT Id FROM Account WHERE Id = " + id);
```

**Tooling API:**
```ts
await tooling.query(`SELECT Id FROM ApexClass WHERE Name = '${name}'`);
```

**jsforce / @jsforce/jsforce-node variants:**
```ts
await sf.query(`SELECT Id FROM Opportunity WHERE StageName = '${stage}'`);
await sfConn.queryMore(`SELECT Id FROM Lead WHERE Status = '${status}'`);
```

**SOQL-shaped template literal outside a direct call:**
```ts
const soql = `SELECT Id, Name FROM Account WHERE OwnerId = '${ownerId}'`;
await conn.query(soql);
```

## The attack

SOQL does not support parameterized queries in the same way SQL does.
An attacker who controls `name` can inject:
```
' OR Name LIKE '%   →  WHERE Name = '' OR Name LIKE '%'
```
This matches all records, leaking data beyond the intended scope.

## True positive criteria

Flag when BOTH of the following hold:

1. A Salesforce query method (`conn.query`, `conn.queryAll`,
   `conn.queryMore`, `tooling.query`, or any alias with a context
   import from `jsforce`, `@jsforce/jsforce-node`, or
   `@salesforce/*`) is called with a string argument.
2. That string contains interpolation (`${...}`) or concatenation
   (`+`) where the interpolated value comes from user input:
   request params, body fields, URL search params, or data returned
   from user-supplied input.

## What to ignore

- Query strings with no interpolation or concatenation — entirely
  hardcoded SOQL is safe.
- Interpolation of an internal constant (e.g., a known record ID
  from the session, not from request params).
- Salesforce SOQL with only numeric or UUID-shaped values interpolated
  that have been validated against a strict pattern
  (`/^[0-9a-zA-Z]{15,18}$/`) before use.
- Test files.

## Examples

True positives:
```ts
// Template literal with user-supplied name
const name = req.body.accountName;
await conn.query(`SELECT Id FROM Account WHERE Name = '${name}'`);

// Concatenation
await conn.query("SELECT Id FROM Account WHERE Id = " + req.params.id);

// Tooling API — same risk
await tooling.query(`SELECT Id FROM ApexClass WHERE Name = '${req.query.class}'`);
```

False positives to skip:
```ts
// Hardcoded — no interpolation
await conn.query("SELECT Id, Name FROM Account WHERE IsActive = true");

// Internal session value — not user-controlled
await conn.query(`SELECT Id FROM Account WHERE OwnerId = '${session.userId}'`);
// (flag if session.userId can be set by the user; skip if it's set server-side)
```
