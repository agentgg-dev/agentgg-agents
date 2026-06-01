---
slug: over-fetched-response
name: Over-Fetched / Over-Serialized API Response
description: 'API responses that return a full ORM model or DB row to the client without an explicit field allowlist, leaking sensitive columns (password hashes, security answers, internal flags, audit metadata). Walker mode reads the model definition to identify which columns are sensitive.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: (res|reply|ctx)\.(json|send)\s*\(\s*(user|users|account|profile|member|customer)\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Sending a user-shaped record verbatim
      - regex: res\.json\s*\(\s*await\s+\w+\.(findOne|findByPk|findAll|find|findUnique|findFirst|findMany)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: ORM result returned directly
      - regex: return\s+\w+\.toJSON\s*\(\)
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: toJSON of a model returned
      - regex: JSON\.stringify\s*\(\s*user\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Stringify of a user record
      - regex: (SELECT|select)\s+\*\s+FROM
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb,go,php,java,kt,cs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: SELECT * in query
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - php
    - java
    - kt
    - cs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}'
    - '**/node_modules/**'
    - '**/dist/**'
  preFilter:
    - regex: (res|reply|ctx)\.(json|send)\s*\(\s*(user|users|account|profile|member|customer)\b
      label: Sending a user-shaped record verbatim
    - regex: res\.json\s*\(\s*await\s+\w+\.(findOne|findByPk|findAll|find|findUnique|findFirst|findMany)\s*\(
      label: ORM result returned directly
    - regex: return\s+\w+\.toJSON\s*\(\)
      label: toJSON of a model returned
    - regex: JSON\.stringify\s*\(\s*user\b
      label: Stringify of a user record
    - regex: (SELECT|select)\s+\*\s+FROM
      label: SELECT * in query
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-213
  - CWE-200
  - 'OWASP-A01:2021'
---

You are reviewing source code for over-fetched / over-serialized API
responses — handlers that return a full ORM record or database row to
the client without an explicit field allowlist, leaking sensitive
columns that the client was never supposed to see.

Classic example: a `GET /api/users/me` returns the whole `User` row
including `password` (the hash), `passwordResetToken`, `totpSecret`,
`securityAnswer`, `internalNotes`, or `stripeCustomerId`.

**Walker mode advantage:** to know whether a returned object leaks
sensitive fields, you must Read the model definition — Sequelize
`User.init(...)`, Mongoose `new Schema({...})`, Prisma `model User {}`
in `schema.prisma`, TypeORM `@Entity` class, Django models. The route
handler alone doesn't reveal which columns exist.

## What to look for

**Direct model serialization:**
```ts
// Sequelize
const user = await User.findByPk(req.params.id);
res.json(user);                                 // includes every attribute
res.json(user.toJSON());                        // same

// Mongoose
const u = await User.findById(id);
res.json(u);                                    // includes password hash unless schema strips it
```

**Spread-into-response:**
```ts
res.json({ ...user, friendlyName: ... });       // every column flows through
```

**Prisma without `select`:**
```ts
const user = await prisma.user.findUnique({ where: { id } });
return Response.json(user);                     // every column returned
```

**Generic list endpoints:**
```ts
const users = await User.findAll();
res.json(users);                                // all columns × all rows
```

**SELECT \* feeding the response:**
```sql
SELECT * FROM users WHERE id = ?
```
Then the row sent as JSON without column-by-column construction.

**Sensitive column names to watch for in the model definition:**
`password`, `passwordHash`, `password_hash`, `hashedPassword`,
`totpSecret`, `mfaSecret`, `securityAnswer`, `resetToken`,
`passwordResetToken`, `verifyToken`, `apiKey`, `secret`, `salt`,
`stripeCustomerId`, `internalNotes`, `isDeleted`, `roleInternal`,
`deletedAt` (when soft-delete should be hidden).

## How to investigate (use the tools)

1. **Find candidate responses.** Look for `res.json(user)`,
   `Response.json(record)`, returning a model `toJSON()`, or spreading
   a fetched row into a response.

2. **Read the model definition.** Locate the matching model file —
   `models/user.ts` for Sequelize, `schema.prisma` for Prisma, the
   `@Entity` class for TypeORM, the Mongoose schema. List the columns.

3. **Check for protections in the model:**
   - Sequelize: `defaultScope: { attributes: { exclude: ["password"] } }`
     or a `toJSON()` override that deletes sensitive keys.
   - Mongoose: `schema.set("toJSON", { transform: ... })` or `select: false`
     on the schema field.
   - Prisma: needs explicit `select` / `omit` per query — no global hide.
   - TypeORM: `@Column({ select: false })` or class-transformer
     `@Exclude()`.

4. **Check for protection in the handler:**
   - Explicit field whitelist: `res.json({ id, email, name })`.
   - DTO / response schema (Zod, Joi, class-validator) that strips
     unknown keys.
   - Prisma `select: { id: true, email: true }`.

If neither the model nor the handler strips sensitive fields, and the
endpoint is reachable (especially without admin auth), flag it.

## True positive criteria

Flag when ALL of the following hold:

1. A handler returns a model instance, ORM row, or `SELECT *` result
   directly to the client (via `res.json`, `Response.json`, spread,
   `toJSON()`, etc.).
2. The model contains at least one sensitive field by name.
3. No allowlist (handler-side DTO / Prisma `select` / Sequelize
   `attributes` exclusion / Mongoose `select: false` / TypeORM
   `@Exclude`) removes that field before serialization.

## What to ignore

- Endpoints that build the response object explicitly:
  `res.json({ id: user.id, email: user.email })`.
- Models with no sensitive columns (e.g., a `Country` reference table).
- Internal/admin endpoints with explicit admin role check, when the
  leak is intentional for that audience.
- Test fixtures.
- Responses that go through a typed DTO / response schema that strips
  unknown keys (Zod `.strict()` `.parse(output)`, class-transformer
  with `excludeExtraneousValues: true`).

## Examples

True positives:
```ts
// Sequelize User has a `password` column; returned wholesale
app.get("/api/users/:id", async (req, res) => {
  const user = await User.findByPk(req.params.id);
  res.json(user);   // leaks password hash
});

// Prisma without select
export async function GET(req: Request) {
  const u = await prisma.user.findUnique({ where: { id } });
  return Response.json(u);   // every column
}

// Mongoose with no toJSON transform
const u = await User.findOne({ email });
res.json(u);   // includes password unless schema sets select: false
```

False positives to skip:
```ts
// Explicit allowlist
res.json({ id: user.id, email: user.email, name: user.name });

// Prisma select
const u = await prisma.user.findUnique({
  where: { id },
  select: { id: true, email: true, name: true },
});

// Sequelize defaultScope hides password
User.init({...}, { defaultScope: { attributes: { exclude: ["password"] } } });

// Mongoose schema field marked select: false
new Schema({ password: { type: String, select: false } });
```

When the model has many columns and only some are sensitive, prioritize
leaks of credentials, secrets, tokens, and security-question answers.
A leaked `createdAt` is noise; a leaked `password` hash is a finding.
