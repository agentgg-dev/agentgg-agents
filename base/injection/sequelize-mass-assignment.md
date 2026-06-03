---
slug: sequelize-mass-assignment
name: Sequelize Mass Assignment
description: 'Sequelize Model.create / build / update / bulkCreate calls that receive a request body directly or via spread, letting the caller write to any column on the model — including role, isAdmin, emailVerified, deletedAt, internal flags.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
references:
  - CWE-915
  - 'OWASP-A08:2021'
---

You are reviewing TypeScript/JavaScript source code for mass assignment
in Sequelize ORM — `Model.create(payload)`, `Model.build(payload)`,
`Model.update(payload, ...)`, `Model.bulkCreate([...])`, and instance
`record.update(payload)` / `record.set(payload)` calls where
`payload` is a request body (or spread of one) without an explicit
column allowlist.

The damage: the model has columns like `role`, `isAdmin`,
`emailVerified`, `subscriptionTier`, `internalNotes`, `deletedAt`.
A registration handler that does `User.create(req.body)` lets the
attacker send `{ email, password, role: "admin" }` and become admin.

## What to look for

**`Model.create` / `build` with request body:**
```ts
await User.create(req.body);
await User.create({ ...req.body });
const post = Post.build(body);
```

**`Model.update` with body:**
```ts
await User.update(req.body, { where: { id } });
await User.update({ ...body }, { where: { id } });
```

**Instance `update` / `set`:**
```ts
const u = await User.findByPk(id);
await u.update(req.body);
u.set(req.body);
await u.save();
```

**`bulkCreate` with array of bodies:**
```ts
await User.bulkCreate(req.body);   // each element fully attacker-shaped
```

**Variable names that flag as "incoming payload":**
`req.body`, `request.body`, `body`, `payload`, `input`, `data`,
`json`, `args`, `params` — when defined as the parsed request and
passed directly into a Sequelize call.

## True positive criteria

Flag when BOTH of the following hold:

1. A Sequelize method (`create`, `build`, `bulkCreate`, `update`,
   instance `update`/`set`) is called.
2. The argument is a request-body variable (or spread of one) without
   explicit field selection or a `fields:` allowlist option that
   restricts which columns are written.

## What to ignore

- Calls with explicit object literals enumerating every field:
  ```ts
  await User.create({ name: body.name, email: body.email, role: "user" });
  ```
- Calls passing the `fields` option to restrict columns:
  ```ts
  await User.create(req.body, { fields: ["name", "email"] });
  await user.update(req.body, { fields: ["name", "bio"] });
  ```
- Inputs that went through a schema parser that strips unknown keys
  before reaching Sequelize (Zod `.strict()`, Joi
  `{ stripUnknown: true }`, class-validator with
  `{ excludeExtraneousValues: true }`).
- Seed scripts, migrations, and test fixtures that insert
  developer-controlled data.

## Examples

True positives:
```ts
// Registration endpoint — caller can set role/isAdmin
app.post("/register", async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});

// PATCH user profile — caller can set deletedAt, emailVerified, etc.
app.patch("/users/:id", async (req, res) => {
  await User.update(req.body, { where: { id: req.params.id } });
});

// Instance update spread
const user = await User.findByPk(req.params.id);
await user.update({ ...req.body, updatedAt: new Date() });
```

False positives to skip:
```ts
// Explicit fields
await User.create({
  name:     req.body.name,
  email:    req.body.email,
  password: hash(req.body.password),
});

// fields allowlist
await User.update(req.body, {
  where:  { id: req.params.id },
  fields: ["name", "bio"],     // only these columns are written
});

// Zod-validated, stripUnknown
const safe = RegisterSchema.parse(req.body);   // schema only has { name, email, password }
await User.create(safe);
```

The `fields:` option on Sequelize calls is the cleanest defense and
the one you should be able to grep for in a hardened codebase — its
absence on a `.create(body)` is a strong signal.
