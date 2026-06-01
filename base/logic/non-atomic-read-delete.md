---
slug: non-atomic-read-delete
name: Non-Atomic Read-Then-Delete
description: 'redis.get followed by redis.del (or DB find followed by delete) — two concurrent requests both succeed in reading the value before either deletes it, processing it twice. Walker mode follows token/cache helpers across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'redis\.(get|hget|hgetall)\s*\([\s\S]{0,200}redis\.(del|hdel)\s*\('
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: redis get + del pair (verify atomicity)
      - regex: '\.(findFirst|findUnique|findOne)\s*\([\s\S]{0,300}\.(delete|destroy|deleteMany)\s*\('
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: find + delete pair (verify transaction)
      - regex: (magic|otp|invite|reset|verify|consume).*Token|oneTimeUse
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: One-time-token shape (high-risk)
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
  preFilter:
    - regex: 'redis\.(get|hget|hgetall)\s*\([\s\S]{0,200}redis\.(del|hdel)\s*\('
      label: redis get + del pair (verify atomicity)
      multiline: true
    - regex: '\.(findFirst|findUnique|findOne)\s*\([\s\S]{0,300}\.(delete|destroy|deleteMany)\s*\('
      label: find + delete pair (verify transaction)
      multiline: true
    - regex: (magic|otp|invite|reset|verify|consume).*Token|oneTimeUse
      label: One-time-token shape (high-risk)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-367
  - CWE-362
---

You are reviewing source code for non-atomic read-then-delete
sequences — a common one-time-token / single-use-record race where
two concurrent requests both observe the value, both proceed to use
it, and only one of them actually wins the delete.

**Walker mode advantage:** the read-then-delete may be inside a
`consumeMagicLink` / `useOneTimeToken` helper imported from a shared
module. Open it to verify it uses `GETDEL`, a transaction, or
`DELETE ... RETURNING` — all of which close the race window.

## What to look for

**Redis read-then-delete:**
```ts
const cached = await redis.get(key);
if (!cached) return null;
await redis.del(key);
```
Both concurrent callers see the value and proceed before either
deletes it.

**Redis HGET then HDEL:**
```ts
const value = await redis.hget(bucket, field);
await redis.hdel(bucket, field);
```

**Session expiration via separate read + write:**
```ts
const session = await redis.hgetall(`session:${id}`);
await redis.set(`session:${id}`, "expired");
```

**DB find then delete:**
```ts
const row = await db.findFirst({ where: { id } });
await db.deleteMany({ where: { id: row.id } });

const r = await client.findUnique({ where: { id } });
await client.destroy(r.id);
```

## The classic vulnerability shape

One-time tokens (password reset, magic link, OTP) are usually
implemented as "read, validate, delete". Without atomicity, both
the legitimate user and a racing attacker can pass the validation
step, doubling effects.

## Safe patterns

**Redis `GETDEL` (atomic):**
```ts
const value = await redis.getdel(key);   // atomic read+delete
```

**Redis `WATCH` / `MULTI` transaction:**
```ts
await redis
  .multi()
  .get(key)
  .del(key)
  .exec();
```

**Lua script via `redis.eval`:**
```lua
local v = redis.call("GET", KEYS[1])
if not v then return nil end
redis.call("DEL", KEYS[1])
return v
```

**DB delete with `RETURNING` (Postgres):**
```sql
DELETE FROM otp_tokens WHERE token = $1 RETURNING user_id
```
Only the request that wins the delete gets a row back.

**Distributed lock around the critical section.**

## True positive criteria

Flag when ALL of the following hold:

1. A read operation (`redis.get`, `db.findFirst`, `db.findUnique`,
   `redis.hget`, `redis.hgetall`) precedes
2. A delete or invalidate (`redis.del`, `db.delete`,
   `db.deleteMany`, `redis.hdel`, `redis.set(..., "expired")`)
3. With no transaction, atomic op, or distributed lock wrapping
   both.

## What to ignore

- `redis.getdel(key)` — atomic.
- `redis.eval(luaScript, ...)` performing the read+delete in Lua.
- DB transactions wrapping both operations.
- `DELETE ... RETURNING` patterns.
- Test files.

## Examples

True positives:
```ts
// Magic link consumption — race window
const token = await redis.get(`magic:${id}`);
if (!token) throw new Error("invalid");
await redis.del(`magic:${id}`);
return signIn(token);

// One-time invite
const invite = await db.invite.findFirst({ where: { code } });
if (!invite) throw new Error("invalid");
await db.invite.delete({ where: { id: invite.id } });
```

False positives to skip:
```ts
// Atomic GETDEL
const token = await redis.getdel(`magic:${id}`);
if (!token) throw new Error("invalid");
return signIn(token);

// DELETE ... RETURNING
const [invite] = await sql`
  DELETE FROM invites WHERE code = ${code} RETURNING *
`;
if (!invite) throw new Error("invalid");

// Transaction
await db.$transaction(async (tx) => {
  const invite = await tx.invite.findFirst({ where: { code } });
  if (!invite) throw new Error();
  await tx.invite.delete({ where: { id: invite.id } });
});
```
