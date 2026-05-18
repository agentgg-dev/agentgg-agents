---
slug: non-atomic-operation
name: Non-Atomic Read-Check-Write (TOCTOU)
description: Read a value, check a condition, then write — between the read and write another request can change the value. Classic race condition affecting balances, counters, quotas, and uniqueness checks. Walker mode follows transaction wrappers across files.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/migrations/**"
  - "**/seed*/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "\\.(findUnique|findFirst|findById|findOne)\\s*\\([\\s\\S]{0,300}\\.update\\s*\\("
    label: "find + update pair (verify transaction)"
    multiline: true
  - regex: "redis\\.get\\s*\\([\\s\\S]{0,200}redis\\.set\\s*\\("
    label: "redis.get + redis.set pair (verify atomicity)"
    multiline: true
  - regex: "\\bbalance\\b[\\s\\S]{0,200}\\.update\\s*\\(|quota|credits"
    label: "Balance/quota/credits mutation (high-risk)"
    multiline: true
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-367
  - CWE-362
  - OWASP-A04:2021
---

You are reviewing source code for non-atomic read-then-write
operations — TOCTOU (time-of-check / time-of-use) race conditions
where a value is read, a decision is made on it, and a write happens,
all in separate database calls.

**Walker mode advantage:** the read and write may be inside a helper
that itself runs in a transaction (`withTransaction(async (tx) => ...)`).
Open the helper to confirm atomicity. Also check whether the write
uses an atomic operator (`{ increment: 1 }`, `decrement`, SQL
`balance = balance - ?`) — if it does, no finding regardless of the
surrounding code. Between the read and write, a
concurrent request can change the value, invalidating the check.

## What to look for

**Balance / quota check-then-spend:**
```ts
async function transfer(id, amount) {
  const account = await db.account.findById(id);
  if (account.balance < amount) return;          // check
  await db.account.update({                       // write
    id,
    balance: account.balance - amount,
  });
}
```
Two concurrent transfers both see the original balance, both pass
the check, both write — overdraft.

**Counter increment:**
```ts
const item = await repo.findOne({ id });
await repo.save({ ...item, count: item.count + 1 });
```
Two concurrent increments produce one increment.

**Uniqueness check-then-insert:**
```ts
const existing = await db.users.findFirst({ where: { email } });
if (existing) throw new Error("email taken");
await db.users.create({ data: { email, name } });
```
Two concurrent signups with the same email both miss the existing
record, both create. Fix: rely on a UNIQUE constraint and catch the
violation.

**Idempotency-key race:**
```ts
const seen = await redis.get(idempotencyKey);
if (seen) return seen;
const result = await charge();
await redis.set(idempotencyKey, result);
```
Two requests with the same key both miss the seen check and both
charge.

## Safe patterns

1. **Database transaction:** wrap read + write in `db.$transaction(...)`
   with appropriate isolation.
2. **Atomic update with WHERE:** `UPDATE accounts SET balance = balance - 100 WHERE id = ? AND balance >= 100` and check rowcount.
3. **Distributed lock:** `withLock(key, async () => {...})` for the
   critical section.
4. **UNIQUE constraint + catch:** let the DB enforce uniqueness.
5. **`INCR` / `HINCRBY` for Redis counters.**

## True positive criteria

Flag when ALL of the following hold:

1. The code reads a value or row, then performs a logical decision
   on it (`if (...) {...}` or implicit decision in subsequent code).
2. The code writes back to the same row/key, with the write
   depending on the value just read.
3. The read and write are NOT inside a transaction, lock, or atomic
   `UPDATE ... WHERE` with the previous value as a guard.

## What to ignore

- Code wrapped in `db.$transaction`, `prisma.$transaction`, or a
  similar transactional context.
- Code using a distributed lock around the critical section.
- `UPDATE ... SET counter = counter + 1` (atomic increment SQL).
- Redis `INCR`, `INCRBY`, `HINCRBY`, `SETNX`, `SET ... NX`.
- Test files / migrations / seed scripts.

## Examples

True positives:
```ts
// Balance check + debit
const account = await db.account.findById(id);
if (account.balance < amount) throw new Error("insufficient");
await db.account.update({ id, balance: account.balance - amount });

// Increment via fetch + save
const post = await db.posts.findUnique({ where: { id } });
await db.posts.update({ where: { id }, data: { views: post.views + 1 } });

// Uniqueness check + insert
const existing = await db.users.findUnique({ where: { email } });
if (existing) throw new Error("taken");
await db.users.create({ data: { email } });
```

False positives to skip:
```ts
// Transactional
await db.$transaction(async (tx) => {
  const acct = await tx.account.findById(id);
  if (acct.balance < amount) throw new Error("insufficient");
  await tx.account.update({ where: { id }, data: { balance: { decrement: amount } } });
});

// Atomic increment
await db.posts.update({
  where: { id },
  data: { views: { increment: 1 } },
});

// Redis atomic op
await redis.incr(`views:${id}`);
```
