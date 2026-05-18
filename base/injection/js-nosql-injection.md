---
slug: js-nosql-injection
name: NoSQL Injection (JavaScript / MongoDB)
description: Mongoose / MongoDB driver queries built with $where, JSON.parse(req.*), or uncoerced request values — allows query operator smuggling or server-side JS execution. Walker mode traces the value source and any coercion/validation helpers.
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
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "\\$where\\s*:\\s*(`|\"|')[^\"`']*\\$\\{|\\$where\\s*:\\s*[\"'][^\"']*\\+"
    label: "$where with template-literal or concatenation"
  - regex: "JSON\\.parse\\s*\\(\\s*(req|request|ctx)\\."
    label: "JSON.parse over request input passed to query"
  - regex: "new\\s+RegExp\\s*\\(\\s*(req|request)\\."
    label: "new RegExp from request input (used in query)"
  - regex: "\\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany)\\s*\\(\\s*\\{[^}]*:\\s*(req|request)\\.(body|query|params)\\."
    label: "Mongo query field set directly from request without coercion"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-943
  - OWASP-A03:2021
---

You are reviewing Node.js / TypeScript source code for NoSQL injection
in MongoDB / Mongoose — patterns where user input influences a MongoDB
query in ways that allow an attacker to inject operators, execute
server-side JavaScript, or bypass authentication.

**Walker mode advantage:** the request value may have been parsed,
coerced, or validated before the query call — possibly in a
middleware, a Zod schema, or a helper. Follow imports to verify:
`String(req.body.email)`, `emailSchema.parse(...)`, or
`ObjectId(...)` neutralize the operator-smuggling vector. A finding
requires the absence of any such coercion on the path from request to
query.

## What to look for

**`$where` with string concatenation or template literals:**
```ts
User.find({ $where: "this.name == '" + name + "'" })
db.collection.find({ $where: `this.x == '${input}'` })
Model.find({ $where: function() { return this.x === y; } })
```
`$where` evaluates a JavaScript expression server-side. Building it
from user input is equivalent to `eval` — an attacker can inject
`'|| true || '` or call arbitrary JS.

**`JSON.parse(req.body.*)` as a query argument:**
```ts
Model.find(JSON.parse(req.body.filter))
```
Passing raw user JSON as the entire query document lets the caller
supply MongoDB operators: `{ "$ne": null }` bypasses equality checks,
`{ "$gt": "" }` matches everything.

**`$where` inside aggregation pipelines:**
```ts
coll.aggregate([{ $match: { $where: "this.score > " + score } }])
```

**`new RegExp(req.*)` in queries:**
```ts
User.find({ name: new RegExp(req.query.q) })
```
A caller-controlled regex is a ReDoS vector and allows the caller to
craft a pattern that matches unintended documents. Use a MongoDB text
index or escape the string before constructing the regex.

**Uncoerced `req.*` field values in queries:**
```ts
Model.findOne({ email: req.body.email })
User.find({ username: req.query.username })
```
If the caller sends `{ "email": { "$ne": null } }` in the JSON body
and the field value is used without coercing to a primitive type,
MongoDB will treat it as an operator expression. The fix is to
coerce: `{ email: String(req.body.email) }`.

## True positive criteria

Flag when ANY of the following hold:

1. `$where` receives a string built from user input (concatenation
   or template literal).
2. The entire query filter is `JSON.parse(userInput)`.
3. `$where` appears inside an aggregation pipeline with a
   user-influenced operand.
4. `new RegExp(req.*)` is used in a query.
5. A Mongoose/Mongo `find`/`findOne` receives a field value directly
   from `req.body`, `req.query`, or `req.params` without coercion to
   a primitive (`String()`, `Number()`, etc.) or schema validation
   that guarantees the shape.

## What to ignore

- `$where` with a fully hardcoded string (no interpolation).
- `find` / `findOne` where the field value has been cast via
  `String()`, `Number()`, `mongoose.Types.ObjectId(id)`, or
  validated by a schema (Zod, Joi, Yup) before use.
- Mongoose models where the schema enforces strict field types
  and the query uses dot-notation with known schema fields.
- Test files.

## Examples

True positives:
```ts
// $where with template literal
User.find({ $where: `this.name == '${req.body.name}'` });

// JSON.parse — operator smuggling
Model.find(JSON.parse(req.body.filter));

// Uncoerced req.body field — {"email": {"$ne": null}} bypasses check
User.findOne({ email: req.body.email });

// new RegExp from query string
User.find({ name: new RegExp(req.query.search) });
```

False positives to skip:
```ts
// Coerced to string — safe
User.findOne({ email: String(req.body.email) });

// Validated by Zod before query
const { email } = emailSchema.parse(req.body);
User.findOne({ email });

// Hardcoded $where
User.find({ $where: "this.status === 'active'" });
```
