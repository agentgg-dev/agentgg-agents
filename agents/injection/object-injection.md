---
slug: object-injection
name: Prototype Pollution / Object Injection
description: 'Object.assign, lodash merge, or defaultsDeep called with user-controlled input — allows an attacker to set properties on Object.prototype and affect all objects in the process. Traces validation helpers between request and merge.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: (_|lodash)\.(merge|defaultsDeep|mergeWith)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: lodash deep merge call
      - regex: '\b(deepMerge|deepCopy|deepExtend|extend)\s*\([^)]*\b(req|request|body|payload|input)\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Custom deep-merge call with request data
      - regex: 'Object\.assign\s*\([^)]*\b(req\.body|request\.body|body|payload|input|formData)\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Object.assign with request input as source
      - regex: '\[\s*(req|request)\.(query|body|params)\.[a-zA-Z_]+\s*\]\s*='
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Dynamic property assignment with request-controlled key
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
    - regex: (_|lodash)\.(merge|defaultsDeep|mergeWith)\s*\(
      label: lodash deep merge call
    - regex: '\b(deepMerge|deepCopy|deepExtend|extend)\s*\([^)]*\b(req|request|body|payload|input)\b'
      label: Custom deep-merge call with request data
    - regex: 'Object\.assign\s*\([^)]*\b(req\.body|request\.body|body|payload|input|formData)\b'
      label: Object.assign with request input as source
    - regex: '\[\s*(req|request)\.(query|body|params)\.[a-zA-Z_]+\s*\]\s*='
      label: Dynamic property assignment with request-controlled key
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-1321
  - 'OWASP-A08:2021'
---

You are reviewing JavaScript / TypeScript source code for prototype
pollution — a class of vulnerability where a deep merge or property
assignment using user-controlled input writes to `__proto__`,
`constructor`, or `prototype` on the plain object prototype chain,
affecting every object in the application process.

**Cross-file analysis:** the merged value may have been validated
(Zod, Joi, ajv with `additionalProperties: false`) one step upstream.
Follow imports to verify — a `userSchema.parse(req.body)` before the
merge neutralizes the prototype-pollution surface. Also check whether
the merge utility is one that filters `__proto__` / `constructor`
keys (some hardened forks do).

## What to look for

**`Object.assign` with user input as a source:**
```ts
const merged = Object.assign({}, req.body);
Object.assign(config, params);
```
`Object.assign` does a shallow copy and does not walk the prototype
chain itself, but if `req.body` contains `{ "__proto__": { "admin": true } }`
the key `"__proto__"` is written as an own property on the target —
which in some older Node.js versions can pollute. More importantly,
this is a mass-assignment surface independent of the prototype issue.

**`lodash.merge` / `_.merge` with user input:**
```ts
const out = _.merge({}, defaults, req.body);
lodash.merge(target, userInput);
```
`_.merge` recursively copies nested properties, including
`__proto__` and `constructor.prototype`. Supplying
`{ "__proto__": { "isAdmin": true } }` pollutes the global prototype.

**`_.defaultsDeep` / `defaultsDeep` with user input:**
```ts
_.defaultsDeep(opts, userOpts);
defaultsDeep(target, source);
```
Same recursive merge semantics as `_.merge` — same prototype
pollution risk.

**Custom deep-merge utilities:**
```ts
deepMerge(target, payload);
merge(config, body);
```
Any function named `merge`, `deepMerge`, `deepCopy`, `extend`, or
`assign` that recursively copies nested objects from user input.

**Dynamic property assignment with user-controlled key:**
```ts
obj[req.query.key] = "value";
body[userKey] = req.params.id;
params[someKey] = 1;
```
If `req.query.key` is `"__proto__"`, the assignment reaches
`Object.prototype`.

## True positive criteria

Flag when ANY of the following hold:

1. A deep-merge function (`_.merge`, `_.defaultsDeep`, `deepMerge`,
   or similar recursive merge) is called with a user-supplied object
   as a source argument.
2. `Object.assign` is called with user input as a source AND the
   result is used in a security-relevant context (setting
   permissions, config, or shared state).
3. A computed property key sourced from user input is used to assign
   to an object: `obj[req.query.key] = value`.

## What to ignore

- `Object.assign({}, req.body)` where TypeScript types narrow
  `req.body` to a specific interface with no `__proto__` field, AND
  the result is used only as a value-level DTO (not merged into a
  shared config or prototype chain).
- `_.merge` where all arguments are hardcoded or internal constants.
- `lodash.merge` inside a test file.
- Deep merge where user input is validated by a schema (Zod, Joi)
  that rejects unknown keys before the merge.

## Examples

True positives:
```ts
// lodash merge — prototype pollution risk
const config = _.merge({}, defaultConfig, req.body);

// defaultsDeep — recursive merge
_.defaultsDeep(appOptions, userOptions);

// Dynamic key assignment
const settings = {};
settings[req.query.key] = req.query.value;

// Object.assign propagating mass assignment
const user = Object.assign({}, req.body);
await db.users.update({ id }, user);
```

False positives to skip:
```ts
// Shallow assign to a known-shape type — no prototype issue
const opts: { timeout: number } = Object.assign({}, defaults, { timeout: 5000 });

// Zod validates before merge — no unknown keys
const body = userSchema.parse(req.body);
_.merge(result, body);

// Test file
_.merge({}, { __proto__: { test: true } }); // in spec.ts
```
