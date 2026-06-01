---
slug: fs-write-symlink-boundary
name: Filesystem Write Without Symlink Boundary Check
description: fs.writeFile / fs.mkdir / fs.copyFile to a non-literal path without realpath / startsWith(rootDir) validation — attacker can place a symlink to escape the intended root. Follows path-resolver helpers.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'fs(\.promises)?\.(writeFile|writeFileSync|createWriteStream|copyFile|copyFileSync|symlink|link|rename|appendFile|chmod|chown|truncate|mkdir|mkdirSync)\s*\([^)]*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fs write call with template-literal path
      - regex: 'fs(\.promises)?\.(writeFile|copyFile|appendFile|mkdir|createWriteStream)\s*\([^)]*\bpath\.(join|resolve)\s*\([^)]*\b(req|request|params|body)\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fs write with path.join/resolve combining request data
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
    - regex: 'fs(\.promises)?\.(writeFile|writeFileSync|createWriteStream|copyFile|copyFileSync|symlink|link|rename|appendFile|chmod|chown|truncate|mkdir|mkdirSync)\s*\([^)]*`[^`]*\$\{'
      label: fs write call with template-literal path
    - regex: 'fs(\.promises)?\.(writeFile|copyFile|appendFile|mkdir|createWriteStream)\s*\([^)]*\bpath\.(join|resolve)\s*\([^)]*\b(req|request|params|body)\b'
      label: fs write with path.join/resolve combining request data
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-22
  - CWE-59
  - 'OWASP-A01:2021'
---

You are reviewing Node.js source code for filesystem writes that
operate on a user-influenced path without verifying the path resolves
inside an allowed root.

**Cross-file analysis:** projects commonly have a `safeWrite()` or
`resolveWithinRoot()` helper that does the `realpath + startsWith`
check. When the candidate file uses such a helper, open it to verify
the check is correct — common mistakes: comparing to `ROOT` without
the trailing separator (allows sibling `ROOT-evil/`), or skipping
the `realpath` step (allows symlink escape). The risk: even if you `path.join(ROOT, userInput)`
and validate the input doesn't contain `..`, an attacker who can place
a symlink at any path component can redirect the write outside ROOT.

This agent complements `path-traversal` which focuses on `..` escapes;
this one focuses on symlink escapes in writes.

## What to look for

**`fs.writeFile` / `fs.mkdir` / `fs.copyFile` / etc. on a non-literal
path:**
```ts
fs.writeFile(`${root}/${name}`, data, cb);
fs.mkdirSync(`${rootDir}/${subdir}`);
fs.copyFile(source, `${dest}/${userPath}`, cb);
fs.appendFile(path.join(ROOT, req.body.path), entry, cb);
fs.createWriteStream(path.resolve(BASE, params.file));
```

**The set of write functions to watch:**
`fs.writeFile`, `fs.writeFileSync`, `fs.createWriteStream`,
`fs.copyFile`, `fs.copyFileSync`, `fs.symlink`, `fs.link`,
`fs.rename`, `fs.appendFile`, `fs.chmod`, `fs.chown`, `fs.truncate`,
`fs.mkdir`, plus the `fs/promises` (`fsp`) equivalents.

## Required boundary check

To prevent symlink escape, resolve the realpath and verify it's
within the allowed root:

```ts
import { realpath } from "node:fs/promises";

const candidate = path.resolve(ROOT, userInput);
const resolved = await realpath(candidate).catch(() => candidate);
if (!resolved.startsWith(ROOT + path.sep)) {
  throw new Error("path outside allowed root");
}
await fs.writeFile(resolved, data);
```

Common helper names to look for:
- `realpath`, `fs.realpath`
- `path.relative` with `startsWith` check
- `resolveWritablePathWithinRoot`
- `withinRoot`, `insideRoot`

## True positive criteria

Flag when ALL of the following hold:

1. A filesystem write function is called with a path argument that
   is built from a user-controlled value (template literal,
   `path.join`/`path.resolve` with `req.*`, concatenation).
2. No realpath / startsWith / within-root check appears in the same
   function (or in a wrapping helper present in the file).

## What to ignore

- Writes to a fully hardcoded path.
- Writes where the path is built from internal identifiers
  (database-generated UUIDs).
- Writes preceded by a `realpath` + `startsWith(ROOT)` check on
  the same path.
- Test files.

## Examples

True positives:
```ts
// Write to path.join with req.body.path — no realpath check
await fs.writeFile(path.join(UPLOAD_DIR, req.body.path), data);

// Template-literal path
fs.writeFileSync(`${ROOT}/${name}`, data);

// Symlink target user-controlled
await fs.symlink(req.body.target, path.join(ROOT, "link"));
```

False positives to skip:
```ts
// Boundary check present
const dest = path.resolve(ROOT, req.body.path);
const realDest = await fs.realpath(dest).catch(() => dest);
if (!realDest.startsWith(ROOT + path.sep)) throw new Error("escape");
await fs.writeFile(realDest, data);

// Hardcoded path
await fs.writeFile("/var/log/app.log", entry);

// UUID-based name (server-generated, not user)
await fs.writeFile(path.join(ROOT, crypto.randomUUID()), buffer);
```
