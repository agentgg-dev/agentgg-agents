---
slug: nodejs-readfile-path-traversal
name: Node.js File Read Path Traversal
description: 'User-controlled paths passed to Node.js file-read APIs (readFile, readFileSync, createReadStream, readFileAsync) without sanitization, enabling path traversal to read arbitrary files on the server.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'require\s*\(\s*[''"]fs[''"]\s*\)|from\s*[''"]fs[''""]|import\s+\*\s+as\s+fs'
        in:
          - '**/*.{js,ts,mjs,cjs}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
        label: Node.js fs module imported
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/build/**'
    - '**/*.test.*'
    - '**/*.spec.*'
  preFilter:
    - regex: '\.createReadStream\('
      label: createReadStream call
    - regex: '\.readFile(?:Sync|Async)?\('
      label: readFile/readFileSync/readFileAsync call
references:
  - CWE-22
  - 'OWASP-A01:2021'
---

You are reviewing Node.js code for path traversal vulnerabilities in file-read operations. User-controlled path components passed to `fs` APIs without sanitization allow attackers to read arbitrary files (e.g., `../../../../etc/passwd`).

## Functions to examine

- `fs.readFile(path, ...)` / `fs.readFileSync(path, ...)`
- `fs.createReadStream(path, ...)`
- `fs.readFileAsync(path, ...)` (promisify wrappers)

## True positive criteria

Flag when ALL hold:
1. A user-supplied value (HTTP request param, query string, body field, URL segment, cookie, or header) flows into the path argument
2. No adequate sanitization is applied:
   - `path.basename()` alone is NOT sufficient (strips directory but can still be bypassed with URL encoding in some contexts)
   - Safe pattern: `path.resolve()` against a base directory + prefix check: `if (!resolved.startsWith(BASE_DIR)) throw`

## Common patterns

**Vulnerable:**
```js
app.get('/file', (req, res) => {
  fs.readFile('./uploads/' + req.query.name, (err, data) => res.send(data));
});

app.get('/download', (req, res) => {
  const stream = fs.createReadStream(path.join('./files', req.params.filename));
  stream.pipe(res);
});
```

**Safe:**
```js
const safePath = path.resolve('./uploads', req.query.name);
if (!safePath.startsWith(path.resolve('./uploads') + path.sep)) {
  return res.status(403).send('Forbidden');
}
fs.readFile(safePath, callback);
```

## What to ignore

- Paths built entirely from constants or environment variables with no user input
- File reads in test files with hardcoded fixture paths
- Paths validated against an explicit allowlist before use

Report: the file API called, where the path value originates (req.query/req.params/req.body/etc.), and what sanitization if any is applied before the call.
