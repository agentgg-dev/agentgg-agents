---
slug: path-traversal
name: Path Traversal
description: 'File system operations (read, write, unlink, stat) using user-controlled paths without validation — allows reading or writing files outside the intended directory via ../ sequences. Follows path-sanitizer helpers.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'fs(\.promises)?\.(readFile|readFileSync|readFileAsync|writeFile|writeFileSync|unlink|unlinkSync|stat|statSync|open|createReadStream|createWriteStream|rename|renameSync)\s*\([^)]*\b(req|request|params|body|userPath|filename|originalname)\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fs operation with request-derived path
      - regex: 'fs(\.promises)?\.(readFile|readFileAsync|writeFile|unlink|stat|open|createReadStream|createWriteStream)\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: fs operation with template-literal path
      - regex: 'path\.(join|resolve)\s*\([^)]*\b(req|request|params|body|userInput|filename|originalname)\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: path.join/resolve combining with request data
      - regex: \bopen\s*\(\s*os\.path\.join\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: open() over os.path.join
      - regex: os\.path\.join\s*\([^)]*\b(request|params|filename|user_path|body|args|name)\b
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: os.path.join combining request data
      - regex: send_file\s*\(|send_from_directory\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: Flask send_file / send_from_directory
      - regex: \bopen\s*\(\s*f[\"']
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: open() with an f-string path
      - regex: FileResponse\s*\(
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: FastAPI/Django FileResponse
where:
  extensions:
    - py
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
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/.venv/**'
    - '**/venv/**'
    - '**/site-packages/**'
  preFilter:
    - regex: 'fs(\.promises)?\.(readFile|readFileSync|readFileAsync|writeFile|writeFileSync|unlink|unlinkSync|stat|statSync|open|createReadStream|createWriteStream|rename|renameSync)\s*\([^)]*\b(req|request|params|body|userPath|filename|originalname)\b'
      label: fs operation with request-derived path
    - regex: 'fs(\.promises)?\.(readFile|readFileAsync|writeFile|unlink|stat|open|createReadStream|createWriteStream)\s*\(\s*`[^`]*\$\{'
      label: fs operation with template-literal path
    - regex: '\.readFileAsync\s*\('
      label: promisified readFileAsync call
    - regex: 'path\.(join|resolve)\s*\([^)]*\b(req|request|params|body|userInput|filename|originalname)\b'
      label: path.join/resolve combining with request data
    - regex: \bopen\s*\(\s*os\.path\.join\s*\(
      label: open() over os.path.join
    - regex: os\.path\.join\s*\([^)]*\b(request|params|filename|user_path|body|args)\b
      label: os.path.join with request data
    - regex: send_file\s*\(|send_from_directory\s*\(
      label: Flask send_file
    - regex: \bopen\s*\(\s*f[\"']
      label: open() with f-string path
  maxFilesPerBatch: 5
references:
  - CWE-22
  - 'OWASP-A01:2021'

---

You are reviewing Node.js / TypeScript source code for path traversal
— a file system operation that uses a user-controlled value as part of
the file path, allowing an attacker to escape the intended directory
with `../` sequences and read or write arbitrary files on the server.

**Cross-file analysis:** repositories often have a `safeJoin()` /
`confineToDir()` / `assertWithin()` helper that does the right
`resolve()` + `startsWith()` check. If the candidate file calls one,
open the helper and verify the boundary check is correct — common
failure: comparing to `BASE` without the trailing separator allows a
sibling `BASE-evil/` to pass.

## What to look for

**Direct path operations with user input:**
- `fs.readFile(userPath, ...)` / `fs.readFileSync(userPath)`
- `fs.writeFile(userPath, data, ...)` / `fs.writeFileSync(userPath, data)`
- `fs.unlink(userPath, ...)` / `fs.unlinkSync(userPath)`
- `fs.stat(userPath, ...)` / `fs.statSync(userPath)`
- `fs.createReadStream(userPath)` / `fs.createWriteStream(userPath)`
- `fs.open(userPath, ...)` / `fs.promises.readFile(userPath)`
- `fs.readFileAsync(userPath, ...)` (promisify wrapper around
  `fs.readFile`; same sink under a different name)

**Path construction with user input:**
- `path.join(baseDir, userInput)` — `path.join` normalizes `..`
  segments, so `path.join("/uploads", "../../etc/passwd")` resolves
  to `/etc/passwd`. Joining a base with user input is only safe if
  you verify the result is still under the base.
- `path.resolve(baseDir, userInput)` — same issue. Resolves to an
  absolute path that may be outside the intended root.
- Template literal paths: `` `/data/${filename}` `` passed to any `fs`
  function.

**User input sources to trace:**
- `req.query.*`, `req.params.*`, `req.body.*` (Express)
- `request.json()`, `request.formData()`, URL search params (Fetch API)
- Environment-derived values that originate from external input
- File name from a multipart upload (`req.file.originalname`)

## True positive criteria

Flag when ALL of the following hold:

1. A file system operation is called with a path argument.
2. The path argument includes a value from a user-controlled source
   (request param, body field, query string, uploaded filename).
3. No path-confinement check is applied before the operation. A safe
   check looks like:

   ```ts
   const resolved = path.resolve(BASE_DIR, userInput);
   if (!resolved.startsWith(BASE_DIR + path.sep)) {
     throw new Error("Path outside allowed directory");
   }
   ```

   Flag if this check is absent, applied to the wrong variable, or
   applied after the file operation.

   `path.basename()` alone is NOT sufficient confinement. It strips
   directory components but does not bind the result to a base
   directory, and it can still be bypassed where the value is decoded
   again after the call. If `basename()` is the only check before the
   file operation, flag it.

## What to ignore

- `path.join` / `path.resolve` where all arguments are hardcoded
  strings or module-level constants with no user input.
- File paths derived exclusively from internal IDs (e.g., a UUID
  looked up from the database) where the user never directly supplies
  the path string.
- Cases where the user input passes through a strict allowlist before
  being used as a path: e.g., `filename === "report.pdf"` and only
  that exact value is accepted.
- Test files, seed scripts, or developer-only tooling.
- Cloud storage SDKs (S3, GCS) — object keys do not map to the local
  filesystem and do not carry path traversal risk in the same way.

## Examples

True positives:
```ts
// Filename from request body used directly
const filePath = path.join("/uploads", req.body.filename);
fs.writeFileSync(filePath, data);  // ../../etc/cron.d/backdoor

// Query param read without confinement check
const content = fs.readFileSync(`/data/${req.query.file}`, "utf8");

// Uploaded file's original name used as the save path
const dest = path.join(UPLOAD_DIR, req.file.originalname);
fs.renameSync(req.file.path, dest);

// path.resolve without startsWith check
const abs = path.resolve(BASE_DIR, params.subdir);
return fs.createReadStream(abs);
```

False positives to skip:
```ts
// Hardcoded path — no user input
const cfg = fs.readFileSync(path.join(__dirname, "config.json"), "utf8");

// UUID from database — user never supplies the path string
const filePath = path.join(STORAGE_DIR, record.fileId + ".bin");

// Allowlist enforced before use
if (!/^[a-z0-9-]+\.pdf$/.test(name)) throw new Error("invalid");
const safe = path.join(DOCS_DIR, name);

// Confinement check present and correct
const resolved = path.resolve(BASE, userInput);
if (!resolved.startsWith(BASE + "/")) throw forbidden();
fs.readFile(resolved, cb);
```
