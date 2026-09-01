---
slug: nodejs-tar-path-traversal
name: Node.js TAR Extraction Path Traversal
description: 'TAR archive extraction using tar, tar-stream, or tar-fs without entry path validation — a crafted archive escapes the extraction directory and overwrites arbitrary server files, enabling RCE or config tampering.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'require\s*\(\s*[''"]tar[''"]\s*\)|from\s*[''"]tar[''""]'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: tar import
      - regex: 'require\s*\(\s*[''"]tar-stream[''"]\s*\)|from\s*[''"]tar-stream[''""]'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: tar-stream import
      - regex: 'require\s*\(\s*[''"]tar-fs[''"]\s*\)|from\s*[''"]tar-fs[''""]'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: tar-fs import
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
    - jsx
    - tsx
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/*.test.{js,ts,mjs}'
    - '**/*.spec.{js,ts,mjs}'
    - '**/__tests__/**'
  preFilter:
    - regex: 'require\s*\(\s*[''"]tar[''"]\s*\)|tar\.(extract|x)\s*\('
      label: tar extract call
    - regex: 'require\s*\(\s*[''"]tar-stream[''"]\s*\)|tar\.extract\s*\('
      label: tar-stream extract
    - regex: 'require\s*\(\s*[''"]tar-fs[''"]\s*\)|tarFs\.extract\s*\('
      label: tar-fs extract
    - regex: '\.pipe\s*\([^)]*\.createWriteStream|\.pipe\s*\([^)]*Extract'
      label: stream pipe to file write during tar extraction
    - regex: 'entry\.path|header\.name|entry\.header'
      label: TAR entry path accessed
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-22
  - 'OWASP-A01:2021'
---

You are reviewing Node.js source code for TAR extraction path traversal (tar slip) — the same class as zip slip but for `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2` archives. A crafted archive with entry paths containing `../` sequences can write files outside the intended extraction directory.

## The vulnerability

TAR entries store arbitrary filenames. An attacker-controlled archive can contain:
```
../../.ssh/authorized_keys
../config/database.yml
../../../../etc/cron.d/evil
```

When code writes entries to disk by joining the output directory with the entry name, without checking the resolved path stays under the output directory, arbitrary files on the server can be overwritten.

## Library-specific patterns

**tar (the `tar` npm package):**
```js
// Safe: tar.x with cwd — the tar package strips leading / and .. by default
await tar.x({ file: 'archive.tgz', cwd: '/var/uploads' });

// VULNERABLE: manual path construction overrides the safety
await tar.x({ file: archive, cwd: '/uploads', onentry: entry => {
  const dest = path.join('/uploads', entry.path);  // VULNERABLE
  entry.pipe(fs.createWriteStream(dest));
}});
```
Note: the `tar` npm package's built-in extraction (`tar.x`, `tar.extract`) strips `../` by default in modern versions. Flag only if entry paths are extracted manually.

**tar-stream:**
```js
const extract = tar.extract();
extract.on('entry', (header, stream, next) => {
  const dest = path.join('/uploads/', header.name);  // VULNERABLE
  stream.pipe(fs.createWriteStream(dest));
  stream.on('end', next);
});
fs.createReadStream(uploadedFile).pipe(extract);
```
`tar-stream` is a low-level parser with no path sanitization — all path handling is the developer's responsibility.

**tar-fs:**
```js
fs.createReadStream(uploadedFile).pipe(tarFs.extract('/uploads'));
// tarFs.extract strips leading / but NOT .. sequences — VULNERABLE to relative traversal
```

## True positive criteria

Flag when ALL hold:
1. A TAR library is used to extract a user-supplied archive (upload, external download from user-controlled URL)
2. Entry path names (`header.name`, `entry.path`) are used to construct file system write paths without traversal sanitization
3. No path confinement check validates the resolved destination stays under the output directory

Safe check:
```js
const dest = path.resolve(outputDir, header.name);
if (!dest.startsWith(path.resolve(outputDir) + path.sep)) {
  throw new Error('Traversal detected');
}
```

## What to ignore

- `tar.x()` / `tar.extract()` from the `tar` npm package used without manual `onentry` path handling — these strip `../` natively
- Extraction of hardcoded, trusted archives (application assets, built-in resources)
- Code that only reads entry metadata or streams entry content in memory without writing to disk
- Test files extracting known-good test fixtures

## Examples

True positives:
```js
// tar-stream with manual path join — no traversal check
const extract = tarStream.extract();
extract.on('entry', (header, stream, next) => {
  const filePath = path.join(uploadDir, header.name);
  stream.pipe(fs.createWriteStream(filePath));
  stream.on('end', next);
});
req.pipe(extract);
```
```js
// tar-fs — strips leading / but not ..
req.pipe(tarFs.extract('/var/app/uploads'));
// archive entry '../../../etc/passwd' would write to /var/app/etc/passwd — still bad
```

False positives to skip:
```js
// tar npm package with default extraction — strips ../ natively
await tar.x({ file: './assets/templates.tgz', cwd: './tmp' });
```

Report where the archive originates (user upload, user-supplied URL), which library handles extraction, and whether the entry path goes through any sanitization before the write call.
