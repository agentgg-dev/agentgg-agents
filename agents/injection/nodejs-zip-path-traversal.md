---
slug: nodejs-zip-path-traversal
name: Node.js ZIP Extraction Path Traversal
description: 'ZIP archive extraction using adm-zip, unzip, or unzipper without validating entry paths — a crafted archive can write files to arbitrary locations on the server (zip slip), enabling remote code execution or config overwrite.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'require\s*\(\s*[''"]adm-zip[''"]\s*\)|from\s*[''"]adm-zip[''""]'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: adm-zip import
      - regex: 'require\s*\(\s*[''"]unzipper[''"]\s*\)|from\s*[''"]unzipper[''""]'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: unzipper import
      - regex: 'require\s*\(\s*[''"]unzip[''"]\s*\)|from\s*[''"]unzip[''""]'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: unzip import
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
    - regex: 'require\s*\(\s*[''"]adm-zip[''"]\s*\)|new\s+AdmZip\s*\('
      label: adm-zip usage
    - regex: 'require\s*\(\s*[''"]unzipper[''"]\s*\)|unzipper\.(Open|Parse)'
      label: unzipper usage
    - regex: 'require\s*\(\s*[''"]unzip[''"]\s*\)|\.pipe\s*\(\s*unzip'
      label: unzip usage
    - regex: '\.extractAllTo\s*\(|\.extractEntryTo\s*\(|\.getEntry\s*\('
      label: adm-zip extraction call
    - regex: '\.pipe\s*\([^)]*\.createWriteStream|\.pipe\s*\([^)]*Extract'
      label: stream pipe to file write during extraction
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-22
  - CVE-2018-1002204
  - 'OWASP-A01:2021'
---

You are reviewing Node.js source code for ZIP extraction path traversal (zip slip) — a vulnerability where a crafted ZIP archive contains entries with paths like `../../etc/cron.d/backdoor` that escape the intended extraction directory when written to disk.

## The vulnerability

ZIP archives store entry filenames as-is. A malicious archive can include entries like:
```
../../server/routes/auth.js
../../../../etc/cron.d/evil
../config/database.yml
```

When extraction code joins the output directory with the entry filename and writes without checking the result stays under the output directory, the attacker controls where files land on the server.

## Library-specific patterns

**adm-zip:**
```js
const zip = new AdmZip(uploadedFile);
zip.extractAllTo('/var/uploads/extracted/', true);  // VULNERABLE if archive is user-supplied
```
```js
zip.getEntries().forEach(entry => {
  const dest = path.join('/var/uploads/', entry.entryName);  // VULNERABLE
  fs.writeFileSync(dest, entry.getData());
});
```

**unzipper:**
```js
fs.createReadStream(uploadedZip)
  .pipe(unzipper.Extract({ path: '/var/uploads/' }));  // potentially safe if unzipper sanitizes
```
Note: `unzipper.Extract` does sanitize paths internally in recent versions, but `unzipper.Parse` with manual path handling does not.

**unzip (older package):**
```js
fs.createReadStream(uploadedZip)
  .pipe(unzip.Extract({ path: '/var/uploads/' }))
  .on('entry', entry => {
    const dest = path.join('/uploads/', entry.path);  // VULNERABLE
    entry.pipe(fs.createWriteStream(dest));
  });
```

## True positive criteria

Flag when ALL hold:
1. A ZIP library is used to extract an archive
2. The archive source is user-supplied (uploaded file, downloaded URL from user input, third-party data)
3. The extraction does NOT verify that each resolved entry path stays within the intended output directory

A safe check looks like:
```js
const safeDest = path.resolve(outputDir, entry.entryName);
if (!safeDest.startsWith(path.resolve(outputDir) + path.sep)) {
  throw new Error('Zip slip detected');
}
```

## What to ignore

- Extraction of hardcoded/trusted archives (built-in assets, application resources)
- Code that only reads entry metadata or contents in memory without writing to disk
- `unzipper.Extract()` in recent versions (has built-in sanitization) — still flag if the version is old or if manual path handling follows
- Test code extracting known-safe test fixtures

## Examples

True positives:
```ts
const zip = new AdmZip(req.file.buffer);
zip.extractAllTo(path.join(__dirname, 'uploads'), true);
// No path validation — attacker can write anywhere
```
```js
unzipper.Open.buffer(uploadBuffer).then(d => {
  d.files.forEach(file => {
    file.stream().pipe(fs.createWriteStream(path.join('/uploads', file.path)));
    // path.join does not prevent traversal with absolute paths in file.path
  });
});
```

False positives to skip:
```ts
const zip = new AdmZip('./assets/templates.zip');  // hardcoded, not user-supplied
zip.extractAllTo('./tmp/templates');
```

Report where the archive originates (user upload, external URL, etc.), which extraction call is unsafe, and whether any path validation exists before the write.
