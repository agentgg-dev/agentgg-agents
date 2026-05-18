---
slug: zip-slip
name: Zip Slip / Archive Entry Path Traversal
description: Code that extracts archive entries (zip, tar, gzip, jar, war) by joining the entry name onto a destination path without verifying the resolved path stays inside the destination — a crafted `../../etc/cron.d/payload` entry writes outside the intended directory.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
  - "**/*.{py,rb,go,php,java,kt,cs}"
references:
  - CWE-22
  - CWE-23
  - OWASP-A01:2021
---

You are reviewing source code for Zip Slip — archive extraction loops
that take the entry's name from inside the archive and write to
`destination + entry.name` without verifying the resolved path is
contained within the destination directory.

An attacker who controls the uploaded archive includes an entry named
`../../etc/cron.d/payload` (or `..\..\Windows\System32\...` on Windows).
The naive extractor writes the file there, gaining file overwrite —
often escalating to RCE via cron, init scripts, web roots, or SSH
authorized_keys.

This is **distinct from generic path-traversal** because the tainted
input is the archive's internal filename, not a request parameter,
and the safe check has a specific shape (`resolved.startsWith(dest)`).

## What to look for

**Node.js — unzipper:**
```ts
fs.createReadStream(zipPath)
  .pipe(unzipper.Parse())
  .on("entry", (entry) => {
    const out = path.join("uploads/", entry.path);     // entry.path attacker-controlled
    entry.pipe(fs.createWriteStream(out));
  });
```

**Node.js — adm-zip:**
```ts
const zip = new AdmZip(uploadedBuf);
zip.extractAllTo("uploads/", true);                    // extractAllTo with no validation
// or per-entry:
for (const e of zip.getEntries()) {
  fs.writeFileSync(path.join("uploads/", e.entryName), e.getData());
}
```

**Node.js — jszip / node-stream-zip / yauzl:**
```ts
const z = await JSZip.loadAsync(buf);
for (const name of Object.keys(z.files)) {
  fs.writeFileSync(path.join(dest, name), await z.file(name).async("nodebuffer"));
}
```

**Node.js — tar:**
```ts
await tar.x({ file: archive, C: dest });               // tar handles `..` since v6, but older versions / option mistakes are unsafe
```

**Python:**
```python
import zipfile
with zipfile.ZipFile(uploaded) as z:
    z.extractall(dest)                                 # safe in 3.12+; unsafe before, and even now `..` outside `dest` slips through on some platforms
# Per-entry, classic unsafe:
for member in z.namelist():
    out = os.path.join(dest, member)
    with open(out, "wb") as fh:
        fh.write(z.read(member))
```
```python
import tarfile
with tarfile.open(uploaded) as t:
    t.extractall(dest)                                 # Python < 3.12 had no filter; 3.12+ requires filter= argument or warns
```

**Java:**
```java
try (ZipInputStream zin = new ZipInputStream(in)) {
  ZipEntry e;
  while ((e = zin.getNextEntry()) != null) {
    File out = new File(dest, e.getName());            // e.getName() attacker-controlled
    try (FileOutputStream fos = new FileOutputStream(out)) {
      zin.transferTo(fos);
    }
  }
}
```

**Go:**
```go
r, _ := zip.OpenReader(path)
for _, f := range r.File {
    out := filepath.Join(dest, f.Name)                 // no Clean / containment check
    w, _ := os.Create(out)
    rc, _ := f.Open()
    io.Copy(w, rc)
}
```

**Defense shape** — what a SAFE loop looks like:

```ts
const destAbs = path.resolve(dest);
for (const entry of entries) {
  const resolved = path.resolve(destAbs, entry.name);
  if (!resolved.startsWith(destAbs + path.sep) && resolved !== destAbs) {
    throw new Error("zip slip");
  }
  // ...write...
}
```

```python
for member in z.namelist():
    target = os.path.realpath(os.path.join(dest, member))
    if not target.startswith(os.path.realpath(dest) + os.sep):
        raise Exception("zip slip")
```

Or use a library/API with built-in protection:
- Python 3.12+ `tarfile.extractall(filter="data")`.
- Node `tar` v6+ with default options (rejects `..`).

## True positive criteria

Flag when ALL of the following hold:

1. An archive is opened from request input, user-uploaded file, or any
   path under user influence.
2. Code iterates entries (or calls a bulk extract) and writes each
   to `dest + entryName` form.
3. No `startsWith(resolvedDest)` containment check, no `realpath`
   verification, and the library version is not known to protect
   by default.

## What to ignore

- `tar.x({ cwd: dest, strict: true })` on Node `tar` v6+ (rejects
  `..` automatically).
- Python `tarfile.extractall(path, filter="data")` (3.12+).
- Java `Files.copy(zin, target.normalize().toAbsolutePath())` *with*
  a subsequent containment check against the dest root.
- Extractors that explicitly call a `safeJoin(dest, name)` helper
  that throws on traversal — verify the helper actually does this.
- Test fixtures and seed scripts that unpack developer-trusted
  archives.

## Examples

True positives:
```ts
// Naive write: entry.path can be ../../etc/foo
fs.createReadStream(tempFile)
  .pipe(unzipper.Parse())
  .on("entry", (entry) => {
    const out = "uploads/" + entry.path;
    entry.pipe(fs.createWriteStream(out));
  });

// Broken containment: `includes(path.resolve('.'))` matches even when
// the resolved path escapes the intended subdir.
const absolutePath = path.resolve("uploads/complaints/" + fileName);
if (absolutePath.includes(path.resolve('.'))) {
  entry.pipe(fs.createWriteStream("uploads/complaints/" + fileName));
}
```
```python
# zipfile.extractall before 3.12 — and even on 3.12, `..` outside dest still extracts
with zipfile.ZipFile(uploaded) as z:
    z.extractall("/var/data/uploads")
```
```java
File out = new File(uploadDir, zipEntry.getName());
new FileOutputStream(out).write(buf);
```

False positives to skip:
```ts
// startsWith containment check — safe
const destAbs = path.resolve(uploadDir);
const resolved = path.resolve(destAbs, entry.path);
if (!resolved.startsWith(destAbs + path.sep)) throw new Error("zip slip");
entry.pipe(fs.createWriteStream(resolved));

// Modern tar with default safety
await tar.x({ file: archive, C: dest });
```

The most reliable test: "if the archive contains an entry named
`../../../tmp/owned`, what file gets written?" If you cannot prove
from the code that an exception is thrown before the write, it's a
finding.
