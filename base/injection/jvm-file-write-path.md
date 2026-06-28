---
slug: jvm-file-write-path
name: Arbitrary File Write or Rename via Unvalidated Path (JVM)
description: 'Java file-write and file-rename/move operations (FileOutputStream, Files.write, Files.move, FileWriter, File.renameTo, FileUtils.writeStringToFile) whose path argument is user-controlled — allows writing or renaming to arbitrary locations including JSP/WAR deploy directories, cron files, and SSH authorized_keys. Traces path values and checks for base-directory confinement.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'new\s+FileOutputStream\s*\(|new\s+FileWriter\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: FileOutputStream or FileWriter construction
      - regex: 'Files\.(write|newOutputStream|createFile|createDirectories)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: java.nio.file.Files write/create operations
      - regex: 'FileUtils\.(writeStringToFile|writeByteArrayToFile|copyInputStreamToFile|write)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Apache Commons IO FileUtils write
      - regex: 'new\s+File\s*\([^)]*\)\s*\.\s*(createNewFile|mkdirs|mkdir)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: new File(...).createNewFile() / mkdirs()
      - regex: 'FileCopyUtils\.(copy|copyToByteArray)\s*\(|StreamUtils\.copy\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring FileCopyUtils / StreamUtils copy to file
      - regex: 'Files\.move\s*\(|\.renameTo\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: File rename or move with potentially user-controlled target
where:
  extensions:
    - java
    - kt
  excludePatterns:
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: 'new\s+FileOutputStream\s*\(|new\s+FileWriter\s*\('
      label: FileOutputStream or FileWriter construction
    - regex: 'Files\.(write|newOutputStream|createFile|createDirectories)\s*\('
      label: java.nio.file.Files write/create operations
    - regex: 'FileUtils\.(writeStringToFile|writeByteArrayToFile|copyInputStreamToFile|write)\s*\('
      label: Apache Commons IO FileUtils write
    - regex: 'new\s+File\s*\([^)]*\)\s*\.\s*(createNewFile|mkdirs|mkdir)\s*\('
      label: new File(...).createNewFile() / mkdirs()
    - regex: 'FileCopyUtils\.(copy|copyToByteArray)\s*\(|StreamUtils\.copy\s*\('
      label: Spring FileCopyUtils / StreamUtils copy to file
    - regex: 'Files\.move\s*\(|file\.renameTo\s*\(|\.renameTo\s*\(\s*new\s+File\s*\('
      label: File rename or move with potentially user-controlled target path
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-22
  - CWE-73
  - 'OWASP-A01:2021'
---

You are reviewing JVM source code (Java / Kotlin) for arbitrary file write
via an unvalidated user-controlled path — a file system write operation
whose destination path is derived from user input without confirming the
result stays within a permitted base directory.

The classic path traversal (`../../etc/cron.d/backdoor`) is one form, but
the more dangerous variant in server-side Java is an absolute path supplied
directly by the user. Because many Java path-validation checks only strip
`..` sequences, an attacker who can supply an absolute path (e.g.
`/opt/tomcat/webapps/ROOT/shell.jsp`) bypasses relative-traversal guards
entirely and can write arbitrary content to arbitrary locations — including
JSP files that trigger immediate code execution in Tomcat/Jetty deployments.

**Cross-file analysis:** the path value is often passed through several
layers before reaching the write call. A `fileName` parameter received in
a REST controller may flow through a service into a utility method. Open
callers to determine whether the path is ever validated against a safe base
directory before the write occurs.

## What to look for

**FileOutputStream / FileWriter with a variable path:**
```java
String filePath = request.getParameter("outputFile");
OutputStream out = new FileOutputStream(filePath);   // absolute path allowed
out.write(content);
```

**java.nio.file.Files write operations:**
```java
Path target = Paths.get(userSuppliedPath);
Files.write(target, data);
Files.newOutputStream(target).write(content);
Files.createFile(target);
```

**Apache Commons IO FileUtils:**
```java
File dest = new File(userFileName);
FileUtils.writeStringToFile(dest, masterPassword, "UTF-8");
FileUtils.copyInputStreamToFile(uploaded, dest);
```

**File creation from user-supplied name:**
```java
File f = new File(userPath);
f.createNewFile();                  // creates the file at arbitrary location
new FileWriter(f).write(content);
```

**Spring utility copy:**
```java
FileCopyUtils.copy(inputStream, new FileOutputStream(userPath));
```

**File rename / move with user-controlled target:**
```java
// REST "external upload" renames the file at the caller-supplied path
File target = new File(userSuppliedPath + ".zip");
existingFile.renameTo(target);                    // arbitrary rename

Path src = Paths.get(existingFilePath);
Files.move(src, Paths.get(userTargetPath));       // arbitrary move/rename
```

## True positive criteria

Flag when ALL of the following hold:

1. A file-write operation is called (any of the APIs above).
2. The path argument is, transitively, user-controlled: a request
   parameter, form field, REST body, URL segment, or a value that the user
   wrote to a database and is now retrieved and used as a path.
3. No base-directory confinement check is applied. The correct check
   resolves the canonical path and verifies it starts with the permitted
   base:
   ```java
   Path resolved = Paths.get(baseDir).resolve(userInput).normalize();
   if (!resolved.startsWith(Paths.get(baseDir))) {
       throw new SecurityException("Path outside allowed directory");
   }
   ```
   Flag if this check is absent, applied to the wrong variable (the raw
   input rather than the resolved path), or performed after the write.

## What to ignore

- Paths built entirely from server-controlled constants or from a UUID/
  hash that the application assigned (users never supply the path string
  directly).
- Paths validated against a strict allowlist of legal values before use.
- Write operations inside `src/test/` or developer-only tooling.
- Writes to temp files created by `File.createTempFile()` where the
  directory is the system temp dir and the user controls only the content,
  not the path.

## Examples

True positives:
```java
// Admin-supplied absolute path written without confinement check
String fileName = request.getParameter("dumpFile");
File f = new File(fileName);             // "/opt/tomcat/webapps/ROOT/shell.jsp"
FileUtils.writeStringToFile(f, masterPasswordPlaintext, "UTF-8");

// REST upload to user-specified path
String dest = body.getTargetPath();
Files.write(Paths.get(dest), uploadedBytes);   // can be /etc/cron.d/backdoor

// Only relative-traversal stripped — absolute path still accepted
String cleaned = fileName.replace("../", "");
new FileOutputStream(new File(cleaned)).write(data);   // /tmp/evil still works
```

False positives to skip:
```java
// Path confined to upload directory
Path resolved = uploadDir.resolve(fileName).normalize();
if (!resolved.startsWith(uploadDir)) throw new SecurityException("invalid path");
Files.write(resolved, data);

// Server-assigned name — user controls content, not path
String id = UUID.randomUUID().toString();
Files.write(storageDir.resolve(id + ".bin"), data);

// Constant path — no user input
FileUtils.writeStringToFile(new File("/var/app/config/default.xml"), template);
```

If the write destination is, or can be, influenced by user-supplied data
and no canonical-path confinement is applied, treat it as a finding.
