---
slug: jvm-webshell
name: JSP / JVM Webshell Indicators
description: 'JSP and Java files showing webshell indicators — a scriptlet passing a request parameter to Runtime.exec or ProcessBuilder, reflective class loading from request data, or a file-upload handler writing a .jsp into a served directory. Backdoors of this shape allow remote command execution over HTTP.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\([^)]*request\.getParameter'
        in:
          - '**/*.{jsp,jspx,jsw,jsv}'
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Runtime.exec driven directly by a request parameter
      - regex: 'new\s+ProcessBuilder\s*\([^)]*request\.getParameter'
        in:
          - '**/*.{jsp,jspx,jsw,jsv}'
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: ProcessBuilder driven directly by a request parameter
      - regex: '<%[^>]{0,400}(Runtime\.getRuntime|ProcessBuilder|defineClass)'
        in:
          - '**/*.{jsp,jspx,jsw,jsv}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: JSP scriptlet containing process execution or class definition
      - regex: 'defineClass\s*\(|ClassLoader[^;]{0,120}Base64|Class\.forName\s*\([^)]*request\.'
        in:
          - '**/*.{jsp,jspx,jsw,jsv}'
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: reflective class loading, possibly from request-supplied bytes
      - regex: '\.getOutputStream\s*\(\s*\)[\s\S]{0,200}\.jsp[x]?[\"'']'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: upload handler writing a .jsp file
where:
  extensions:
    - jsp
    - jspx
    - jsw
    - jsv
    - java
    - kt
  excludePatterns:
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: 'Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\('
      label: Runtime.exec call
    - regex: 'new\s+ProcessBuilder\s*\('
      label: ProcessBuilder construction
    - regex: 'ClassLoader[^;]{0,120}Base64'
      label: class loader fed Base64-decoded bytes
    - regex: 'defineClass\s*\(|Class\.forName\s*\('
      label: reflective class loading
    - regex: '<%[^>]{0,200}(Runtime|ProcessBuilder|exec)'
      label: JSP scriptlet with execution primitives
    - regex: '\.jsp[x]?[\"'']'
      label: JSP filename literal (upload sink)
  maxFilesPerBatch: 5
references:
  - CWE-506
  - CWE-94
  - 'OWASP-A03:2021'
---

You are reviewing JSP and Java files for webshell indicators. A webshell
is a backdoor that accepts a command over HTTP and runs it on the server.
On the JVM these usually arrive as a dropped `.jsp` file, or as an upload
handler that lets an attacker drop one.

Treat this as a compromise indicator, not an ordinary code-quality issue.
A confirmed webshell means the host should be assumed compromised.

## High-confidence indicators

### Request parameter straight into process execution

```java
Runtime.getRuntime().exec(request.getParameter("cmd"));
new ProcessBuilder(request.getParameter("c")).start();
```

No legitimate application passes a raw request parameter into process
execution. In a `.jsp` scriptlet this is close to conclusive.

### JSP scriptlet holding execution primitives

A `<% ... %>` block that references `Runtime.getRuntime`, `ProcessBuilder`,
or `defineClass` is worth reading in full. Modern applications put logic in
controllers and servlets, so a JSP carrying process execution is out of
place even when it is not obviously malicious.

### Reflective loading of attacker-supplied bytes

```java
Class<?> c = defineClass(null, decoded, 0, decoded.length);
Class.forName(request.getParameter("cls")).newInstance();
```

A common evasion is to Base64-decode a class body from the request or from
a header, define it, then invoke it. That keeps the shell out of the file
on disk.

### Upload handler that can write a .jsp

An upload endpoint writing under a served directory without an extension
allowlist is the delivery mechanism, even if no shell is present yet. Check
whether the target directory is served by the container and whether the
extension is validated.

## True positive criteria

Flag when any of these holds:

1. In a `.jsp`, `.jspx`, `.jsw` or `.jsv` file, a request-controlled value
   reaches `Runtime.exec`, `ProcessBuilder`, or reflective class
   definition, with no allowlist between them.
2. In a `.java` or `.kt` file, a request-controlled value reaches reflective
   class definition, or reaches `Runtime.exec` / `ProcessBuilder` together
   with a backdoor signal: a hardcoded password compared against a request
   parameter, a Base64 or hex decoded command, or a class body decoded from
   request data.
3. An upload path can write a `.jsp`/`.jspx` into a directory the servlet
   container serves, and the handler does not restrict the extension.

A request value that reaches `Runtime.exec` or `ProcessBuilder` in ordinary
application code, with no backdoor signal, is command injection, not a
webshell. Do not report it here.

Raise confidence when the file also shows: a hardcoded password compared
against a request parameter before execution, Base64 or hex decoding of
the command, a single-file JSP with no corresponding source in version
control, or an odd filename in a directory of otherwise normal views.

## What to ignore

- Build, deployment, and developer tooling that legitimately shells out
  using server-controlled arguments, for example a Gradle task or an admin
  CLI whose input never comes from a request.
- `Runtime.exec` with a hardcoded command and no request-derived argument.
- Test fixtures under `src/test/` that exercise a command runner.
- Upload handlers with a confirmed extension allowlist writing outside any
  served directory.
- Security tooling in the repo that deliberately contains webshell samples
  as detection fixtures. Check whether the path looks like a test corpus.

## Examples

True positive:
```java
// dropped file, served directly, command from the query string
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
```

False positive to skip:
```java
// fixed command, arguments from server configuration
Process p = new ProcessBuilder("/usr/bin/convert", inputPath, outputPath).start();
```

If a request-controlled value reaches process execution or class
definition without an allowlist, treat it as a finding and say plainly
that the host should be triaged as potentially compromised.
