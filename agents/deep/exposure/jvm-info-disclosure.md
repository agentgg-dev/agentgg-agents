---
slug: jvm-info-disclosure
name: Sensitive System Info Exposed in HTTP Responses (JVM)
description: 'Java web handlers that render System.getenv(), System.getProperties(), classpath URLs, JVM runtime info, or build/version manifest data in HTTP responses accessible to unauthenticated or low-privilege users — leaking environment variables, internal paths, software versions, and configuration that aids attackers in fingerprinting and targeting the server.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'System\.getenv\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: System.getenv() call
      - regex: 'System\.(getProperties|getProperty)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: System.getProperties / getProperty call
      - regex: 'getClassLoader\s*\(\)\s*\.\s*(getURLs|getResource)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: ClassLoader URL enumeration (classpath disclosure)
      - regex: 'ManagementFactory\.(getRuntimeMXBean|getOperatingSystemMXBean|getPlatformMXBeans)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: JVM management / runtime info via ManagementFactory
      - regex: '(getPackage|getImplementationVersion|getSpecificationVersion|getImplementationTitle)\s*\(\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Package version or title via reflection
      - regex: 'getResourceAsStream\s*\(\s*"[^"]*MANIFEST\.MF"'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Reading MANIFEST.MF for build/version info
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
    - regex: 'System\.getenv\s*\('
      label: System.getenv() call
    - regex: 'System\.(getProperties|getProperty)\s*\('
      label: System.getProperties / getProperty call
    - regex: 'getClassLoader\s*\(\)\s*\.\s*(getURLs|getResource)\s*\('
      label: ClassLoader URL enumeration (classpath disclosure)
    - regex: 'ManagementFactory\.(getRuntimeMXBean|getOperatingSystemMXBean|getPlatformMXBeans)\s*\('
      label: JVM management / runtime info via ManagementFactory
    - regex: '(getPackage|getImplementationVersion|getSpecificationVersion|getImplementationTitle)\s*\(\)'
      label: Package version or title via reflection
    - regex: 'getResourceAsStream\s*\(\s*"[^"]*MANIFEST\.MF"'
      label: Reading MANIFEST.MF for build/version info
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-200
  - CWE-497
  - 'OWASP-A05:2021'
---

You are reviewing JVM source code (Java / Kotlin) for sensitive system
information leakage — places where environment variables, JVM system
properties, classpath contents, runtime info, or build/version metadata
are read and then written into HTTP responses that are accessible to
unauthenticated users or users with insufficient privilege.

This class of vulnerability does not cause direct code execution, but
it gives attackers a precise map of the software stack, internal paths,
credentials stored in env vars, and configuration — all of which narrow
the attack surface significantly.

**Cross-file analysis:** the sensitive value is often read in a status
or admin page component and passed to a template or model. Trace where
the read value flows — if it ends up in a model that renders into an
HTTP response, check whether that response endpoint requires admin-level
authentication.

## What to look for

**Environment variables in web responses:**
```java
// Server status page renders all env vars — no auth required
Map<String, String> env = System.getenv();
model.addAttribute("environment", env);
return "serverStatus";   // template renders every key/value
```
Environment variables commonly contain `DATABASE_URL`, `SECRET_KEY`,
`AWS_SECRET_ACCESS_KEY`, `ADMIN_PASSWORD`, and internal hostnames.

**System properties / classpath in responses:**
```java
String classpath = System.getProperty("java.class.path");
response.getWriter().write("Classpath: " + classpath);
// reveals internal file system layout: /opt/app/lib/internal-secret-2.3.jar
```

**ClassLoader URL enumeration:**
```java
URL[] urls = ((URLClassLoader) getClass().getClassLoader()).getURLs();
// each URL is a full path: file:/home/geoserver/webapps/geoserver/WEB-INF/lib/...
for (URL url : urls) { out.write(url.toString()); }
```

**JVM runtime info via ManagementFactory:**
```java
RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
String classPath = runtime.getClassPath();     // same as java.class.path
String vmArgs = runtime.getInputArguments().toString(); // may include -Dpassword=...
```

**Build/version info from manifests or Package:**
```java
// Welcome page footer shows GeoServer version + revision
String version = GeoServerInfo.class.getPackage().getImplementationVersion();
// About page shows all JAR versions
InputStream is = getClass().getResourceAsStream("/META-INF/MANIFEST.MF");
```
Version info alone is CWE-200 — it lets attackers look up exact CVEs
for the disclosed version.

## True positive criteria

Flag when ALL of the following hold:

1. A sensitive system-info source is read: `System.getenv()`,
   `System.getProperty()` for JVM or OS properties, `getClassLoader().getURLs()`,
   `ManagementFactory.getRuntimeMXBean()`, `Package.getImplementationVersion()`,
   or `MANIFEST.MF` reading.
2. The value is placed into an HTTP response — via a model/view, response
   writer, JSON serialization, or template rendering.
3. The response endpoint is accessible without admin-level authentication,
   OR the code has no visible authorization check on the path that reaches
   the response (unauthenticated, or available to any authenticated user).

## What to ignore

- Reads that are used only in server-side logic (logging, conditional
  config) and never placed into an HTTP response.
- Admin-only endpoints with a clear auth gate (`@PreAuthorize("hasRole('ADMIN')")`,
  `SecurityContextHolder` check, or equivalent) where only an admin can
  trigger the response — this is acceptable for operator tooling.
- Build version read once at startup and stored in a private field — not
  a finding unless that field is later exposed in an HTTP response without
  auth.
- Test utilities and developer-only tooling under `src/test/`.

## Examples

True positives:
```java
// Server status page — accessible to non-admins, dumps all env vars
public ModelAndView serverStatus(HttpServletRequest request) {
    model.put("environment", System.getenv());   // leaks secrets in env
    model.put("systemProperties", System.getProperties()); // leaks paths
    return new ModelAndView("serverStatus", model);
}

// GWC home page renders classpath and version info to all users
String cp = getClass().getClassLoader().getURLs().toString();
model.addAttribute("classpath", cp);
```

False positives to skip:
```java
// Used only for logging — never in HTTP response
log.debug("Java classpath: {}", System.getProperty("java.class.path"));

// Admin-only endpoint with auth gate
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/status")
public ResponseEntity<Map<String,String>> adminStatus() {
    return ResponseEntity.ok(System.getenv());  // acceptable — admin only
}
```
