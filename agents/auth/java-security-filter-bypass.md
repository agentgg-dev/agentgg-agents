---
slug: java-security-filter-bypass
name: Security Filter Path-Pattern Bypass (Java)
description: 'Spring Security antMatchers / requestMatchers, Apache Shiro filter chains, and Java EE web.xml security constraints that protect a path without covering extension variants (e.g. /rest protected but /rest.html open) or sub-path variants (/admin but not /admin/) — allows unauthenticated access to protected resources by appending a suffix or alternate representation.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'antMatchers\s*\(|antMatcher\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring Security antMatchers usage
      - regex: 'requestMatchers\s*\(|mvcMatchers\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring Security requestMatchers / mvcMatchers
      - regex: '@EnableWebSecurity|WebSecurityConfigurerAdapter|SecurityFilterChain'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring Security configuration class
      - regex: 'filterChainDefinitionMap|addDefinition\s*\(|shiro.*filter'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Apache Shiro filter chain definition
      - regex: '<url-pattern>\s*/[^*]'
        in:
          - '**/web.xml'
          - '**/spring-security.xml'
        label: Java EE exact-path url-pattern in security constraint
where:
  extensions:
    - java
    - kt
    - xml
  excludePatterns:
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: 'antMatchers\s*\(|antMatcher\s*\('
      label: Spring Security antMatchers usage
    - regex: 'requestMatchers\s*\(|mvcMatchers\s*\('
      label: Spring Security requestMatchers / mvcMatchers
    - regex: '@EnableWebSecurity|WebSecurityConfigurerAdapter|SecurityFilterChain'
      label: Spring Security configuration class
    - regex: 'filterChainDefinitionMap|addDefinition\s*\(|shiro.*filter'
      label: Apache Shiro filter chain definition
    - regex: '<url-pattern>\s*/[^*]'
      label: Java EE exact-path url-pattern in security constraint
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-863
  - CWE-284
  - 'OWASP-A01:2021'
---

You are reviewing Java security configuration — Spring Security filter
chains, Apache Shiro definitions, and Java EE `web.xml` security
constraints — for path-pattern bypass vulnerabilities.

The root cause: a security rule protects `/rest` but the underlying
servlet / dispatcher also serves `/rest.html`, `/rest.json`, or `/rest/`
under the same code path. The security filter only matches the pattern
as written, so requests using the alternate URL bypass authentication
entirely.

This class of bug is purely about completeness of path patterns in the
security layer, not about missing auth logic inside handlers. The handler
is protected; the problem is that a different URL representation reaches
the same handler without going through the security rule.

## Common bypass patterns

**1. Extension bypass:**
`antMatchers("/rest")` protects only the bare path. A request for
`/rest.html` or `/rest.json` does not match and is served unauthenticated.
The protected path must be `/rest`, `/rest/*`, AND `/rest.*` — or use
`mvcMatchers("/rest")` which in Spring MVC matches suffix-mapped requests
automatically (but only when `ContentNegotiationStrategy` is suffix-based).

**2. Trailing-slash bypass:**
`antMatchers("/admin")` does not match `/admin/`. In older Spring Security
versions this was a separate path; an attacker appending `/` bypassed the
rule.

**3. antMatcher vs mvcMatcher mismatch (Spring Security 5.x):**
`antMatchers` and `mvcMatchers` use different path-matching strategies.
Using `antMatchers` for an MVC endpoint can leave gaps when the
`DispatcherServlet` is mapped to `/*` and processes suffix-mapped requests.
Using `mvcMatchers` is the correct approach for Spring MVC endpoints.

**4. Shiro filter chain exact vs wildcard:**
`filterChainDefinitionMap.put("/rest", "authc")` — the value `"authc"`
applies only to the exact URL `/rest`. Requests for `/rest.html` or
`/rest/` bypass the filter. Must use `"/rest*"` or `"/rest/**"` as key.

**5. web.xml `<url-pattern>` without extension wildcard:**
```xml
<security-constraint>
  <web-resource-collection>
    <url-pattern>/rest</url-pattern>   <!-- only exact match -->
  </web-resource-collection>
  <auth-constraint><role-name>*</role-name></auth-constraint>
</security-constraint>
```
Requests for `/rest.html` bypass the constraint.

## What to look for

**Spring Security — antMatchers with bare paths:**
```java
http.authorizeRequests()
    .antMatchers("/rest").authenticated()    // "/rest.html" is NOT covered
    .antMatchers("/admin").hasRole("ADMIN")  // "/admin/" is NOT covered
    .anyRequest().permitAll();
```

**Spring Security — inconsistent matcher types:**
```java
// antMatchers used for an MVC endpoint — may not match suffix-mapped requests
http.authorizeRequests()
    .antMatchers("/api/users").authenticated()   // risky with suffix mapping
    // should be: .mvcMatchers("/api/users")
```

**Apache Shiro — exact-path definitions:**
```java
filterChainDefinitionMap.put("/rest", "authc");       // "/rest.html" bypasses
filterChainDefinitionMap.put("/admin", "authc, roles[admin]");
// Should be: "/rest*" or "/rest/**"
```

**web.xml — exact url-pattern:**
```xml
<url-pattern>/rest</url-pattern>     <!-- "/rest.html" not covered -->
<url-pattern>/admin</url-pattern>    <!-- "/admin/" not covered -->
```

## True positive criteria

Flag when ALL of the following hold:

1. A path pattern in a security configuration rule is either:
   - An exact match with no wildcard: `"/rest"`, `"/admin"`.
   - A prefix match ending in `/**` but not covering the bare path
     with extensions: `"/rest/**"` does not match `/rest.html`.
2. The same URL prefix can be reached using a different URL representation
   (extension, trailing slash) that the pattern does not match.
3. The protected path leads to a non-public resource — something that
   requires authentication or authorization to access.

Use the file-system tools to read the security config and the MVC or
servlet mapping files together. Confirm that the URL representations not
covered by the security pattern still route to the same protected handler.

## What to ignore

- Patterns ending in `*` that cover extensions: `"/rest*"` covers
  `/rest.html`, `/rest.json`, `/rest/` — these are safe.
- `mvcMatchers` without `antMatchers` in a standard Spring MVC setup where
  suffix-based content negotiation is disabled — this is generally safe.
- Paths that are intentionally public (login, health, static resources).
- Tests under `src/test/`.

## Examples

True positives:
```java
// GeoServer-style: /rest protected but /rest.html open
http.authorizeRequests()
    .antMatchers("/rest", "/rest/**").authenticated()
    // Missing: "/rest.*" — so /rest.html bypasses auth and leaks REST index

// Shiro exact key
filterChainDefinitionMap.put("/admin", "authc, roles[admin]");
// /admin.html or /admin/ bypasses — should be "/admin*"
```

```xml
<!-- web.xml: exact-match constraint bypassed by extension -->
<url-pattern>/api/management</url-pattern>
<!-- /api/management.html not protected -->
```

False positives to skip:
```java
// antMatcher covering path AND extension wildcard
http.authorizeRequests()
    .antMatchers("/rest", "/rest/*", "/rest.*").authenticated();

// mvcMatchers in a default Spring Boot setup (no suffix mapping)
http.authorizeRequests()
    .mvcMatchers("/rest/**").authenticated();

// requestMatchers with complete coverage
http.authorizeHttpRequests()
    .requestMatchers("/admin/**").hasRole("ADMIN");
```

For each protected path found, verify that the pattern, combined with
the other rules in the chain, leaves no extension or trailing-path
variant unprotected. If the handler at that URL requires auth and a
reachable URL variant bypasses the security rule, report it.
