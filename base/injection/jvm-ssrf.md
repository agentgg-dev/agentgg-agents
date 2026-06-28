---
slug: jvm-ssrf
name: Server-Side Request Forgery (JVM)
description: 'Java HTTP client calls (java.net.URL, HttpURLConnection, RestTemplate, WebClient, Apache HttpClient, OkHttp) where the URL is user-controlled — allows probing internal networks, cloud metadata endpoints, or triggering SSRF via XML entity resolution. Traces URL construction and checks for allowlist validation.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'new\s+URL\s*\(\s*[^")][^)]*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: java.net.URL constructed with variable (not string literal)
      - regex: 'restTemplate\.(getForObject|getForEntity|postForObject|postForEntity|exchange|execute)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring RestTemplate HTTP call
      - regex: 'WebClient\.(create|builder)\s*\(\s*\)|\.uri\s*\(\s*[^")][^)]*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring WebClient with variable URI
      - regex: 'new\s+HttpGet\s*\(|new\s+HttpPost\s*\(|new\s+HttpPut\s*\(|new\s+HttpDelete\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Apache HttpClient request construction
      - regex: 'new\s+Request\.Builder\s*\(\)|\.url\s*\(\s*[^")][^)]*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: OkHttp Request.Builder with variable URL
      - regex: 'HttpRequest\.newBuilder\s*\(\)|URI\.create\s*\([^")][^)]*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Java 11 HttpClient / URI.create with variable
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
    - regex: 'new\s+URL\s*\([^)]*\)\s*\.\s*(openConnection|openStream|getContent)\s*\('
      label: java.net.URL.openConnection/openStream with variable
    - regex: 'restTemplate\.(getForObject|getForEntity|postForObject|postForEntity|exchange|execute)\s*\('
      label: Spring RestTemplate HTTP call
    - regex: 'WebClient\.(create|builder)\s*\(\s*\)|\.uri\s*\(\s*[^")][^)]*\)'
      label: Spring WebClient with variable URI
    - regex: 'new\s+HttpGet\s*\(|new\s+HttpPost\s*\(|new\s+HttpPut\s*\(|new\s+HttpDelete\s*\('
      label: Apache HttpClient request construction
    - regex: 'new\s+Request\.Builder\s*\(\)|\.url\s*\(\s*[^")][^)]*\)'
      label: OkHttp Request.Builder with variable URL
    - regex: 'HttpRequest\.newBuilder\s*\(\)|URI\.create\s*\([^")][^)]*\)'
      label: Java 11 HttpClient / URI.create with variable
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-918
  - 'OWASP-A10:2021'
---

You are reviewing JVM source code (Java / Kotlin) for Server-Side Request
Forgery (SSRF) — server-side HTTP calls whose URL is influenced by user
input, letting an attacker make the server issue requests to internal
networks, cloud metadata endpoints (169.254.169.254), or localhost services.

Java SSRF is structurally the same as Node.js SSRF but the APIs differ.
A common GeoServer/GeoTools pattern is a REST API that accepts a `url`
parameter to load a remote resource (coverage file, WMS GetMap legend,
data store URL) without checking whether the URL resolves to an internal
address.

**XML entity SSRF:** A secondary path exists via XML parser entity
resolution — when an XML document containing `<!ENTITY ext SYSTEM "http://...">` 
is parsed and entities are resolved, the parser makes an outbound HTTP
request on behalf of the attacker. Check the `xxe` agent for that pattern;
here focus on explicit HTTP client calls.

**Cross-file analysis:** the URL is often passed through a service layer.
A REST endpoint accepts a `fileUrl` body field and calls a utility method;
the utility eventually calls `new URL(fileUrl).openStream()`. Read the
utility before deciding whether validation occurs.

## What to look for

**java.net.URL / HttpURLConnection:**
```java
String fileUrl = request.getParameter("url");
URL u = new URL(fileUrl);
InputStream in = u.openStream();              // fetches arbitrary URL

HttpURLConnection conn = (HttpURLConnection) u.openConnection();
conn.setRequestMethod("GET");
conn.connect();
```

**Spring RestTemplate:**
```java
String target = req.getParam("endpoint");
Object result = restTemplate.getForObject(target, ResponseBody.class);
ResponseEntity<byte[]> resp = restTemplate.exchange(target, HttpMethod.GET, null, byte[].class);
```

**Spring WebClient (reactive):**
```java
String uri = body.getCallbackUrl();
Mono<String> resp = webClient.get().uri(uri).retrieve().bodyToMono(String.class);
```

**Apache HttpClient 4.x / 5.x:**
```java
String url = request.getParameter("serviceUrl");
CloseableHttpClient client = HttpClients.createDefault();
HttpGet get = new HttpGet(url);              // url can be ldap:// or file://
client.execute(get);
```

**OkHttp:**
```java
String target = body.getFileUrl();
Request req = new Request.Builder().url(target).build();
client.newCall(req).execute();
```

**Java 11 HttpClient:**
```java
HttpRequest httpReq = HttpRequest.newBuilder()
    .uri(URI.create(userSuppliedUrl))
    .build();
client.send(httpReq, HttpResponse.BodyHandlers.ofString());
```

**URL parameter in a REST "fetch by URL" endpoint:**
```java
// GeoServer-style: /coveragestores/{name}/url.json — method=url, fileURL from body
String fileURL = params.get("fileURL");
// Missing: URLCheckers.confirm(fileURL)
downloadAndStore(new URL(fileURL));
```

## True positive criteria

Flag when ALL of the following hold:

1. A Java HTTP client constructs a request from a URL argument.
2. The URL argument is, transitively, user-controlled: a request
   parameter, REST body field, URL path segment, or a database record
   the user can write.
3. No host allowlist or private-IP block is applied before the request.
   A safe check validates the resolved hostname against a permitted set
   AND blocks private/link-local ranges: `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`.

## What to ignore

- URLs built from a fixed base URL with the user-supplied segment used
  only as a path/query component, where the host is a server-controlled
  constant:
  ```java
  String id = request.getParameter("id");
  restTemplate.getForObject(FIXED_API_BASE + "/items/" + sanitizedId, Item.class);
  ```
- Requests that go through a validated URL-checker utility whose body you
  have confirmed checks the host against an allowlist AND blocks private ranges.
- URLs sourced from operator-controlled configuration (environment variables,
  application.properties) where users cannot write the value.
- Test code under `src/test/`.
- `file://`, `jar://` URLs used for classpath resource loading in a context
  where the path is server-controlled.

## Examples

True positives:
```java
// GeoServer Coverage REST — no URLCheckers.confirm()
String fileURL = request.getParameter("fileURL");
IOUtils.copy(new URL(fileURL).openStream(), outputStream);

// Webhook delivery with user-supplied callback
String callback = subscription.getCallbackUrl();   // user-authored
restTemplate.postForObject(callback, payload, Void.class);

// Data store JDBC URL supplied by admin user — accepts ldap://
String jdbcUrl = adminBody.getConnectionUrl();
new URL(jdbcUrl).openConnection();   // protocol not validated
```

False positives to skip:
```java
// Fixed host — user controls only path segment validated with regex
String layer = request.getParameter("layer");
if (!layer.matches("^[a-zA-Z0-9_:-]+$")) throw new BadRequestException();
restTemplate.getForObject(INTERNAL_WMS_BASE + "?layers=" + layer, byte[].class);

// URL from operator config
String apiBase = env.getProperty("upstream.api.url");
restTemplate.getForObject(apiBase + "/health", String.class);
```

If a user-supplied string is used as, or forms the host portion of, a URL
passed to any Java HTTP client without host allowlisting and private-range
blocking, treat it as a finding.
