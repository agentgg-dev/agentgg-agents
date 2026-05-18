---
slug: response-header-leak
name: Response Headers Leaking Infrastructure Details
description: Response headers exposing server identity (X-Powered-By, Server) or internal debug info (X-Debug, X-Internal-Trace, X-Trace-Id) — fingerprints attackers use for targeted exploits.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs,lua,go,conf}"
references:
  - CWE-200
  - OWASP-A05:2021
---

You are reviewing source code for HTTP response headers that leak
internal infrastructure details — server identity, version numbers,
debug flags, internal trace IDs — to clients.

## What to look for

**Server identity headers:**
```ts
res.setHeader("X-Powered-By", "Express");
res.setHeader("Server", "nginx/1.21.0");
response.setHeader("server", "apache");
```
Should be removed. Express has `app.disable("x-powered-by")`.

**Debug headers leaked to clients:**
```ts
res.setHeader("X-Debug", "true");
res.setHeader("X-Internal-Trace", traceId);
res.setHeader("X-Trace-Id", id);
```
Internal trace IDs should not be in client-visible response headers
unless your support flow specifically uses them (and then only the
ID, not internal state).

**Nginx configuration:**
```
add_header server_version $server_version;
add_header X-Debug "1";
```

**Lua / OpenResty:**
```lua
ngx.header["x-debug-info"] = "yes"
```

**Go:**
```go
w.Header().Set("X-Debug", "true")
w.Header().Set("Server", "Custom/1.0")
```

## True positive criteria

Flag when a response sets:

1. `X-Powered-By` to any non-empty value.
2. `Server` header to anything other than removing it.
3. `X-Debug`, `X-Internal`, `X-Internal-Trace`, `X-Trace-Id`,
   `X-Debug-Info` or similar internal-named headers in a
   production-reachable response.
4. Nginx `add_header server_version` or `add_header X-Debug`.

## What to ignore

- Setting headers to empty / removing them: `app.disable("x-powered-by")`,
  `res.removeHeader("X-Powered-By")`.
- Standard security headers (`Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options`) — these are good.
- `X-Request-Id` / `X-Correlation-Id` — these are typically opaque
  IDs and acceptable.
- Test / mock servers.

## Examples

True positives:
```ts
// Powered-By leak
res.setHeader("X-Powered-By", "Next.js/14.0");

// Internal trace ID leaked
app.use((req, res, next) => {
  res.setHeader("X-Internal-Trace", req.context.traceId);
  next();
});
```

```nginx
add_header X-Debug "1";
add_header server_version $server_version;
```

False positives to skip:
```ts
// Removing the header
app.disable("x-powered-by");
res.removeHeader("X-Powered-By");

// Standard security headers
res.setHeader("Strict-Transport-Security", "max-age=31536000");
res.setHeader("X-Frame-Options", "DENY");

// Opaque request ID for client support
res.setHeader("X-Request-Id", crypto.randomUUID());
```
