---
slug: ssrf
name: Server-Side Request Forgery
description: Server-side HTTP/network requests whose destination is taken from user input without validation, letting an attacker reach internal services, cloud metadata, or arbitrary hosts.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: "\\b(fetch|axios|got|request|urllib|requests\\.(get|post)|http\\.(get|request)|httpClient)\\b"
        in:
          - "**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go}"
        notIn:
          - "**/*.{test,spec}.*"
        label: "outbound HTTP client call present"
where:
  extensions: [ts, tsx, js, jsx, mjs, cjs, py, rb, go]
  excludePatterns:
    - "**/__tests__/**"
    - "**/*.{test,spec}.*"
  preFilter:
    - regex: "(fetch|axios|got|request|http\\.get|requests\\.(get|post))\\s*\\([^)]*(req\\.|request\\.|params|body|query|input|url)"
      label: "HTTP call with request-derived destination"
    - regex: "new URL\\s*\\([^)]*(req\\.|request\\.|params|body|query|input)"
      label: "URL constructed from request input"
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-918
  - OWASP-A10:2021
---

You are reviewing for server-side request forgery: code that makes an
outbound network request to a destination the caller controls, with
no allowlist or validation of the target host.

The destination often passes through a helper (`httpClient(url)`,
`proxyRequest(opts)`). When a flagged call takes a request-derived
URL, use Read/Grep to follow it and confirm whether any host
validation happens before the request is issued.

## Flag

```ts
const r = await fetch(req.query.url);                 // attacker picks the host
const img = await axios.get(`${req.body.endpoint}/x`);
requests.get(request.GET["target"])                   # python
```
Especially dangerous when the target can reach `169.254.169.254`
(cloud metadata), `localhost`, or internal IP ranges.

## Skip

- Requests to a hardcoded/config host where only a path segment is
  user-controlled.
- Code that validates the URL against an allowlist of hosts, or
  resolves+checks the IP isn't private, before requesting.
- Client-side-only code.

A finding needs a user-controlled destination AND the absence of
effective host validation on the path to the request.
