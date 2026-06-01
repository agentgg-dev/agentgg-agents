---
slug: go-ssrf
name: Server-Side Request Forgery (Go)
description: 'Go HTTP requests (http.Get, http.Post, http.NewRequest) where the URL is built from string concatenation or fmt.Sprintf with caller-controlled input — SSRF risk. Follows allowlist helpers and HTTP client wrappers.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'http\.(Get|Post|Head|NewRequest)\s*\([^)]*\bfmt\.Sprintf\b'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: http.* call wrapping fmt.Sprintf URL
      - regex: 'http\.(Get|Post|Head|NewRequest)\s*\([^)]*\+'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: http.* call with concatenated URL
      - regex: \.Do\s*\(\s*req\b
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: '*http.Client.Do() — likely custom request'
      - regex: 'url\.Parse\s*\([^)]*\+'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: url.Parse on concatenated string
  prompt: Run only if this project uses go — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - go
  excludePatterns:
    - '**/*_test.go'
    - '**/vendor/**'
  preFilter:
    - regex: 'http\.(Get|Post|Head|NewRequest)\s*\([^)]*\bfmt\.Sprintf\b'
      label: http.* call wrapping fmt.Sprintf URL
    - regex: 'http\.(Get|Post|Head|NewRequest)\s*\([^)]*\+'
      label: http.* call with concatenated URL
    - regex: \.Do\s*\(\s*req\b
      label: '*http.Client.Do() — likely custom request'
    - regex: 'url\.Parse\s*\([^)]*\+'
      label: url.Parse on concatenated string
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-918
  - 'OWASP-A10:2021'
---

You are reviewing Go source code for Server-Side Request Forgery
(SSRF) — HTTP calls where the destination URL is assembled from
string concatenation, `fmt.Sprintf`, or `url.Parse` using a value
that originates from caller input (HTTP request, queue message, CLI
flag, configuration from an external source).

**Cross-file analysis:** Go projects commonly have a `pkg/httpx` or
`internal/safehttp` wrapper that enforces an allowlist or blocks
private IPs. If a candidate routes through `safehttp.Get(url)`, open
the wrapper and verify what it actually does. Trace the URL
construction back to its origin — a `tenantSlug` from a JWT claim is
different from `req.URL.Query().Get("url")`.

## What to look for

**String concatenation in URL argument:**
```go
resp, err := http.Get(baseURL + path)         // path from request
resp, err := http.Post("https://" + host + "/api", ...)
resp, err := http.Head(scheme + "://" + target)
```

**`fmt.Sprintf` URL construction:**
```go
url := fmt.Sprintf("https://%s/resource", host)
req, err := http.NewRequest("GET", fmt.Sprintf("https://api.%s/", tenant), nil)
```

**`http.NewRequest` with concatenated or formatted URL:**
```go
req, err := http.NewRequest("POST", baseURL + path, body)
req, err := http.NewRequest("GET", fmt.Sprintf("%s/users/%s", base, id), nil)
```

**`url.Parse` with concatenated string:**
```go
u, err := url.Parse(scheme + "://" + host + path)
```

**Caller-controlled input sources to trace:**
- `r.URL.Query().Get("url")`, `r.FormValue("endpoint")`,
  `r.PostFormValue("target")`
- Struct fields populated from JSON/query decode
- Function parameters named `url`, `host`, `endpoint`, `target`,
  `destination`, `callback`, `webhook`

## True positive criteria

Flag when ALL of the following hold:

1. An HTTP call is made: `http.Get`, `http.Post`, `http.Head`,
   `http.NewRequest`, or a custom `*http.Client` method.
2. The URL string is assembled with `+` concatenation, `fmt.Sprintf`,
   or `url.Parse` using a variable whose value is traceable to caller
   input.
3. No hostname allowlist, private-IP block, or DNS-validation check
   is applied to the resolved destination before the request.

## What to ignore

- `http.Get` / `http.NewRequest` where the entire URL is a hardcoded
  string literal with no variable parts.
- Template URLs where only an ID or fixed path segment is substituted
  and the base domain is a hardcoded constant:
  `fmt.Sprintf("https://api.internal/users/%s", userID)` — safe
  because the host is fixed.
- Test files (`_test.go`).
- HTTP calls to a URL loaded from a restricted config file or env var
  where the user cannot influence the value.

## Examples

True positives:
```go
// host comes from request query
host := r.URL.Query().Get("host")
resp, _ := http.Get("https://" + host + "/data")

// webhook URL from request body — caller-controlled
req, _ := http.NewRequest("POST", webhookURL, body)

// tenant subdomain from JWT claim
url := fmt.Sprintf("https://%s.partner-api.com/events", tenantSlug)
resp, _ := http.Get(url)  // if tenantSlug can be arbitrary, SSRF to *.partner-api.com is low risk, but flag for review
```

False positives to skip:
```go
// Hardcoded host — only path segment varies
url := fmt.Sprintf("https://api.example.com/users/%s", userID)
resp, _ := http.Get(url)

// Test file
func TestFetch(t *testing.T) {
    resp, _ := http.Get(ts.URL + "/echo")
}
```
