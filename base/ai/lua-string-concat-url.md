---
slug: lua-string-concat-url
name: Lua / OpenResty URL Built by String Concatenation
description: 'OpenResty / Nginx-Lua code that builds URLs by concatenating ngx.var, ngx.req fields, or request arguments — SSRF / open-redirect / URL injection.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - lua
where:
  extensions:
    - lua
references:
  - CWE-918
  - CWE-601
---

You are reviewing OpenResty / Nginx-Lua code for URLs built by
concatenating request-derived values. The destination URL can be
redirected by the caller, leading to SSRF (when the URL is fetched)
or open redirect (when issued as `ngx.redirect`).

## What to look for

**URL built by `..` concatenation with request values:**
```lua
local target = "http://internal.svc/v1/" .. ngx.var.arg_id
local endpoint = path .. "https://upstream.local/data"
local res = ngx.location.capture("/proxy/" .. backend_id)
request_uri = "/api/" .. tenant_id .. "/users"
local u = base .. "https://service" .. suffix
```

**Sources of caller-controlled values in OpenResty:**
- `ngx.var.arg_*` — query parameters
- `ngx.var.http_*` — request headers (e.g., `ngx.var.http_host`)
- `ngx.var.request_uri` — full request URI
- `ngx.req.get_uri_args()`, `ngx.req.get_post_args()`,
  `ngx.req.get_headers()`
- `ngx.var.remote_addr` (rare, but client-supplied if behind a
  misconfigured proxy)

## Safe pattern

Build URLs from validated, internal values. Validate any caller-
supplied segment against a strict allowlist or regex:
```lua
local id = ngx.var.arg_id
if not id or not id:match("^[A-Za-z0-9-]+$") then
  ngx.exit(ngx.HTTP_BAD_REQUEST)
end
local target = "http://internal.svc/v1/" .. id
```

## True positive criteria

Flag when:
1. A URL string is built with `..` concatenation.
2. Any concatenated operand comes from `ngx.var.arg_*`,
   `ngx.req.get_*_args`, `ngx.var.http_*`, or another caller-
   supplied source.
3. No allowlist / regex validation appears on the path between
   reading the value and using it in the URL.

## What to ignore

- URLs built entirely from internal Lua variables / constants /
  shared dict values that aren't request-derived.
- Test files (`_test.lua`, `_spec.lua`).
- Values validated against a strict regex before use.

## Examples

True positives:
```lua
local id = ngx.var.arg_id
local res = ngx.location.capture("/proxy/" .. id)

local host = ngx.var.http_host
local url = "https://" .. host .. "/internal"
ngx.redirect(url)
```

False positives to skip:
```lua
local id = ngx.var.arg_id
if not id or not id:match("^[A-Za-z0-9-]+$") then
  return ngx.exit(ngx.HTTP_BAD_REQUEST)
end
local res = ngx.location.capture("/proxy/" .. id)
```
