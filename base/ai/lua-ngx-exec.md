---
slug: lua-ngx-exec
name: Lua ngx.exec / os.execute / io.popen with User Input
description: OpenResty ngx.exec / ngx.redirect / os.execute / io.popen called with caller-controlled input — internal subroute hijack, open redirect, or shell command injection.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.lua"
references:
  - CWE-78
  - CWE-601
---

You are reviewing OpenResty / Lua code for `ngx.exec`, `ngx.redirect`,
`os.execute`, and `io.popen` calls that use caller-controlled
arguments. Each is a different sink:

- `ngx.exec("@upstream" .. x)` — internal redirect to a named
  location. With caller-controlled input, can target arbitrary
  internal subroutes.
- `ngx.redirect(...)` — HTTP redirect. Caller-controlled URL =
  open redirect.
- `os.execute(cmd)` — runs a shell command. Caller-controlled `cmd`
  = command injection / RCE.
- `io.popen(cmd)` — same as `os.execute` for command injection.

## What to look for

**ngx.exec with concatenation:**
```lua
ngx.exec("@upstream_" .. ngx.var.arg_target)
ngx.exec("/internal" .. user_path)
```

**ngx.redirect with caller-controlled URL:**
```lua
ngx.redirect("https://example.com/" .. ngx.var.arg_redirect)
ngx.redirect(ngx.var.arg_next)
```

**os.execute / io.popen with user input:**
```lua
os.execute("rm -rf " .. dir)
local fh = io.popen("convert " .. user_file)
```

**ngx.location.capture (intra-server subrequest) with controlled
target:**
```lua
local res = ngx.location.capture("/proxy/" .. arg_target)
```

## True positive criteria

Flag when:
1. `ngx.exec`, `ngx.redirect`, `os.execute`, `io.popen`, or
   `ngx.location.capture` is called with a `..`-concatenated
   argument.
2. Any concatenated operand is caller-controlled (`ngx.var.arg_*`,
   `ngx.req.get_*_args`, `ngx.var.http_*`).
3. No strict allowlist / regex validation appears before the call.

## What to ignore

- Calls with fully hardcoded targets.
- Calls where the input is validated against a strict allowlist on
  the same path.
- Test files.

## Examples

True positives:
```lua
local target = ngx.var.arg_target
ngx.exec("@backend_" .. target)

local cmd = "convert " .. ngx.var.arg_file
os.execute(cmd)

ngx.redirect(ngx.var.arg_next)
```

False positives to skip:
```lua
local ALLOWED = { backend_a = true, backend_b = true }
local target = ngx.var.arg_target
if not ALLOWED[target] then return ngx.exit(ngx.HTTP_BAD_REQUEST) end
ngx.exec("@backend_" .. target)
```
