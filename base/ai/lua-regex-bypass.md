---
slug: lua-regex-bypass
name: Lua Regex / Pattern Used for Security Check (Bypassable)
description: Lua patterns or PCRE regexes used to validate URLs / hosts / paths for security decisions — Lua patterns have %z quirks, frontier patterns, and other gotchas; PCRE without anchors is bypassable.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.lua"
references:
  - CWE-1287
  - CWE-918
---

You are reviewing OpenResty / Lua code for security checks
implemented with Lua patterns or `ngx.re.match` / `ngx.re.find` /
`ngx.re.gmatch` that are bypassable.

## Why Lua patterns are tricky

- Lua patterns are NOT regular expressions. `%z` matches NUL bytes,
  `%f[set]` is a frontier match, character class behavior differs
  from regex.
- Lua patterns have no `^` / `$` anchoring by default; `string.match`
  matches anywhere unless explicitly anchored.
- Lua patterns have no alternation (`|`) — common workarounds are
  wrong.

## What to look for

**Unanchored pattern matching:**
```lua
if string.match(target, "https://trusted") then end
-- "https://evil.com?ref=https://trusted" matches!
-- Need ^https://trusted$ or ^https://trusted/

if string.find(host, "internal.host") then end
-- substring match, "evil.internal.host.attacker.com" matches
```

**Bypassable host check via dot escape:**
```lua
local valid_url = host:match(".+%.example%.com$")
-- "evil-example.com" matches (.+ greedy + literal text)

if redirect_target:match(".*allowed.com.*") then end
-- "allowed.com.evil.com" matches
```

**`ngx.re` (PCRE) without anchors:**
```lua
local ok = ngx.re.match(host, "https?://[^/]+\\.com$")
-- Better than Lua patterns, but still need full-anchor checking
```

**Use of `string.match` for security WITHOUT case-insensitive flag:**
```lua
if string.match(scheme, "^https") then end
-- "HTTPS://" passes (case sensitive), "javaScript:" still rejected
-- but be wary of mixed case bypass attempts
```

## Safe pattern

Parse the URL properly and compare components:
```lua
local resty_url = require "resty.url"
local parsed, err = resty_url.parse(input)
if not parsed or parsed.host ~= "trusted.example.com" then
  return ngx.exit(ngx.HTTP_BAD_REQUEST)
end
```

Or use anchored, restrictive patterns:
```lua
-- Allowlist a hostname exactly
local OK = { ["trusted.example.com"] = true, ["api.example.com"] = true }
if not OK[host] then return ngx.exit(ngx.HTTP_BAD_REQUEST) end
```

## True positive criteria

Flag when:
1. A Lua pattern (`string.match`, `string.find`, `:match`,
   `:find`) or `ngx.re.match` is used to validate a URL, host,
   path, scheme, or other security-relevant input.
2. The pattern lacks anchoring (`^...$`), uses unbounded wildcards
   (`.+`, `.*`) in security-significant positions, or relies on
   substring matching for an allowlist.

## What to ignore

- Patterns used for parsing/extraction (not security gates).
- Patterns properly anchored AND used only for content matching.
- Test files.

## Examples

True positives:
```lua
-- Substring match allowlist
if redirect_url:match("trusted.com") then
  return ngx.redirect(redirect_url)
end

-- Unanchored
if string.find(host, "internal.svc") then proceed() end
```

False positives to skip:
```lua
-- Exact match against allowlist
local OK = { ["trusted.example.com"] = true }
if not OK[host] then return ngx.exit(ngx.HTTP_BAD_REQUEST) end

-- Properly anchored pattern + extra checks
if host:match("^[a-z0-9-]+%.example%.com$") then ok() end
```
