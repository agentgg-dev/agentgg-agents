---
slug: lua-shared-dict-poisoning
name: Lua ngx.shared Dict Write from User Input
description: 'OpenResty ngx.shared.*:set / :add / :replace / :incr where the key or value is derived from request input — cache poisoning, counter tampering, session injection.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - lua
where:
  extensions:
    - lua
references:
  - CWE-444
  - CWE-22
---

You are reviewing OpenResty / Lua code for writes to `ngx.shared.*`
dictionaries (in-memory shared storage across worker processes)
that use caller-controlled keys or values. Failure modes:

- **Cache poisoning:** writing to `ngx.shared.cache` with a key
  derived from request data lets attackers create new entries or
  overwrite legitimate ones.
- **Rate-limit bypass:** writing to `ngx.shared.ratelimit` with a
  caller-controlled key lets attackers reset their own counter.
- **Session injection:** writing to `ngx.shared.sessions` with a
  caller-controlled session ID lets attackers seed sessions for
  other users.
- **Counter tampering:** `:incr` with an attacker-supplied delta or
  on an attacker-supplied key.

## What to look for

**`:set` / `:add` / `:replace` with request-derived key or value:**
```lua
ngx.shared.cache:set(ngx.var.arg_key, value)
ngx.shared.ratelimit:add(client_ip, 1, 60)
ngx.shared.tokens:replace("token_" .. user_id, payload)
ngx.shared.sessions:set(sid, data, 3600)
```

**`:incr` with caller-controlled delta or key:**
```lua
ngx.shared.counters:incr(metric, delta_from_request)
```

## Where keys / values become caller-controlled

- `ngx.var.arg_*`, `ngx.var.http_*` — direct from request.
- `client_ip` derived from `X-Forwarded-For` without verifying the
  upstream.
- `user_id` decoded from an unsigned cookie / header.

## True positive criteria

Flag when:
1. A write to `ngx.shared.<dict>` (set/add/replace/incr) occurs.
2. The key OR value is derived from a caller-controlled source.
3. The dictionary's purpose is security-relevant: rate limiting,
   sessions, tokens, allowlist/blocklist, counters used in auth
   decisions.

## What to ignore

- Writes to ngx.shared used for application caching of public data
  with non-sensitive keys.
- Writes where the key is fully internal (server-generated UUID).
- Test files.

## Examples

True positives:
```lua
-- Rate limit keyed on client-supplied IP
local ip = ngx.var.http_x_forwarded_for
ngx.shared.ratelimit:incr(ip, 1)

-- Session set under attacker-controlled SID
local sid = ngx.var.arg_sid
ngx.shared.sessions:set(sid, "trusted-user", 3600)
```

False positives to skip:
```lua
-- Public CDN cache, key from internal route
ngx.shared.cache:set("homepage:v1", html, 3600)

-- Authenticated user ID from verified JWT
local user_id = verified_claims.sub
ngx.shared.counters:incr("user:" .. user_id, 1)
```
