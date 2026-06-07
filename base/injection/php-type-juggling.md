---
slug: php-type-juggling
name: PHP Type-Juggling Auth/Hash Bypass
description: 'PHP loose comparison (== / !=) on security-sensitive values — password/hash/token/secret checks, strcmp() loose-compared, in_array() without strict flag — allowing magic-hash and type-confusion auth bypass. Traces compared values back to their source across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(\$(pass(word)?|hash|token|secret|sig|signature|mac|hmac|digest|otp|code|key|csrf|nonce)\w*)\s*[!=]=[^=]'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/spec/**'
        label: Loose comparison on a security-sensitive variable
      - regex: 'strcmp\s*\([^)]*\)\s*==[^=]|==\s*strcmp\s*\(|strcmp\s*\([^)]*\)\s*!=[^=]'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/spec/**'
        label: strcmp() result loose-compared (null on array, 0 falsy)
      - regex: 'in_array\s*\([^)]*\)(?!\s*,\s*true)'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/spec/**'
        label: in_array() call (check for missing strict flag)
      - regex: '[!=]=\s*(md5|sha1|hash|crypt|password_hash|bin2hex)\s*\(|(md5|sha1|hash|crypt)\s*\([^)]*\)\s*[!=]=[^=]'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
          - '**/spec/**'
        label: Digest function result loose-compared (use hash_equals)
where:
  extensions:
    - php
  excludePatterns:
    - '**/vendor/**'
    - '**/tests/**'
    - '**/spec/**'
    - '**/node_modules/**'
  preFilter:
    - regex: '(\$(pass(word)?|hash|token|secret|sig|signature|mac|hmac|digest|otp|code|key|csrf|nonce)\w*)\s*[!=]=[^=]'
      label: Loose comparison on a security-sensitive variable
    - regex: 'strcmp\s*\([^)]*\)\s*==[^=]|==\s*strcmp\s*\(|strcmp\s*\([^)]*\)\s*!=[^=]'
      label: strcmp() result loose-compared
    - regex: 'in_array\s*\([^)]*\)(?!\s*,\s*true)'
      label: in_array() without strict flag
    - regex: '[!=]=\s*(md5|sha1|hash|crypt|password_hash|bin2hex)\s*\(|(md5|sha1|hash|crypt)\s*\([^)]*\)\s*[!=]=[^=]'
      label: Digest function result loose-compared
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-697
  - CWE-1025
---

You are reviewing PHP source for type-juggling authentication and
hash-comparison bypass — PHP's loose comparison operators (`==`, `!=`)
coerce operands before comparing, so an attacker who controls one side
can make a security check pass with a value that is not actually equal.
The classic outcomes are auth bypass and signature/token forgery.

**Cross-file analysis:** the comparison is often a few hops from the
input. A controller compares `$user->password` against a value that
traces back to `$_POST['password']` through a model or service. Open
the function that produces each operand and confirm whether one side
is attacker-controlled and whether the other is a stored hash, token,
or secret. The danger is in the *operator*, but the impact depends on
the *source* of the operands.

## What to look for

- Loose comparison on secrets:
  ```php
  if ($_GET['token'] == $storedToken) { ... }
  if ($password == $row['password']) { grant(); }
  ```
  With `==`, the string `"0e123"` magic-hash equals another `0e...`
  string numerically, and `"0" == "0e..."` style coercions apply.
- `strcmp()` result loose-compared. `strcmp($a, $b) == 0` is the
  intended "equal" check, but if `$a` is an array, `strcmp` returns
  `NULL` and `NULL == 0` is `true` — passing an array (`token[]=x`)
  bypasses the check:
  ```php
  if (strcmp($_POST['password'], $real) == 0) { login(); }
  ```
- Digest functions loose-compared (magic hashes). When the *plaintext*
  is attacker-chosen, an `md5`/`sha1` digest that starts `0e` followed
  by all digits is treated as scientific notation `0`, so two distinct
  magic-hash inputs compare equal:
  ```php
  if (md5($_GET['code']) == md5($_GET['guess'])) { ... }
  if ($hash == "0e1137126905") { ... }
  ```
- `in_array($needle, $haystack)` without the third `true` (strict)
  argument — `in_array("1abc", [1,2,3])` is `true` via coercion; with
  an allowlist of tokens/IDs this lets an attacker match a value that
  is not in the list.
- Digest equality that should use `hash_equals()` for constant-time,
  type-safe comparison but uses `==`/`===` on raw strings instead
  (constant-time matters for HMAC/signature checks).

## True positive criteria

A finding is real when one operand of a loose comparison (or a
loose-compared `strcmp`/digest result, or a non-strict `in_array`) is
attacker-controlled AND the other side is a security gate — a stored
password/hash, an API token or session token, an HMAC/signature, a
CSRF token, or an authorization allowlist.

You must be able to say: "I am an unauthenticated client. I can send
`token=0e1234...` (or `token[]=x` to make strcmp return NULL), and
because the check uses `==` the comparison evaluates true, so I pass
the gate without the real secret." Name the attacker and the trust
boundary (the request parameter). The burden is on the code to prove
the comparison is type-safe (`===`, `hash_equals`, or `in_array(...,
true)`); if it can't, flag it.

## What to ignore

- Comparisons that already use strict `===` / `!==`, or `hash_equals`,
  or `in_array($x, $arr, true)`.
- Loose comparison of values that are not security-sensitive and not
  attacker-controlled (counters, flags, internal status enums).
- `==` against a hardcoded non-numeric, non-magic constant where
  neither operand is attacker-controlled.
- Comparisons where both operands are cast/validated to a fixed type
  upstream (e.g. `(int)$id == $row['id']` where ids are ints, or the
  input passed `ctype_xdigit()` and a length check before compare).
- `password_verify($plain, $hash)` — this is the correct API and is
  not a loose comparison.

## Examples

True positives:
```php
if ($_POST['password'] == $user['password']) { login(); }

if (strcmp($_GET['api_key'], API_KEY) == 0) { authorize(); }

if (md5($_GET['key']) == $stored) { reset_admin_pw(); }

if (in_array($_GET['role'], $adminRoles)) { grantAdmin(); }
```

False positives to skip:
```php
if (hash_equals($expectedHmac, $providedHmac)) { ... }

if ($_POST['password'] === $user['password']) { ... }

if (password_verify($_POST['password'], $user['hash'])) { ... }

if (in_array($_GET['role'], $adminRoles, true)) { ... }
```

If a loose comparison sits on the path between a request value and a
secret, treat it as a finding unless the code demonstrably forces both
operands to the same type before comparing.
