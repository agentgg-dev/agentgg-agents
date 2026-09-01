---
slug: webshell-php
name: PHP Webshell Detection
description: 'PHP webshell patterns: one-liner code execution via eval/exec/passthru/assert with user input, gzuncompress+base64_decode decode chains, variable function calls with superglobals, and Reflection API abuse — indicators of a backdoor in committed PHP files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)\bgzuncompress\s*\(\s*base64_decode|\$\w+\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)|(?i)(?:new\s+ReflectionFunction|new\s+ReflectionClass)'
        in:
          - '**/*.{php,php3,php4,php5,phtml}'
        notIn:
          - '**/vendor/**'
        label: PHP webshell signature patterns present
where:
  extensions:
    - php
    - php3
    - php4
    - php5
    - phtml
    - cgi
    - inc
  excludePatterns:
    - '**/vendor/**'
    - '**/node_modules/**'
  preFilter:
    - regex: '(?i)\b(?:passthru|eval|exec|system|phpinfo|assert|call_user_func|call_user_func_array)\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)'
      label: Dangerous function called directly with superglobal user input
    - regex: '(?i)gzuncompress\s*\(\s*base64_decode\s*\('
      label: gzuncompress(base64_decode(...)) — webshell decode chain
    - regex: '\$\w+\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)\s*\['
      label: Variable function call with user input as argument
    - regex: '(?i)new\s+(?:ReflectionFunction|ReflectionClass)\s*\('
      label: Reflection API usage
    - regex: '(?i)cmdshell|c99shell|r57shell'
      label: Known webshell keyword
    - regex: '(?i)0x647261646e617473|65786563'
      label: Hex-encoded dangerous string (sandratic/exec obfuscation)
references:
  - CWE-506
  - CWE-94
---

You are reviewing PHP files for webshell indicators. Webshells are backdoor scripts allowing remote command execution via HTTP requests. They are often obfuscated to evade detection.

## High-confidence patterns

### Direct superglobal execution — critical

```php
eval($_GET['cmd']);
system($_POST['c']);
assert($_REQUEST['x']);
call_user_func($_COOKIE['fn'], $_GET['arg']);
```

These are direct one-liner webshells. No legitimate application code passes raw user input straight to these functions.

### Decode + execute chain — critical

```php
eval(gzuncompress(base64_decode($encoded)));
eval(str_rot13(base64_decode($obf)));
@eval(gzinflate(base64_decode('...')));
```

Multi-layer encoding to hide a payload. The `@` error suppressor is a secondary indicator.

### Variable function call with user input — critical

```php
$fn = $_GET['func'];
$fn($_POST['arg']);  // executes any PHP function named by the user
```

This pattern routes the HTTP request to any PHP built-in or user-defined function.

### Reflection API abuse — high

```php
new ReflectionFunction($_GET['func']);
$r = new ReflectionClass($_GET['class']);
$r->newInstance();
```

Legitimate use of Reflection exists (ORMs, DI containers) but only on internal class names, not user-controlled strings.

### Known webshell keywords

- `c99shell`, `r57shell`, `cmdshell` — webshell family names
- Hex strings encoding dangerous words: `0x647261646e617473` = "sandratic", `65786563` = "exec"

## True positive criteria

Flag at critical:
1. Any of the direct superglobal execution patterns above
2. Multi-layer decode+eval chains in PHP source files

Flag at high:
3. Variable function calls where the function name comes from user input
4. Reflection API instantiation on user-controlled class/function names
5. Known webshell keywords or obfuscated hex strings

## Context matters

Check where the file lives in the repo:
- A webshell in `uploads/` or `public/tmp/` with no other PHP files nearby is extremely suspicious
- A webshell in a test file that also contains unit tests is lower severity (but still flag it)
- Framework files in `vendor/` are excluded — third-party code is out of scope

Also look for: file creation timestamps inconsistent with surrounding files, single-file PHP with no class declarations, error suppression (`@`) on dangerous calls.

Report: the pattern found, the file path (especially if in a uploads or public directory), the obfuscation technique used (base64, gzip, rot13, hex), and whether the file appears to be standalone or part of the application codebase.
