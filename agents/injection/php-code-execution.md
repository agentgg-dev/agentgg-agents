---
slug: php-code-execution
name: PHP Remote Code Execution Sinks
description: 'PHP code execution sinks (eval, exec, system, passthru, assert, backtick operator, registerPHPFunctions, import_request_variables, parse_str) called with user-supplied input, enabling server-side code execution.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bassert\s*\('
        in:
          - '**/*.{php,php3,php4,php5,phtml}'
        notIn:
          - '**/vendor/**'
          - '**/node_modules/**'
        label: PHP dangerous code execution function present
where:
  extensions:
    - php
    - php3
    - php4
    - php5
    - phtml
    - inc
  excludePatterns:
    - '**/vendor/**'
    - '**/node_modules/**'
  preFilter:
    - regex: '(?i)\beval\s*\('
      label: eval() call
    - regex: '(?i)\bexec\s*\(|\bsystem\s*\(|\bpassthru\s*\(|\bshell_exec\s*\('
      label: exec/system/passthru/shell_exec call
    - regex: '(?i)\bassert\s*\(\s*\$'
      label: assert() with variable argument (PHP < 8 executes as eval)
    - regex: '`[^`]*\$(?:_GET|_POST|_REQUEST|_COOKIE)'
      label: backtick operator with user input
    - regex: '(?i)registerPHPFunctions\s*\('
      label: registerPHPFunctions (allows PHP code in XSLT)
    - regex: '(?i)import_request_variables\s*\('
      label: import_request_variables (deprecated, writes globals)
    - regex: '(?i)(?:parse_str|mb_parse_str)\s*\('
      label: parse_str/mb_parse_str (writes to local scope)
    - regex: '\$_(GET|POST|REQUEST|COOKIE|SERVER)\['
      label: Superglobal user input accessed
references:
  - CWE-94
  - CWE-78
  - 'OWASP-A03:2021'
---

You are reviewing PHP code for sinks that execute code or commands, especially when user input is involved.

## Sinks to evaluate

### eval() — critical

Executes a string as PHP code. Any user input reaching eval() is RCE.
```php
eval($_GET['code']);                     // direct RCE
eval(base64_decode($_POST['data']));     // obfuscated but still RCE
eval('$x = ' . $_REQUEST['val'] . ';'); // injection into eval string
```

### exec() / system() / passthru() / shell_exec()

Execute OS commands. User input in the command string is OS command injection.
```php
system("ls " . $_GET['dir']);           // command injection
exec($_POST['cmd'], $out);              // direct command injection
passthru("cat " . $filename);          // if $filename traces to user input
```

### assert() with string argument (PHP < 8)

In PHP 5.x/7.x, `assert(string)` evaluates the string as PHP code:
```php
assert($_GET['test']);       // RCE in PHP < 8
assert("$_GET[test]");      // also RCE
```
PHP 8 removed this behavior, so flag only if the codebase is PHP < 8 or the assertion receives a variable argument.

### Backtick operator

Backticks execute OS commands like `shell_exec()`:
```php
$out = `ls {$_GET['dir']}`;   // command injection
```

### registerPHPFunctions()

Used with XSLT to call arbitrary PHP functions from an XSL stylesheet:
```php
$xslt->registerPHPFunctions();  // allows any PHP function call from XSL — flag unconditionally
```

### import_request_variables() (PHP 4/5, deprecated)

Writes GET/POST/COOKIE values directly into local or global scope:
```php
import_request_variables('gp');  // $_GET and $_POST become local variables — RCE if extract() or eval() is downstream
```

### parse_str() / mb_parse_str()

Write query string values into the current symbol table without a second argument:
```php
parse_str($_SERVER['QUERY_STRING']);  // pollutes local scope with user-controlled variable names
```

## True positive criteria

Flag at critical:
1. `eval()` receives any data traceable to user input
2. `exec()`/`system()`/`passthru()` with user input concatenated into the command
3. `assert(string)` where the string traces to user input (PHP < 8)
4. Backtick operator with user input

Flag at high:
5. `registerPHPFunctions()` called in any XSLT context — allows arbitrary PHP calls from the stylesheet
6. `import_request_variables()` used anywhere — deprecated and always unsafe
7. `parse_str($_SERVER['QUERY_STRING'])` or `parse_str($userInput)` without second argument — pollutes scope

## What to ignore

- `eval()` with hardcoded constant strings only
- `exec()` with commands built entirely from server-side constants
- `parse_str($query, $result)` with two arguments — writes to the second variable, not scope

Report: the sink function, the source of user input, and any encoding/decoding applied before the call (base64, rot13, gzinflate — these are common webshell obfuscation techniques and raise severity).
