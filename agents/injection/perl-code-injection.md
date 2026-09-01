---
slug: perl-code-injection
name: Perl Code and Command Injection
description: 'Dangerous Perl patterns: eval with user input, system/exec with user-controlled commands, open() with shell metacharacters, and weak PRNG (srand/rand) for security-sensitive operations.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.pl$|\.pm$|\.cgi$'
        in:
          - '**/*.pl'
          - '**/*.pm'
          - '**/*.cgi'
          - '**/*.perl'
        notIn:
          - '**/vendor/**'
          - '**/node_modules/**'
        label: Perl source files present
where:
  extensions:
    - pl
    - pm
    - cgi
    - perl
    - pod
  excludePatterns:
    - '**/vendor/**'
    - '**/node_modules/**'
  preFilter:
    - regex: '\beval\s*[\{"''`]|\beval\s*\$'
      label: eval with variable or string
    - regex: '\bsystem\s*\(|\bexec\s*\('
      label: system/exec call
    - regex: '\bopen\s*\(\s*\w+\s*,'
      label: open() call (can execute commands with | prefix)
    - regex: '\b(?:srand|rand)\s*\('
      label: srand/rand PRNG call
    - regex: '\b(?:bind|connect|socket)\s*\('
      label: socket/network call
references:
  - CWE-78
  - CWE-94
  - CWE-338
  - 'OWASP-A03:2021'
---

You are reviewing Perl code for code injection and command injection vulnerabilities.

## Patterns to evaluate

### eval with dynamic content — critical

```perl
eval $user_input;                  # executes user input as Perl code
eval "return $cgi->param('x')";   # code injection via CGI parameter
eval { ... }                       # block eval is safe — only catches exceptions
```

The dangerous form is `eval STRING` (evaluates at runtime). Block `eval { ... }` is used for exception handling and is safe.

### system() and exec() — high

```perl
system("ls $dir");                 # OS command injection if $dir is user input
exec("/bin/cat $params{file}");    # exec with user-controlled argument
system($cgi->param('cmd'));        # direct command injection
```

Safe when called with a list (no shell interpolation):
```perl
system("/bin/ls", $dir);          # safe — passed as argv, no shell
exec("/bin/cat", $file);          # safe — no shell metacharacter expansion
```

### open() with pipe prefix — high

Perl's `open()` executes a command when the filename starts or ends with `|`:
```perl
open(OUT, "| sendmail $email");      # command injection — $email controls the command
open(IN, "$filename |");             # executes $filename as a command
open(my $fh, ">$user_path");        # file write to user-controlled path
```

Safe alternatives:
```perl
open(my $fh, '<', $filename) or die; # three-argument open — safe, no shell
```

### Weak PRNG (srand/rand) for security operations

```perl
srand(time);
my $token = rand(1000000);  # predictable: seed is just the current time
```

If `srand`/`rand` is used for generating session tokens, password reset codes, CSRF tokens, or cryptographic material — flag it. Use `/dev/urandom` or `Crypt::Random` instead.

## True positive criteria

Flag at critical:
1. `eval STRING` where the string includes CGI params (`$cgi->param(...)`, `$q->param(...)`) or environment variables from user input
2. `open(FH, "| $user_input")` or `open(FH, "$user_input |")` — two-argument open with user-controlled command

Flag at high:
3. `system("command $var")` or `exec("command $var")` where `$var` traces to CGI input — single-argument form uses shell
4. `open(FH, ">$path")` where `$path` traces to user input — arbitrary file write

Flag at medium:
5. `srand(time)` or `srand()` followed by `rand()` used for security tokens

## What to ignore

- `eval { ... }` (block form — exception handling, not code execution)
- `system("/bin/command", $arg)` (list form — no shell, safe)
- Three-argument `open(FH, '<', $path)` — safe form
- `srand`/`rand` used only for non-security purposes (random display ordering, non-secret game logic)

Report: the vulnerable Perl construct, the source of user input (CGI param, environment variable, file content), and whether the two-argument or list form of the call is used.
