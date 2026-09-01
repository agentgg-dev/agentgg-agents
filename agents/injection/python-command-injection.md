---
slug: python-command-injection
name: Python Command Injection
description: 'User-controlled data passed to Python shell-execution APIs (os.system, subprocess with shell=True, os.popen, commands.getoutput) without sanitization, enabling OS command injection.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'import\s+os\b|from\s+os\s+import|import\s+subprocess\b|from\s+subprocess\s+import|import\s+commands\b'
        in:
          - '**/*.py'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
        label: os or subprocess module imported in Python files
where:
  extensions:
    - py
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/*test*'
    - '**/*_test.py'
  preFilter:
    - regex: 'os\.system\('
      label: os.system call
    - regex: 'os\.popen\d?\('
      label: os.popen call
    - regex: 'subprocess\.(?:call|run|Popen)\('
      label: subprocess call/run/Popen
    - regex: 'commands\.getoutput\('
      label: commands.getoutput (deprecated Python 2)
    - regex: 'shell\s*=\s*True'
      label: shell=True in subprocess
references:
  - CWE-78
  - 'OWASP-A03:2021'
---

You are reviewing Python code for OS command injection. The risk: user-controlled data concatenated into shell commands allows arbitrary command execution on the server.

## Dangerous patterns

### os.system / os.popen

```python
os.system("ping " + user_input)       # command injection
os.popen("ls " + request.args['dir']) # command injection
```

### subprocess with shell=True

When `shell=True`, the command is passed to `/bin/sh -c` and the entire string is shell-interpreted:
```python
subprocess.call("grep " + user_input, shell=True)   # command injection
subprocess.run(f"cat {filename}", shell=True)        # command injection
```

`shell=False` (the default) with a list argument is safe even with user input:
```python
subprocess.run(["grep", user_input, filename], shell=False)  # safe
```

### commands.getoutput (Python 2, deprecated)

```python
output = commands.getoutput("id " + user_input)  # command injection
```

## True positive criteria

Flag when ANY of these hold:
1. User input (from `request.args`, `request.form`, `request.data`, `request.json`, environment variables the user controls, CLI args without validation) flows into `os.system()`, `os.popen()`, `commands.getoutput()`
2. User input flows into a `subprocess` call with `shell=True`
3. User input is string-interpolated into the shell command string (f-string, `.format()`, `%` formatting, or `+` concatenation)

Flag at lower severity: subprocess with `shell=True` and constant command string (no user input) — still bad practice but not directly exploitable.

## What to ignore

- `subprocess.run([...], shell=False)` with user input in list args — safe
- `os.system()` called with a fully hardcoded constant string — no injection vector
- Commands built from environment variables that are not user-settable

Report: the function called, where the user input originates, how it's inserted into the command (concatenation, f-string, etc.), and whether any sanitization (shlex.quote, allowlist) is applied.
