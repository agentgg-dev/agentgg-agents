---
slug: rce
name: Remote Code Execution (eval / exec)
description: 'eval(), new Function(), child_process.exec with a shell, vm.runInContext, and Python/Ruby equivalents with user-controlled input — allows arbitrary code execution. Walker mode traces the argument origin.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '\beval\s*\(\s*(?![''"][^''"]*[''"]\s*\))'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: eval() with non-literal argument
      - regex: new\s+Function\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: new Function() — runtime code construction
      - regex: vm\.(runInNewContext|runInThisContext|runInContext|Script)\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: vm.* — Node VM module (not a sandbox)
      - regex: '\bexec(Sync)?\s*\(\s*[`"''][^`"'']*\$\{|\bexec(Sync)?\s*\([^)]*\+'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: child_process.exec/execSync with interpolation/concat
      - regex: 'spawn\s*\([^)]*\bshell\s*:\s*true\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'spawn({ shell: true }) — invokes a shell'
      - regex: 'os\.system\s*\([^)]*[+%]|os\.system\s*\(\s*f[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Python os.system with formatting/concat
      - regex: 'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Python subprocess with shell=True
      - regex: '\beval\s*\(|\bexec\s*\(\s*[a-zA-Z_]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{py,rb}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/test_*.py'
          - '**/spec/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Python eval()/exec() with variable
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/spec/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '\beval\s*\(\s*(?![''"][^''"]*[''"]\s*\))'
      label: eval() with non-literal argument
    - regex: new\s+Function\s*\(
      label: new Function() — runtime code construction
    - regex: vm\.(runInNewContext|runInThisContext|runInContext|Script)\s*\(
      label: vm.* — Node VM module (not a sandbox)
    - regex: '\bexec(Sync)?\s*\(\s*[`"''][^`"'']*\$\{|\bexec(Sync)?\s*\([^)]*\+'
      label: child_process.exec/execSync with interpolation/concat
    - regex: 'spawn\s*\([^)]*\bshell\s*:\s*true\b'
      label: 'spawn({ shell: true }) — invokes a shell'
    - regex: 'os\.system\s*\([^)]*[+%]|os\.system\s*\(\s*f[''"]'
      label: Python os.system with formatting/concat
    - regex: 'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True'
      label: Python subprocess with shell=True
    - regex: '\beval\s*\(|\bexec\s*\(\s*[a-zA-Z_]'
      label: Python eval()/exec() with variable
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-94
  - CWE-78
  - 'OWASP-A03:2021'
---

You are reviewing source code for remote code execution sinks —
functions that evaluate a string as code or spawn a shell command
built from user input.

**Walker mode advantage:** the dangerous argument is often built one
or two function calls upstream. Trace the variable: a `cmd` passed to
`exec(cmd)` may be assembled from `req.body.action` in a helper. The
walker should follow the call graph and confirm the trust boundary
crossing.

## What to look for

**JavaScript / TypeScript — eval and dynamic code:**
- `eval(userInput)` — evaluates a JS expression. Any user-controlled
  value reaching `eval()` is code execution.
- `new Function("return " + body)()` / `new Function(params, body)` —
  same semantics as eval but harder to spot.
- `vm.runInNewContext(code, ctx)` / `vm.runInThisContext(snippet)` /
  `vm.Script(code)` — Node.js VM module. Does not provide a security
  sandbox; code can escape via prototype chain.

**Node.js `child_process` with a shell:**
- `exec(cmd)` / `execSync(cmd)` — always invokes a shell. If `cmd` is
  built from user input, the attacker can inject shell metacharacters.
- `spawn("sh", ["-c", cmd])` / `spawn(cmd, { shell: true })` —
  equivalent to exec when shell is involved.
- Note: `spawn("git", ["clone", url])` with a fixed command and
  separate argv array is generally safe (no shell expansion). Flag
  only when a shell is involved or the command name itself is dynamic.

**Python equivalents:**
- `eval(userInput)` / `exec(userInput)` — direct code execution.
- `os.system(cmd)` / `subprocess.call(cmd, shell=True)` /
  `subprocess.Popen(cmd, shell=True)` / `os.popen(cmd)` where `cmd`
  is user-controlled — shell injection.

**Ruby equivalents:**
- Backtick operator `` `cmd` `` with interpolated user input.
- `%x{cmd}` with interpolated user input.
- `Kernel.system(cmd)` / `Kernel.exec(cmd)` where `cmd` is a
  single shell string with user input.

## True positive criteria

Flag when ANY of the following hold AND the argument contains or is
traceable to user input:

1. `eval()`, `new Function()`, `vm.runInNewContext/ThisContext/Script`
   with a non-constant string argument.
2. `child_process.exec` / `execSync` with any string argument (they
   always use a shell).
3. `spawn` with `shell: true` and a command string that includes
   user input.
4. Python `eval()`, `exec()`, `os.system()`, `subprocess` with
   `shell=True`.
5. Ruby backtick or `%x{}` with user-controlled interpolation.

## What to ignore

- `spawn("git", ["clone", repoUrl], { shell: false })` — fixed
  command, separate argv, no shell. Safe even if `repoUrl` is user-
  controlled (the OS treats the whole value as one argument).
- `exec.Command("git", "log", branchName)` in Go — see `go-command-injection`.
- `eval()` with a provably hardcoded string (string literal, no
  interpolation or variable).
- `new Function()` used only to parse JSON or deserialize a known-
  safe serialization format (unusual but possible).
- Build-time scripts, developer tools, and seed scripts that only
  run in controlled CI/developer environments.
- Test files.

## Examples

True positives:
```ts
// eval with user input
eval(req.body.expression);

// new Function with template literal
const fn = new Function("return " + req.body.code);
fn();

// exec — always uses a shell
exec(`git log ${req.query.branch}`);
execSync("ls " + req.body.dir);

// spawn with shell: true
spawn("sh", ["-c", req.body.cmd]);
spawn(req.body.cmd, { shell: true });

// vm — not a real sandbox
vm.runInNewContext(userCode, {});
```
```python
# Python — os.system with user input
os.system("ping " + host)

# subprocess with shell=True
subprocess.call(f"ls {req.form['dir']}", shell=True)

# eval
eval(user_expression)
```

False positives to skip:
```ts
// spawn with fixed command and separate argv — safe
spawn("git", ["clone", "--depth=1", repoUrl]);

// Hardcoded string
eval("1 + 1");

// Build script, not user-facing
execSync("npm run build");
```
