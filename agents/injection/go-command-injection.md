---
slug: go-command-injection
name: Command Injection (Go)
description: Go exec.Command / exec.CommandContext / syscall.Exec with a shell invocation or a user-controlled command name — allows shell metacharacter injection. Traces argument origin and any wrapper functions around exec.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'exec\.(Command|CommandContext)\s*\(\s*["`](sh|bash|zsh|/bin/sh|/bin/bash)'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: exec.Command shell invocation
      - regex: 'exec\.(Command|CommandContext)\s*\([^,)]*\b(fmt\.Sprintf|\+)'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: exec.Command with Sprintf/concat in command argument
      - regex: syscall\.Exec\s*\(
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: syscall.Exec call
      - regex: 'exec\.(Command|CommandContext)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: exec.Command with variable command name
  prompt: Run only if this project uses go — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - go
  excludePatterns:
    - '**/*_test.go'
    - '**/vendor/**'
  preFilter:
    - regex: 'exec\.(Command|CommandContext)\s*\(\s*["`](sh|bash|zsh|/bin/sh|/bin/bash)'
      label: exec.Command shell invocation
    - regex: 'exec\.(Command|CommandContext)\s*\([^,)]*\b(fmt\.Sprintf|\+)'
      label: exec.Command with Sprintf/concat in command argument
    - regex: syscall\.Exec\s*\(
      label: syscall.Exec call
    - regex: 'exec\.(Command|CommandContext)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,'
      label: exec.Command with variable command name
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-78
  - 'OWASP-A03:2021'
---

You are reviewing Go source code for OS command injection —
`exec.Command`, `exec.CommandContext`, or `syscall.Exec` calls where
the command string or arguments are user-controlled in a way that
allows shell metacharacter injection or arbitrary command selection.

**Cross-file analysis:** the dangerous part is whether the
argument value crosses a trust boundary. Trace the variable: was it
`r.URL.Query().Get(...)`, was it derived from a request handler
parameter, or is it a constant from elsewhere in the package? Open
the caller if the suspect command runs inside a helper.

## What to look for

**Shell invocation pattern (highest risk):**
```go
cmd := exec.Command("sh", "-c", userInput)
cmd := exec.Command("bash", "-c", cmdString)
cmd := exec.Command("/bin/sh", "-c", userInput)
```
Passing a user-controlled string as the argument to `sh -c` is
equivalent to `eval` — the shell interprets metacharacters
(`;`, `|`, `&&`, `` ` ``, `$(...)`) embedded in the input.

**User-controlled command name:**
```go
cmd := exec.Command(req.FormValue("tool"), args...)
```
Letting the user choose the binary name is arbitrary command
execution.

**`exec.CommandContext` with the same patterns:**
```go
cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("git log %s", branch))
```

**`syscall.Exec`:**
```go
syscall.Exec("/bin/sh", []string{"sh", "-c", userInput}, os.Environ())
```

**Safe pattern (separate argv):**
```go
exec.Command("git", "log", branchName)
```
When the command name is hardcoded and arguments are passed as
separate `argv` entries (not joined into a shell string), the OS
treats each argument as a literal value — no shell expansion.

## True positive criteria

Flag when ANY of the following hold:

1. The first argument to `exec.Command` is a shell binary (`sh`,
   `bash`, `zsh`, `/bin/sh`, etc.) AND a subsequent argument is
   user-controlled or built via `fmt.Sprintf` / string concatenation.
2. The command name (first argument) is a variable whose value is
   caller-controlled.
3. `syscall.Exec` is called with a user-controlled path or argument.

## What to ignore

- `exec.Command("git", "log", branchName)` — hardcoded command,
  separate argv, no shell. The OS treats `branchName` as one
  argument regardless of metacharacters.
- `exec.Command("ffmpeg", "-i", uploadedFile, "-o", outputFile)` —
  hardcoded binary, separate argv.
- All arguments fully hardcoded (no variables from caller input).
- Test files (`_test.go`).
- `exec.Command("sh", "-c", "npm install")` — hardcoded shell string,
  no interpolation.

## Examples

True positives:
```go
// Shell with user-controlled argument
branch := r.URL.Query().Get("branch")
cmd := exec.Command("sh", "-c", "git log "+branch)

// User-controlled command via fmt.Sprintf
host := r.FormValue("host")
cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ping -c 1 %s", host))

// User-controlled binary name
tool := r.URL.Query().Get("tool")
cmd := exec.Command(tool, "--help")
```

False positives to skip:
```go
// Hardcoded command — separate argv — safe
repoURL := r.FormValue("repo")
cmd := exec.Command("git", "clone", "--depth=1", repoURL)

// Static shell command
cmd := exec.Command("sh", "-c", "ls /tmp")
```
