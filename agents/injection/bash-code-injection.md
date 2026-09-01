---
slug: bash-code-injection
name: Bash Script Code Injection
description: 'Dangerous patterns in shell scripts: eval with user input, curl/wget piped directly to bash, shell=True equivalents, fork bombs, and unbounded rm -rf — enabling arbitrary code execution or destructive file deletion.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\beval\b|\bcurl\b.*\|\s*(ba)?sh|\bwget\b.*\|\s*(ba)?sh|:(){:|rm\s+-[rf]{1,2}'
        in:
          - '**/*.sh'
          - '**/*.bash'
          - '**/Makefile'
          - '**/*.mk'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
        label: Dangerous bash pattern (eval, curl|sh, wget|sh, fork-bomb, rm -rf)
where:
  extensions:
    - sh
    - bash
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
  preFilter:
    - regex: '\beval\b'
      label: eval in shell script
    - regex: '(curl|wget)\s+[''"]?(https?|ftp|file)://[^''" ]+[''"]?\s*\|\s*(ba)?sh'
      label: curl/wget pipe to bash (remote code execution on install)
    - regex: '/bin/(sh|bash)\s+-[ce]'
      label: sh -c / bash -c dynamic command execution
    - regex: ':(\s*)\(\s*\)\s*\{.*\|.*:.*&.*\}\s*;'
      label: Fork bomb pattern
    - regex: 'rm\s+-[rf]{1,3}\s+(?:/|\$(?:HOME|PWD|OLDPWD|\{HOME\}|\{PWD\}))'
      label: rm -rf on root or home directory
references:
  - CWE-78
  - CWE-94
  - 'OWASP-A03:2021'
---

You are reviewing shell scripts for dangerous patterns that can lead to code injection, destructive operations, or unintended command execution.

## Patterns to evaluate

### eval with dynamic content

`eval` in bash executes a string as shell code. If the string includes external input, it is code injection:
```bash
eval "$1"                      # executes first CLI argument as code
eval "$(curl $REMOTE_URL)"     # executes remote URL response
eval "$USER_INPUT"             # direct code injection
```

Safe `eval` uses: evaluating arithmetic expressions from constants (`eval "echo $((2+2))"`) — flag only when the evaluated string traces to external input.

### curl / wget piped to bash (remote code execution)

A common pattern in install scripts that is frequently exploited:
```bash
curl https://example.com/install.sh | bash
wget -qO- https://example.com/setup.sh | sh
```

Flag unconditionally — even legitimate install scripts should download and verify (checksum/signature) before executing. Piping directly is a supply-chain risk.

### sh -c / bash -c with dynamic arguments

```bash
/bin/sh -c "$USER_CMD"       # code injection if $USER_CMD is user-controlled
bash -c "git $GIT_FLAGS"     # injection if $GIT_FLAGS is external input
```

### Fork bomb

```bash
:(){:|:&};:
```

Crash the system by exhausting process limits. Flag unconditionally — there is no legitimate use for a fork bomb in production code.

### rm -rf on uncontrolled or root paths

```bash
rm -rf /          # obvious — wipes filesystem
rm -rf "$DIR/"    # dangerous if $DIR is unset/empty: becomes rm -rf /
rm -rf $HOME/*    # dangerous if HOME is tampered
```

## True positive criteria

Flag at critical:
1. `eval` receiving external input (CLI arg, env var set from user, curl/wget output, file content from user-controlled path)
2. `curl`/`wget` piped directly to `sh`/`bash` — supply chain execution risk
3. Fork bomb pattern

Flag at high:
4. `bash -c "$var"` or `sh -c "$var"` where `$var` derives from external input
5. `rm -rf` on a path composed of an unquoted or potentially-empty variable

## What to ignore

- `eval` on arithmetic or string operations with fully hardcoded values
- `curl | bash` in development tooling README examples (comments, not executed code)
- `rm -rf` on hardcoded paths like `/tmp/build_dir` with no variable interpolation

Report: the pattern found, whether the dangerous argument traces to external input (CLI arg, env, file), and any surrounding context (CI script, Dockerfile RUN step, deployment script).
