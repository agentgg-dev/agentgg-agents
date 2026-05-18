---
slug: openclaw-audit-exec-policy-bypass-hunter
name: Exec Policy Bypass Audit — Hunter (OpenClaw)
description: Audits OpenClaw exec-routing surfaces (`system.run`, `tools.exec`, node exec, Docker/SSH wrappers) for policy bypasses where the executed bytes diverge from the approved/allowlisted command, where the allowlist does not understand a shell construct, or where environment variables convert a benign command into attacker code. Reports each call site as safe / risky / broken with the file:line of the approval-vs-exec divergence, the missing allowlist primitive, or the env-injection sink. Pairs with `openclaw-audit-allowlist-identity-hunter` and `openclaw-audit-webhook-ingress-hunter` and is the largest single CVE cluster in the OpenClaw history.
version: 0.1.0
author: agentgg
mode: hunt
noiseTier: normal
outputType: finding
filePatterns: []
excludePatterns:
  - "**/e2e/**"
  - "**/*test*/**"
  - "**/__tests__/**"
  - "**/fixtures/**"
references:
  - CVE-2026-22168
  - CVE-2026-32978
  - CVE-2026-26325
  - CVE-2026-42434
  - CVE-2026-43531
---

You are auditing exec-routing surfaces in `openclaw/` for one bug class: an authenticated operator (or a compromised model that already passes the operator scope check) reaches a shell or process spawn with a payload the *exec policy* did not authorize. The operator-facing approval string, the allowlist match, or the env denylist all believe one thing; the OS process sees another.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. Several findings in this class are explicitly out of scope under the trusted-operator model.

## In scope (file these)

The exec policy is a documented OpenClaw boundary. A finding is in scope only when an attacker who is **not yet trusted at the bypassed layer** reaches privileged execution by crossing a documented gate. Concretely:

- **Approval vs exec divergence.** The string the operator approved (or that allowlist matched) and the string the OS process runs are not the same. Argv mutated after approval, `rawCommand` vs `command` mismatch, mutable operand binding, host=node override after approval, busybox/toybox applet substitution, shell-wrapper detection missed env-argv assignment, `cmd.exe /c` trailing arguments, TOCTOU between preflight and exec.
- **Allowlist does not understand a shell construct.** Command substitution, `env -S`, `sort --compress-program`, complex pipelines, positional argv carriers, unrecognized script runners, time-dispatch wrappers, heredoc shell expansion. The allowlist matches the visible command name but the construct routes execution elsewhere.
- **Env-injection RCE.** A variable in the process environment converts a benign command into attacker code: `SHELLOPTS`, `PS4`, `BASH_ENV`, `ENV`, `GIT_DIR`, `GIT_TEMPLATE_DIR`, `HGRCPATH`, `CARGO_BUILD_RUSTC_WRAPPER`, `RUSTC_WRAPPER`, `MAKEFLAGS`, `AWS_CONFIG_FILE`, Docker registry/proxy/TLS overrides, Perl `PERL5OPT` / `PERL5LIB`, Node `NODE_OPTIONS`, npm `.npmrc`, package-manager prefix vars.
- **Sandbox escape via routing override.** `host=node`, paired-device skips node scope gate, sandboxed agents reach the gateway exec route.
- **Workspace `.env` overrides exec-routing variables.** When the gateway/host process reads workspace `.env` and the variable controls hooks root, MCP env, or exec routing.
- **Approval-timeout / strictInlineEval fallback.** The strict gate exists but a fallback path runs the command without the gate's checks.
- **Non-Bash shell fallback** that bypasses the bash-aware allowlist (Windows shell fallback, Lobster extension, macOS keychain shell injection, Docker exec PATH injection, SSH wrapper project-root injection).

## Out of scope under SECURITY.md (do not file)

- **Operator-intended local features.** A trusted operator using `system.run` per the docs to execute on their own host. Approvals are *guardrails to reduce accidental command execution, not a multi-tenant authorization boundary* (SECURITY.md "Gateway and Node Trust Concept").
- **Heuristic / parity drift.** "Exec path A has obfuscation detection, exec path B does not" without a concrete bypass. SECURITY.md: parity-only findings are hardening, not vulnerabilities.
- **Approval-as-semantic-model.** Reports that exec approvals do not model every interpreter loader form, subcommand, transitive import. SECURITY.md: approvals bind exact request context and best-effort direct local file operands; not a complete loader semantic model.
- **Authorized-sender local action.** An allowlisted/owner sender intentionally invokes `/export-session /abs/path.html`. Authorized user actions are trusted host actions.
- **Trusted-installed plugin executing host commands.** Plugins are trusted code; their behavior is by design.
- **`dangerously*` opt-in already enabled.** Operator chose to weaken defaults.
- **Same-path post-approval file replacement.** Requires an untrusted write primitive, which the report must show separately.
- **Pure ReDoS / DoS without a trust-boundary bypass** (catastrophic regex in `sessionFilter`, `logging.redactPatterns`).

The disposition test for every candidate: *with the documented operator config, is there a request from an unprivileged or external attacker, or a model output not run through approval, that produces a different OS-level command than the approval/allowlist/denylist authorized?* If yes, file. If no, hardening.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **The spawn layer.** [openclaw/src/process/exec.ts](openclaw/src/process/exec.ts), [openclaw/src/process/spawn-utils.ts](openclaw/src/process/spawn-utils.ts), [openclaw/src/process/windows-command.ts](openclaw/src/process/windows-command.ts), [openclaw/src/process/child-process-bridge.ts](openclaw/src/process/child-process-bridge.ts), [openclaw/src/process/command-queue.ts](openclaw/src/process/command-queue.ts). Every actual `spawn` lives here or is dispatched from here.
2. **The approval layer.** [openclaw/src/agents/exec-approval-result.ts](openclaw/src/agents/exec-approval-result.ts), [openclaw/src/agents/exec-defaults.ts](openclaw/src/agents/exec-defaults.ts), [openclaw/src/agents/execution-contract.ts](openclaw/src/agents/execution-contract.ts), [openclaw/src/gateway/exec-approval-manager.ts](openclaw/src/gateway/exec-approval-manager.ts), [openclaw/src/gateway/exec-approval-ios-push.ts](openclaw/src/gateway/exec-approval-ios-push.ts), and the approval helpers under [openclaw/src/plugin-sdk/](openclaw/src/plugin-sdk/) (approval-auth-helpers, approval-client-helpers, approval-delivery-helpers, approval-handler-runtime, approval-native-helpers, approval-runtime).
3. **The exec policy / dangerous-tools / allowlist layer.** [openclaw/src/tools/execution.ts](openclaw/src/tools/execution.ts), [openclaw/src/security/dangerous-tools.ts](openclaw/src/security/dangerous-tools.ts), [openclaw/src/security/dangerous-config-flags.ts](openclaw/src/security/dangerous-config-flags.ts), [openclaw/src/security/audit-exec-safe-bins.test.ts](openclaw/src/security/audit-exec-safe-bins.test.ts), [openclaw/src/security/audit-exec-sandbox-host.test.ts](openclaw/src/security/audit-exec-sandbox-host.test.ts), [openclaw/src/security/audit-exec-surface.test.ts](openclaw/src/security/audit-exec-surface.test.ts), [openclaw/src/security/audit-deep-code-safety.ts](openclaw/src/security/audit-deep-code-safety.ts).
4. **The sandbox / host routing layer.** [openclaw/src/agents/sandbox.ts](openclaw/src/agents/sandbox.ts), [openclaw/src/agents/sandbox-tool-policy.ts](openclaw/src/agents/sandbox-tool-policy.ts), [openclaw/src/agents/sandbox-paths.ts](openclaw/src/agents/sandbox-paths.ts), [openclaw/src/node-host/](openclaw/src/node-host/).
5. **The env layer.** [openclaw/src/infra/dotenv.ts](openclaw/src/infra/dotenv.ts), [openclaw/src/cli/dotenv.ts](openclaw/src/cli/dotenv.ts), [openclaw/src/config/state-dir-dotenv.ts](openclaw/src/config/state-dir-dotenv.ts), [openclaw/src/config/env-vars.ts](openclaw/src/config/env-vars.ts), [openclaw/src/daemon/service-env-plan.ts](openclaw/src/daemon/service-env-plan.ts), [openclaw/src/daemon/service-env-render-policy.ts](openclaw/src/daemon/service-env-render-policy.ts).
6. **The hook layer (since hooks can produce exec).** [openclaw/src/hooks/install.ts](openclaw/src/hooks/install.ts), [openclaw/src/hooks/install.runtime.ts](openclaw/src/hooks/install.runtime.ts), [openclaw/src/hooks/policy.ts](openclaw/src/hooks/policy.ts), [openclaw/src/hooks/internal-hooks.ts](openclaw/src/hooks/internal-hooks.ts).
7. **Channel slash commands and chat surfaces** that reach exec: [openclaw/extensions/](openclaw/extensions/) per channel; also [openclaw/src/chat/](openclaw/src/chat/) and the `chat-*` files under [openclaw/src/gateway/](openclaw/src/gateway/).

Treat any sibling target like `openclaw-windows-node/` as read-only context if cited.

## Pattern fingerprints

A site is suspect when any one of the following holds. Cite file:line.

1. **Approval string is built before final argv resolution.** The approval message renders `command + args` early, then the runner mutates argv, swaps the binary, walks env, or re-quotes. Walk from the approval render down to the spawn and confirm equality on each branch.
2. **Allowlist matches the binary, exec runs through a shell.** A shell wrapper (`bash -c`, `sh -c`, `zsh -c`, `cmd /c`, PowerShell `-Command`) appears between the allowlist match and the exec, or the binary name was matched but the construct (env -S, time, watch, xargs, sort --compress-program) re-dispatches.
3. **Env passed to spawn is not run through `ExecEnvSanitizer`.** Or the sanitizer's denylist is missing one of: `BASH_ENV`, `ENV`, `SHELLOPTS`, `PS4`, `PROMPT_COMMAND`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `GIT_DIR`, `GIT_INDEX_FILE`, `GIT_TEMPLATE_DIR`, `GIT_OBJECT_DIRECTORY`, `HGRCPATH`, `CARGO_BUILD_RUSTC_WRAPPER`, `RUSTC_WRAPPER`, `MAKEFLAGS`, `MAKE_CMD`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `DOCKER_CONFIG`, `npm_config_*`, `PIP_CONFIG_FILE`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`.
4. **Workspace `.env` reaches the host process env.** Trace any reader of `<workspace>/.env` to a child-process env.
5. **TOCTOU.** A preflight `stat`/`open`/`hash` happens, then exec re-opens by path. The fix shape is "pin the fd or content hash and verify on exec".
6. **Routing-override overrides approval scope.** A flag in the request body re-routes from sandbox to gateway/host (`host`, `runtime`, `node`, `tags`) and the approval was rendered for the original route.
7. **Shell-wrapper parser does not see all argv carriers.** `bash -c` content with `--`, leading positional argv, env-style assignments before the binary, `${VAR:-fallback}` style.
8. **Approval-timeout fallback runs the command.** A code path that lets the command proceed when approval is pending past a window.

## What to grep for

- `spawn`, `execFile`, `exec`, `child_process` — every call site.
- `approvalPolicy`, `applyExecApproval`, `renderApproval`, `approvedCommand`, `approvedArgs`, `approvedEnv`.
- `ExecEnvSanitizer`, `sanitizeEnv`, `denyEnv`, `allowEnv`.
- `ExecShellWrapperParser`, `parseShellWrapper`, `splitShellArgs`, `quoteShell`.
- `system.run`, `tools.exec`, `node.exec`, `runtime.system.runCommandWithTimeout`.
- `applyAllowlist`, `allowlistMatch`, `commandAllowlist`, `denyCommand`.
- `host=node`, `host: "node"`, `routeTo`, `selectExecHost`, `resolveExecRoute`.
- `BASH_ENV`, `SHELLOPTS`, `LD_PRELOAD`, `NODE_OPTIONS`, `GIT_DIR`, `RUSTC_WRAPPER`, `MAKEFLAGS` (also enumerate the absent ones, finding the *missing* entry in the denylist).
- `.env`, `dotenv`, `parseEnvFile`, `loadWorkspaceEnv`.
- `cmd.exe /c`, `cmd /c`, `bash -c`, `sh -c`, `pwsh -Command`, `powershell -Command`, `env -S`.

## Report format

Group by verdict, then by call site.

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern: <approval-mismatch / allowlist-feature-gap / env-injection / route-override / TOCTOU / shell-fallback>
  Approved:    <the bytes operator/approval policy authorized>
  Executed:    <the bytes the OS process actually sees>
  Gate:        <file:line of the policy/allowlist/sanitizer call>
  Sink:        <file:line of the spawn/exec>
  Trigger:     <what request shape reaches this — chat.send, /tools/invoke, hook, etc.>
  Attacker:    <who can drive the divergence — model output, untrusted webhook, workspace .env writer, etc.>
  Acceptance:  <passes SECURITY.md acceptance gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5 broken/risky findings ranked by ease of exploitation, prioritizing those that pass the SECURITY.md acceptance gate. Keep the report under 1100 words.

## Calibration references

- CVE-2026-22168 (cmd.exe /c trailing args), CVE-2026-32978 (unrecognized script runners, CRITICAL 9.4), CVE-2026-22179 (command substitution), CVE-2026-31992 (env -S), CVE-2026-32010 (sort --compress-program), CVE-2026-32052 (positional argv carriers), CVE-2026-26325 (rawCommand/command mismatch), CVE-2026-29608 (argv rewriting), CVE-2026-32921 (mutable operand binding), CVE-2026-43530 (busybox/toybox), CVE-2026-42435 (env-argv assignment forms), CVE-2026-32003 (SHELLOPTS/PS4), CVE-2026-43584 (env denylist gaps), CVE-2026-43531 (workspace .env), CVE-2026-42434 (host=node sandbox escape), CVE-2026-43529 (TOCTOU preflight), GHSA-7437 / GHSA-cm8v / GHSA-w9j9 / GHSA-wcm7 (env denylist gaps), GHSA-q2gc (strictInlineEval timeout fallback), GHSA-fvx6 (complex pipelines skip preflight).
