---
slug: openclaw-audit-workspace-dotenv-trust-hunter
name: Workspace Dotenv Trust Audit — Hunter (OpenClaw)
description: Audits OpenClaw consumers of workspace `.env`, `pnpm-workspace.yaml`, `.npmrc`, `setup-api.js`, `MCP server config`, and similar workspace-supplied configuration for places workspace bytes reach a host process env, a hooks root, an exec routing variable, an MCP stdio env, or a connector endpoint, in a way that converts a non-privileged workspace write into a host-privileged effect.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  prompt: |
    Run only if this codebase IS OpenClaw — the chat-channel automation
    platform — or one of its first-party extensions/connectors. Skip any
    project that merely depends on or integrates with OpenClaw. If the recon
    brief doesn't clearly indicate an OpenClaw codebase, answer no.
where:
  extensions: [ts, tsx, js, jsx, mjs, cjs]
  excludePatterns:
    - "**/e2e/**"
    - "**/*test*/**"
    - "**/__tests__/**"
    - "**/fixtures/**"
  preFilter:
    - { regex: "process\\.env|dotenv|\\.npmrc|pnpm-workspace|setup-api", label: "workspace config consumer" }
    - { regex: "\\benv\\s*:|spawn|exec|stdio|\\bmcp\\b", label: "host env / exec sink" }
references:
  - CVE-2026-43531
  - CVE-2026-35641
  - CVE-2026-43571
  - CVE-2026-43569
---

You are auditing workspace-supplied configuration consumers in `openclaw/` for one bug class: a file living under the workspace root (which the operator may have edited *or* which a tool/model output may have written) is read at startup or during runtime and applied to a host process in a way that grants the workspace write privilege it should not have.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. The trusted-plugin and trusted-workspace-memory boundaries are documented; this audit lives at the *boundary* between them and the host runtime.

## In scope

- Workspace `.env` overrides runtime-control variables that change the gateway's exec routing, hooks root, MCP stdio env, connector endpoint host, MiniMax host, or other code-loading variable.
- A `.npmrc` placed in the workspace causes a local plugin / hook install to fetch from an attacker-controlled registry or run an attacker-controlled lifecycle script.
- A `setup-api.js` (or sibling) is loaded from `cwd` during env-key resolution.
- An MCP stdio server env loads dangerous startup variables from workspace config.
- A workspace-supplied dotenv overrides a connector endpoint host so credentialed requests redirect.
- An OpenShell mirror mode converts an untrusted sandbox file into a workspace hook executed at host startup.
- A hooks-root override loads attacker hook code.
- A hook mapping template bypasses the session-key opt-in.
- A workspace channel shadow executes during built-in channel setup.
- A workspace plugin shadow is auto-enabled or included in channel setup catalog.

## Out of scope under SECURITY.md (do not file)

- **Operator-edited workspace memory** (`MEMORY.md`, `memory/*.md`). Memory writes by an authorized operator are trusted.
- **Operator-installed plugin** running with host privileges by design (Trusted Plugin Boundary).
- **`plugins.allow` containing operator-trusted plugin ids.**
- **Workspace files written by an authorized sender** through a documented intentional command (e.g. `/export-session /abs/path`).
- **`tools.fs.workspaceOnly: false`** when operator opted out.
- **Operator-set `dangerously*` flag** that weakens defaults.
- **Trusted-installed plugin** loading workspace files with full host privilege.

The disposition test: *who can write the workspace file, and what host effect does the consumer apply?* If any party who is not an authorized operator (an external chat sender via reply media, a webhook payload, a tool/model output not behind owner-tool policy, a non-allowlisted attachment, a sandbox file mirror, an iOS A2UI dispatch) can produce that workspace file, file. If only the operator can write it, hardening.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Dotenv readers.** [openclaw/src/infra/dotenv.ts](openclaw/src/infra/dotenv.ts), [openclaw/src/cli/dotenv.ts](openclaw/src/cli/dotenv.ts), [openclaw/src/config/state-dir-dotenv.ts](openclaw/src/config/state-dir-dotenv.ts), [openclaw/src/config/io.ts](openclaw/src/config/io.ts), [openclaw/src/config/env-vars.ts](openclaw/src/config/env-vars.ts). Walk every reader to a `process.env` consumer. The `daemon`-side: [openclaw/src/daemon/service-env-plan.ts](openclaw/src/daemon/service-env-plan.ts), [openclaw/src/daemon/service-env-render-policy.ts](openclaw/src/daemon/service-env-render-policy.ts).
2. **Plugin install / hook install (where workspace bytes can produce host execution).** [openclaw/src/plugins/install.ts](openclaw/src/plugins/install.ts), [openclaw/src/plugins/install.npm-spec.test.ts](openclaw/src/plugins/install.npm-spec.test.ts), [openclaw/src/plugins/install-security-scan.runtime.ts](openclaw/src/plugins/install-security-scan.runtime.ts), [openclaw/src/plugins/marketplace.ts](openclaw/src/plugins/marketplace.ts), [openclaw/src/plugins/uninstall.test.ts](openclaw/src/plugins/uninstall.test.ts), [openclaw/src/plugins/update.test.ts](openclaw/src/plugins/update.test.ts), [openclaw/src/plugins/hooks.ts](openclaw/src/plugins/hooks.ts).
3. **Hook install / transform.** [openclaw/src/hooks/install.ts](openclaw/src/hooks/install.ts), [openclaw/src/hooks/install.runtime.ts](openclaw/src/hooks/install.runtime.ts), [openclaw/src/hooks/installs.ts](openclaw/src/hooks/installs.ts), [openclaw/src/hooks/loader.ts](openclaw/src/hooks/loader.ts), [openclaw/src/hooks/module-loader.ts](openclaw/src/hooks/module-loader.ts), [openclaw/src/hooks/import-url.ts](openclaw/src/hooks/import-url.ts), [openclaw/src/hooks/configured.ts](openclaw/src/hooks/configured.ts), [openclaw/src/hooks/workspace.ts](openclaw/src/hooks/workspace.ts), [openclaw/src/hooks/bundled-dir.ts](openclaw/src/hooks/bundled-dir.ts).
4. **MCP stdio servers.** [openclaw/src/mcp/](openclaw/src/mcp/) (every reader of MCP server config that builds a child-process env or argv).
5. **Workspace-run / agents-config workspace surface.** [openclaw/src/agents/workspace-run.test.ts](openclaw/src/agents/workspace-run.test.ts), [openclaw/src/agents/model-auth.workspace-plugin.test.ts](openclaw/src/agents/model-auth.workspace-plugin.test.ts).
6. **Existing audit surface.** [openclaw/src/security/audit-deep-code-safety.ts](openclaw/src/security/audit-deep-code-safety.ts), [openclaw/src/security/audit-plugins-trust.ts](openclaw/src/security/audit-plugins-trust.ts), [openclaw/src/security/installed-plugin-dirs.ts](openclaw/src/security/installed-plugin-dirs.ts), [openclaw/src/security/audit-extra.async.ts](openclaw/src/security/audit-extra.async.ts).
7. **Any `require(./...)` / `import(...)` that resolves relative to `process.cwd()` or the workspace root.** Grep for `process.cwd()`, `path.join(process.cwd()`, `setup-api`, `openclaw.config`, `.openclaw/`. Especially [openclaw/src/cli/run-main.ts](openclaw/src/cli/run-main.ts) and the entry path.

## Pattern fingerprints

1. **Reader of `<workspace>/.env` extends `process.env` of the host process.** Confirm a denylist of runtime-control / loader / endpoint vars is enforced at the bridge.
2. **Path-relative `require(./setup-api.js)` from cwd.** Code-loading from a workspace-controlled path.
3. **Any `npm`/`pnpm` install run against a directory the workspace can write.** Confirm `--ignore-scripts` and a pinned registry config.
4. **MCP stdio env constructed from workspace YAML/JSON** without a denylist of `BASH_ENV`, `NODE_OPTIONS`, `LD_PRELOAD`, etc.
5. **Connector endpoint host read from workspace `.env`.** Walk to outbound HTTP that includes credentials.
6. **OpenShell mirror copies sandbox files into a hooks/skills directory** that startup later loads.
7. **Channel setup catalog reads workspace plugin metadata** as auto-enable.
8. **Hook mapping template substitution** bypasses a session-key opt-in flag.

## What to grep for

- `dotenv`, `parseEnv`, `loadDotenv`, `readEnvFile`, `\.env`.
- `process.env =`, `Object.assign(process.env`, `setEnv`, `applyEnv`, `mergeEnv`.
- `require(.*cwd`, `import(.*cwd`, `path.join(process.cwd()`, `require.resolve.*workspace`.
- `npm install`, `pnpm install`, `yarn install`, `--registry`, `--ignore-scripts`.
- `mcp.stdio`, `mcpServers`, `stdio`, `command:` entries in MCP config.
- `connector.endpoint`, `connector.host`, `MiniMax`, `connectorBaseUrl`.
- `openshell.mirror`, `mirror.mode`, `mirrorRoot`.
- `setup-api.js`, `setup-api`, `apiSetup`.
- `hooks.root`, `hooksRoot`, `OPENCLAW_HOOKS_ROOT`.
- `channels.setup.catalog`, `pluginShadow`, `workspacePlugin`.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern: <dotenv-runtime-vars / npmrc-install / setup-api-cwd / mcp-stdio-env / connector-host-override / openshell-mirror / hook-mapping-template / channel-catalog-shadow>
  Source:      <which workspace file is read>
  Writer:      <who can write that file — operator only / external chat / webhook / model output / sandbox mirror / attachment>
  Sink:        <host effect — process.env / require / npm install / outbound credentialed request / hook load>
  Boundary:    <denylist or check that should have stopped this — or "absent">
  Acceptance:  <passes SECURITY.md gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-43531 (workspace .env injects runtime-control vars), CVE-2026-35641 (.npmrc local plugin RCE), GHSA-r39h (setup-api.js loaded from cwd), GHSA-mj59 (MCP stdio env loads dangerous startup vars), GHSA-jx3c (workspace .env overrides hooks root), GHSA-2xcp (hook mapping templates bypass session-key), GHSA-h2vw (workspace dotenv MiniMax host override), GHSA-55cf (workspace dotenv connector endpoint hosts), GHSA-m563 (OpenShell mirror to workspace hooks), GHSA-m34q (OpenShell mirror deletes remote dirs), GHSA-2qrv (workspace channel shadows execute), CVE-2026-43571 (channel setup catalog includes plugin shadows), CVE-2026-43569 (workspace provider auth auto-enable plugins).
