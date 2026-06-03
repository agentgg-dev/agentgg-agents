---
slug: openclaw-audit-fs-path-symlink
name: Filesystem Path / Symlink Audit (OpenClaw)
description: Audits OpenClaw filesystem-touching surfaces (FS bridge readFile/writeFile, archive extraction, hook installation, marketplace install, channel media handlers, screen capture out-paths, workspace memory, agent attachments) for path traversal, archive bombs, symlink races, and TOCTOU. Reports each call site as safe / risky / broken with the file:line of the path check, the open/extract/write call, and the specific bypass.
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
    - "**/*.test.ts"
    - "**/*.test.tsx"
    - "**/*.spec.ts"
    - "**/*.spec.tsx"
references:
  - CVE-2026-32055
  - CVE-2026-32036
  - CVE-2026-28393
  - CVE-2026-32044
  - CVE-2026-43567
---

You are auditing filesystem-touching surfaces in `openclaw/` for one bug class: a path that originates outside the trusted workspace boundary reaches an open/read/write/extract call that treats it as if it were inside.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. The FS workspace boundary has well-defined exemptions.

## In scope

- A workspace-relative path that escapes via `..`, encoded dot-segment, non-existent symlink target resolution, absolute-path injection, drive-letter injection on Windows, or NTFS alternate data stream.
- An archive (ZIP/TAR) extraction that follows symlinks, has unbounded expansion, or writes outside the destination directory.
- A symlink race between a stat/preflight and the open/write.
- A TOCTOU between FS bridge `open`/`stat` and the actual `read`/`write`.
- A channel-extension media tag (QQBot reply media tag, structured payload, Discord cover image, Feishu upload_image, Webchat audio embedding, MEDIA: paths shared across channels) that resolves to an arbitrary local file when the protocol is otherwise authenticated.
- An out-path parameter (`screen_record outPath`, `apply_patch` target, FS bridge writeFile) that escapes the workspace root.
- A QMD `memory_get` (or sibling) that reads outside the canonical/indexed memory paths.
- Hook transform path traversal (loads arbitrary JS from outside the hook directory).
- An encoded dot-segment in an HTTP route that reaches a workspace-only filesystem operation.
- A marketplace / clawhub install that follows a symlink in the package.

## Out of scope under SECURITY.md (do not file)

- **Pre-existing symlink/hardlink state in trusted local paths** (extraction targets, skill paths, workspace files like `MEMORY.md` / `memory/*.md`) without a separate untrusted boundary bypass that creates the state.
- **Workspace memory writes** by an authorized operator. Memory files are trusted operator state.
- **Same-path post-approval file replacement** without an untrusted write primitive.
- **Authorized-sender intentional writes** (`/export-session /abs/path`) as long as approval is the binding gate documented for that route.
- **Trusted plugin reading/writing arbitrary host files.** Plugins are TCB.
- **`tools.fs.workspaceOnly: false` deployments** (operator opted out of the boundary).

The disposition test: *can an external attacker, an unauthenticated webhook, a model output not behind owner tool policy, or a non-allowlisted sender produce an FS access that escapes the workspace boundary?* If yes, file. If no, hardening.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Sandbox path / FS bridge.** [openclaw/src/agents/sandbox-paths.ts](openclaw/src/agents/sandbox-paths.ts), [openclaw/src/agents/sandbox-media-paths.ts](openclaw/src/agents/sandbox-media-paths.ts), [openclaw/src/agents/sandbox.ts](openclaw/src/agents/sandbox.ts), [openclaw/src/agents/sandbox-tool-policy.ts](openclaw/src/agents/sandbox-tool-policy.ts).
2. **Archive extraction and plugin/marketplace install.** [openclaw/src/infra/archive.test.ts](openclaw/src/infra/archive.test.ts) (sibling `archive.ts` in same dir), [openclaw/src/infra/install-source-utils.ts](openclaw/src/infra/install-source-utils.ts), [openclaw/src/infra/backup-create.ts](openclaw/src/infra/backup-create.ts), [openclaw/src/plugins/install.ts](openclaw/src/plugins/install.ts), [openclaw/src/plugins/install-security-scan.runtime.ts](openclaw/src/plugins/install-security-scan.runtime.ts), [openclaw/src/plugins/marketplace.ts](openclaw/src/plugins/marketplace.ts), [openclaw/src/hooks/install.ts](openclaw/src/hooks/install.ts), [openclaw/src/hooks/install.runtime.ts](openclaw/src/hooks/install.runtime.ts).
3. **Hook transform and import-url.** [openclaw/src/hooks/import-url.ts](openclaw/src/hooks/import-url.ts), [openclaw/src/hooks/module-loader.ts](openclaw/src/hooks/module-loader.ts), [openclaw/src/hooks/loader.ts](openclaw/src/hooks/loader.ts), [openclaw/src/hooks/workspace.ts](openclaw/src/hooks/workspace.ts), [openclaw/src/hooks/configured.ts](openclaw/src/hooks/configured.ts).
4. **Session / workspace path helpers.** [openclaw/src/gateway/session-utils.fs.ts](openclaw/src/gateway/session-utils.fs.ts), [openclaw/src/gateway/session-utils.ts](openclaw/src/gateway/session-utils.ts), [openclaw/src/gateway/session-reset-service.ts](openclaw/src/gateway/session-reset-service.ts).
5. **Channel media handlers.** [openclaw/extensions/qqbot/src/](openclaw/extensions/qqbot/src/), [openclaw/extensions/feishu/src/](openclaw/extensions/feishu/src/), [openclaw/extensions/discord/src/](openclaw/extensions/discord/src/), [openclaw/extensions/msteams/src/](openclaw/extensions/msteams/src/), [openclaw/extensions/zalo/src/](openclaw/extensions/zalo/src/), [openclaw/extensions/webchat/src/](openclaw/extensions/webchat/src/) (look for `upload`, `media`, `attachment`, `mediaTag`, `MEDIA:`, `screen_record`).
6. **Memory and skills paths.** [openclaw/src/memory/](openclaw/src/memory/), [openclaw/src/security/audit-workspace-skill-escape.test.ts](openclaw/src/security/audit-workspace-skill-escape.test.ts), [openclaw/src/security/audit-synced-folder.test.ts](openclaw/src/security/audit-synced-folder.test.ts), [openclaw/src/security/audit-config-symlink.test.ts](openclaw/src/security/audit-config-symlink.test.ts), [openclaw/src/security/audit-filesystem-windows.test.ts](openclaw/src/security/audit-filesystem-windows.test.ts), [openclaw/src/security/audit-workspace-skills.ts](openclaw/src/security/audit-workspace-skills.ts).
7. **Existing FS-related audit surface.** [openclaw/src/security/audit-fs.ts](openclaw/src/security/audit-fs.ts), [openclaw/src/security/scan-paths.ts](openclaw/src/security/scan-paths.ts), [openclaw/src/security/skill-scanner.ts](openclaw/src/security/skill-scanner.ts), [openclaw/src/security/installed-plugin-dirs.ts](openclaw/src/security/installed-plugin-dirs.ts).

## Pattern fingerprints

1. **`path.resolve` without confinement check.** Resolves user-provided path, then opens it. Confirm a `startsWith(workspaceRoot + path.sep)` check happens *after* `realpath`.
2. **`fs.realpath` not called before the boundary check.** Symlink-not-yet-existent is a known bypass: the realpath fails, the code falls through to the raw path.
3. **TOCTOU.** A `fs.stat`/`fs.lstat` followed by a separate `fs.open` by path. Fix shape: pin the fd, or `O_NOFOLLOW`, or hash-pin.
4. **Archive extraction without symlink rejection.** `tar.extract`, `unzipper`, `adm-zip` called without an entry filter that rejects symlinks/hardlinks/`..` entries.
5. **Archive expansion without size cap.** No `maxSize`, `maxFiles`, or compression-ratio guard.
6. **Channel media tag resolves a path.** `MEDIA:`, `<file>`, `attachment://`, `cid:`, `image/*; src=` accepting an arbitrary local path string.
7. **HTTP path normalization happens after route match.** `decodeURIComponent` on the URL after the route handler matched, allowing `%2e%2e/`.
8. **Hook transform loads from a relative path.** `require()` / `import()` with a path string from operator config that is not workspace-confined.
9. **MEDIA: paths cross-channel.** A media path written by one channel is consumed by another with different trust assumptions.

## What to grep for

- `fs.openSync`, `fs.open`, `fs.readFile`, `fs.writeFile`, `fs.createReadStream`, `fs.createWriteStream`, `fs.mkdir`, `fs.symlink`.
- `fs.realpath`, `realpathSync`, `path.resolve`, `path.join`, `path.normalize`.
- `unzipper`, `adm-zip`, `node-stream-zip`, `tar`, `tar-stream`, `tar.extract`, `tar.x`.
- `O_NOFOLLOW`, `lstat`, `lstatSync`.
- `decodeURIComponent`, `decodeURI`, `%2e`, `%2f`, `path.posix`.
- `workspaceRoot`, `assertWorkspacePath`, `withinWorkspace`, `assertWorkspaceRelative`.
- `MEDIA:`, `attachment://`, `cid:`, `<file>`, `upload_image`, `upload_file`, `screen_record`.
- `applyPatch`, `apply_patch`, `outPath`, `targetPath`, `destPath`.
- `hooks`, `transformPath`, `hooks.transform`.
- `IDENTITY.md`, `appendFile`, `appendFileSync`.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern:  <path-traversal / symlink-follow / archive-bomb / tar-symlink / TOCTOU / encoded-dot / channel-media-tag / hook-transform / cross-channel-media>
  Surface:      <FS bridge / archive install / channel media / hook transform / HTTP route / screen capture>
  Boundary:     <where the check is — file:line — or "absent">
  Sink:         <file:line of open/extract/write>
  Trigger:      <operator config / unauthenticated webhook / chat slash / model output / cross-channel reply>
  Attacker:     <who controls the path string>
  Effect:       <arbitrary file read / write outside workspace / RCE via hook load / archive extraction outside dest>
  Acceptance:   <passes SECURITY.md gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-32055 (workspace path bypass via non-existent symlink), CVE-2026-32036 (encoded dot-segment in /api/channels), CVE-2026-28393 (hook transform path traversal), CVE-2026-32044 / CVE-2026-28452 / CVE-2026-27670 (archive extraction), CVE-2026-32977 (sandbox writeFile commit), CVE-2026-43533 (QQBot media tags), CVE-2026-43526 (QQBot reply media), CVE-2026-43532 (Discord cover images), CVE-2026-41363 (Feishu upload_image), CVE-2026-42438 (host media attachment), CVE-2026-42424 (shared MEDIA paths), CVE-2026-43567 (screen_record outPath), CVE-2026-44111 (QMD memory_get traversal), CVE-2026-41296 / CVE-2026-41397 (FS bridge TOCTOU + symlink), CVE-2026-43529 (TOCTOU exec preflight), GHSA-pmf3 (IDENTITY.md appendFile), GHSA-5799 (SSH tar follows symlinks), GHSA-cr8r (marketplace symlink), GHSA-mr34 / GHSA-gfg9 (webchat media), GHSA-m34q (OpenShell mirror deletes remote dirs), GHSA-846p (QQBot structured payload).
