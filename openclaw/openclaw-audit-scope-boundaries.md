---
slug: openclaw-audit-scope-boundaries
name: Scope Boundaries Audit (OpenClaw)
description: Audits OpenClaw operator-scope graph for places a `operator.read` request reaches `operator.write`, an `operator.write` request reaches `operator.admin`, a non-pairing scope reaches `operator.pairing`, or a device-level token mints credentials for another device. Reports each privileged sink as safe / risky / broken with the file:line of the missing scope check and the path that reaches it. Excludes shared-secret bearer paths (which SECURITY.md documents as full operator access).
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
  - CVE-2026-22172
  - CVE-2026-32922
  - CVE-2026-28472
  - CVE-2026-43574
  - CVE-2026-35621
---

You are auditing scope-boundary enforcement in `openclaw/` for one bug class: a request authenticates as one operator scope but reaches an effect that requires a higher one. The bypass typically lives in a chat-driven slash command, a node.invoke surface, a token rotation flow, a pairing flow, or an HTTP route registration, where the scope check was placed at the wrong layer or omitted on a parallel path.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. The trusted-operator model carves out broad areas of this audit.

## In scope

- A request that authenticates with `operator.read` (or narrower) reaches a sink that mutates persisted state (config write, allowlist write, cron persistence, profile persistence, channel-config persistence).
- An `operator.write` (model-driven) request reaches an `operator.admin` effect (cron schedules, device pairing approval, gateway-level config, talk voice / Telegram / Matrix / Feishu admin-class config).
- A non-pairing scope reaches `operator.pairing` (`device.pair.approve`, `node.pair.approve`, `device.token.rotate`).
- A device token mints credentials for another device, role, or scope set.
- A WebSocket connect handshake skips identity check and joins a higher-privileged scope.
- An HTTP route registration places a sensitive operation in a lower scope than its peers (single-route scope drift inside an otherwise hardened router).
- A subagent fallback uses a synthetic `operator.admin`.
- A read-scoped HTTP client kills sessions, reaches `/sessions/:k/kill`, or reaches another write-only effect.
- An empty approver list grants approval.
- A chat slash command (e.g. `chat.send /verbose`, `chat.send /allowlist`, `/reset-profile`) writes admin-class persisted state.

## Out of scope under SECURITY.md (do not file)

- **Shared-secret bearer auth on `/v1/chat/completions`, `/v1/responses`, `/tools/invoke`.** SECURITY.md is explicit: shared-secret bearer auth grants the full default operator scope set; narrower `x-openclaw-scopes` values are *ignored* on that path. Reports that treat these endpoints as having a narrower per-request scope are out of scope.
- **Authenticated Gateway callers reaching trusted-operator features.** Gateway auth is operator auth.
- **Local auto-paired device sessions on the loopback Control UI.** Documented as full localhost operator capability.
- **`sessionKey` as an authorization boundary.** Session identifiers are routing controls, not per-user authorization boundaries.
- **One operator viewing another's data on the same gateway.** Documented as expected behavior.
- **Trusted plugin executing privileged actions.** Plugins are part of the TCB once installed.
- **Operator-enabled `dangerously*` flag weakening defaults.** Explicit break-glass.
- **Heuristic detection differences across exec surfaces** without a concrete bypass.

The disposition test: *what scope did the caller present, and what scope does the affected effect require?* If they match, no finding. If the lower-scope path reaches the higher-scope effect by routing around the gate (parallel path, layered re-resolution, post-auth state mutation, identity-bearing-vs-shared-secret confusion on a path *not* listed above), file.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Method-to-scope registry.** [openclaw/src/gateway/method-scopes.ts](openclaw/src/gateway/method-scopes.ts) is the canonical map of gateway methods to required scopes. Open this first; every method missing or placed in a lower scope than its peers is a candidate.
2. **Auth flow and route registration.** [openclaw/src/gateway/auth.ts](openclaw/src/gateway/auth.ts), [openclaw/src/gateway/auth-mode-policy.ts](openclaw/src/gateway/auth-mode-policy.ts), [openclaw/src/gateway/auth-resolve.ts](openclaw/src/gateway/auth-resolve.ts), [openclaw/src/gateway/auth-surface-resolution.ts](openclaw/src/gateway/auth-surface-resolution.ts), [openclaw/src/gateway/auth-token-resolution.ts](openclaw/src/gateway/auth-token-resolution.ts), [openclaw/src/gateway/connection-auth.ts](openclaw/src/gateway/connection-auth.ts), [openclaw/src/gateway/device-auth.ts](openclaw/src/gateway/device-auth.ts), [openclaw/src/gateway/auth-rate-limit.ts](openclaw/src/gateway/auth-rate-limit.ts).
3. **Server method dispatch.** [openclaw/src/gateway/server.impl.ts](openclaw/src/gateway/server.impl.ts), [openclaw/src/gateway/server-methods-list.ts](openclaw/src/gateway/server-methods-list.ts), and [openclaw/src/gateway/server-methods/](openclaw/src/gateway/server-methods/). Walk the dispatcher to confirm each method goes through the scope check before reaching the handler.
4. **Pairing and device-token surfaces.** [openclaw/src/pairing/](openclaw/src/pairing/) (especially `pairing-store.ts`, `setup-code.ts`, `pairing-challenge.ts`), and gateway-side pairing in `openclaw/src/gateway/device-*.ts`.
5. **Chat slash commands that mutate persisted state.** [openclaw/src/chat/](openclaw/src/chat/), `openclaw/src/gateway/chat-*.ts`, and per-channel slash dispatchers under [openclaw/extensions/](openclaw/extensions/). Look especially for handlers that recognize `/verbose`, `/allowlist`, `/export-session`, `/reset-profile`, `/cron`, `/feedback`.
6. **Heartbeat owner downgrade.** [openclaw/src/cron/heartbeat-policy.ts](openclaw/src/cron/heartbeat-policy.ts) is the table that decides which event classes downgrade owner. The bug shape is "missing case in the switch".
7. **Subagent / sessions_spawn fallback paths.** [openclaw/src/sessions/](openclaw/src/sessions/), [openclaw/src/agents/](openclaw/src/agents/) (look for `subagent`, `spawn`, `delegate`).
8. **Gateway audit surfaces** that already enumerate this layer: [openclaw/src/security/audit-gateway-auth-selection.test.ts](openclaw/src/security/audit-gateway-auth-selection.test.ts), [openclaw/src/security/audit-gateway-http-auth.test.ts](openclaw/src/security/audit-gateway-http-auth.test.ts), [openclaw/src/security/audit-gateway-tools-http.test.ts](openclaw/src/security/audit-gateway-tools-http.test.ts).

## Pattern fingerprints

1. **HTTP route declared without a `requireScope(...)` decorator** while siblings use one. Grep route registration files; find handlers without a scope wrapper.
2. **`operator.write` callable surface that touches** `account.config.*`, `cron.*`, `device.*`, `node.*`, persisted policy, `gateway.controlUi.*`, `verboseLevel`, agent allowFrom.
3. **Slash-command dispatcher that mutates persisted state.** A `chat.send` handler that recognizes `/foo` and writes to disk/config without re-checking scope. Walk every slash command.
4. **Token mint without scope intersection.** `device.token.rotate` that issues a token whose scope set was not derived from the caller's current scope set, or that retains scopes the caller did not have.
5. **Pairing approval without caller-scope check.** `node.pair.approve` / `device.pair.approve` reachable from `operator.write`.
6. **Connect handshake.** WS `connect` resolves device identity from a field the caller sets without verifying.
7. **Subagent / sessions_spawn fallback.** A synthetic `operator.admin` is constructed for a fallback path.
8. **Empty list collapses to "all".** `approvers.length === 0` taken as "approved", or `allowFrom.length === 0` as "any sender".
9. **Heartbeat owner downgrade misses an event class.** Async exec completion / wake events not flowing through the downgrade.

## What to grep for

- `requireScope`, `withScope`, `assertOperatorScope`, `operatorScopes`, `operator.read`, `operator.write`, `operator.admin`, `operator.pairing`, `operator.approvals`.
- `device.token.rotate`, `device.pair.approve`, `node.pair.approve`, `node.invoke`.
- `chat.send`, slash command dispatchers (look for `/verbose`, `/allowlist`, `/export`, `/reset-profile`, `/cron`).
- `account.config = ` / `Object.assign(account.config` / spread shapes that rewrite `account.config.*`.
- `requireOwner`, `isOwnerSender`, `senderIsOwner`.
- `sessions_spawn`, `subagent`, `synthetic admin`.
- HTTP route declaration files (`app.post`, `app.get`, `router.post`, `defineRoute`).
- `heartbeat`, `ownerDowngrade`, `downgradeOwner`.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Effect:     <what privileged thing this reaches — config write / token mint / pairing approve / cron persist>
  RequiredScope: <operator.admin / operator.pairing / etc.>
  PresentedScope: <operator.read / operator.write / unauthenticated / unknown>
  Path:       <route or call chain that reaches the effect>
  Gate:       <file:line of the scope check that should have caught this — or "absent">
  Sink:       <file:line of the privileged effect>
  Reachable:  <documented surface that triggers this — chat.send, HTTP /api/x, slash command, hook>
  Acceptance: <passes SECURITY.md acceptance gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5 broken/risky findings. Keep the report under 1100 words.

## Calibration references

CVE-2026-22172 (WS shared-auth scope elevation, CRITICAL 9.4), CVE-2026-32922 (device.token.rotate scope, 9.4), CVE-2026-32918 (session_status escape, 9.2), CVE-2026-28472 (WS connect device-identity bypass, 9.2), CVE-2026-33577 / CVE-2026-33579 (node.pair.approve scope), CVE-2026-42422 (device.token.rotate role bypass), CVE-2026-41359 (operator.write reaches Telegram admin), CVE-2026-43568 / CVE-2026-42433 / CVE-2026-41379 (chat.send reaches admin config), CVE-2026-43574 (empty approver lists), CVE-2026-42431 (node.invoke browser.proxy), CVE-2026-32045 (tokenless Tailscale auth bypass), CVE-2026-35621 (chat.send writes allowlist), GHSA-67mf, GHSA-vc32, GHSA-m5jp, GHSA-4f8g, GHSA-5wj5, GHSA-5hff, GHSA-2pr2.
