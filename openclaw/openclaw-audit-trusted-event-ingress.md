---
slug: openclaw-audit-trusted-event-ingress
name: Trusted Event Ingress Audit (OpenClaw)
description: 'Audits OpenClaw event/queue producers and consumers for trust transitions where untrusted external input is enqueued onto a channel that downstream code treats as a trusted system event (System: prompt channel, /hooks/wake, agent hook events, exec-event, channel-setup, cron awareness, heartbeat owner). Reports each producer/consumer pair as safe / risky / broken with the file:line of the producer, the consumer that does not re-sanitize, and the trust class crossed.'
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
  - CVE-2026-43534
  - CVE-2026-43566
  - CVE-2026-24764
  - CVE-2026-27485
  - CVE-2026-32040
---

You are auditing event-channel trust transitions in `openclaw/` for one bug class: a payload that originated from an untrusted source (webhook body, external chat sender, channel description, media bytes, workspace .env) reaches a queue tagged "system", "wake", "hook", "exec-event", "channel-setup", "cron", or otherwise consumed by code that does not re-sanitize, and through that path the attacker forges admin-class effects.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. Prompt-injection-only chains are out of scope. This audit looks for the *boundary bypass* that turns prompt injection into a real escalation.

## In scope

- A webhook payload (after passing signature verification) is enqueued as a *trusted system event* without re-sanitization.
- `/hooks/wake` or a mapped wake payload is promoted into the `System:` prompt channel.
- An external chat message (Slack channel description, Discord embed, MSTeams card, Feishu card-action, Matrix room state) is rendered into a trusted prompt or a privileged event without sanitization.
- A media tag in a chat reply is treated as a trusted local-file reference across channels.
- An agent hook event accepts unsanitized external input.
- A cron-awareness event (isolated cron, scheduled task) is recorded as a trusted system event.
- Background runtime output (lower-trust) is injected into trusted `System:` events.
- Local async exec completion misses the intended `exec-event` downgrade.
- A heartbeat owner-downgrade misses an event class that should have demoted.
- Workspace `.env` reaches the System / hook / exec-event channel.
- Channel-setup catalog includes untrusted workspace plugin shadows that execute.
- Stored XSS in Control UI: an external sender's name/avatar is rendered into an inline-script context.
- Image MIME / data-URL injection lands in HTML.
- An iOS A2UI bridge dispatches `agent.request` from untrusted local-network pages.

## Out of scope under SECURITY.md (do not file)

- **Prompt injection alone.** SECURITY.md: prompt injection by itself is not a vulnerability report unless it crosses a boundary.
- **Operator-trusted memory files.** `MEMORY.md` and `memory/*.md` are trusted local operator state. "Attacker writes to memory, then memory_search returns it" is documented as out of scope.
- **Trusted-installed plugin** firing trusted events.
- **`hooks.gmail.allowUnsafeExternalContent` / `hooks.mappings[].allowUnsafeExternalContent`** when the operator has explicitly enabled them.
- **Supplemental-context visibility from non-allowlisted senders** without a documented boundary bypass. This is a documented hardening direction, not a vulnerability.
- **A trusted-installed channel** doing what the channel does.
- **Authorized-sender intentional commands** rendered into the prompt as part of the documented flow.

The disposition test: *what trust class did the input have at ingress, and what trust class does the consumer assume?* If they differ and the consumer's trust class would not have been granted to that ingress, file. If they match (or the consumer re-sanitizes), no finding.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Hook ingress and message-hook mappers.** [openclaw/src/hooks/hooks.ts](openclaw/src/hooks/hooks.ts), [openclaw/src/hooks/internal-hooks.ts](openclaw/src/hooks/internal-hooks.ts), [openclaw/src/hooks/internal-hook-types.ts](openclaw/src/hooks/internal-hook-types.ts), [openclaw/src/hooks/message-hook-mappers.ts](openclaw/src/hooks/message-hook-mappers.ts), [openclaw/src/hooks/policy.ts](openclaw/src/hooks/policy.ts), [openclaw/src/hooks/fire-and-forget.ts](openclaw/src/hooks/fire-and-forget.ts), [openclaw/src/hooks/plugin-hooks.ts](openclaw/src/hooks/plugin-hooks.ts). The `/hooks/wake` to System: pipeline lives here.
2. **Agent prompt assembly and chat sanitize.** [openclaw/src/gateway/agent-prompt.ts](openclaw/src/gateway/agent-prompt.ts), [openclaw/src/gateway/agent-event-assistant-text.ts](openclaw/src/gateway/agent-event-assistant-text.ts), [openclaw/src/gateway/chat-sanitize.ts](openclaw/src/gateway/chat-sanitize.ts), [openclaw/src/gateway/chat-attachments.ts](openclaw/src/gateway/chat-attachments.ts), [openclaw/src/gateway/control-reply-text.ts](openclaw/src/gateway/control-reply-text.ts).
3. **External-content classification.** [openclaw/src/security/external-content.ts](openclaw/src/security/external-content.ts), [openclaw/src/security/external-content-source.ts](openclaw/src/security/external-content-source.ts), [openclaw/src/security/context-visibility.ts](openclaw/src/security/context-visibility.ts), [openclaw/src/security/dm-policy-shared.ts](openclaw/src/security/dm-policy-shared.ts).
4. **Heartbeat owner downgrade.** [openclaw/src/cron/heartbeat-policy.ts](openclaw/src/cron/heartbeat-policy.ts), and the cron isolated-agent surface ([openclaw/src/cron/isolated-agent.ts](openclaw/src/cron/isolated-agent.ts), [openclaw/src/cron/isolated-agent.hook-content-wrapping.test.ts](openclaw/src/cron/isolated-agent.hook-content-wrapping.test.ts)).
5. **Cron awareness, run-log, and isolated-agent.** [openclaw/src/cron/run-log.ts](openclaw/src/cron/run-log.ts), [openclaw/src/cron/run-diagnostics.ts](openclaw/src/cron/run-diagnostics.ts), [openclaw/src/cron/isolated-agent.delivery-awareness.test.ts](openclaw/src/cron/isolated-agent.delivery-awareness.test.ts).
6. **Channel inbound and reply rendering.** [openclaw/src/plugin-sdk/channel-inbound.ts](openclaw/src/plugin-sdk/channel-inbound.ts), [openclaw/src/plugin-sdk/channel-feedback.ts](openclaw/src/plugin-sdk/channel-feedback.ts), [openclaw/src/plugin-sdk/channel-envelope.ts](openclaw/src/plugin-sdk/channel-envelope.ts), [openclaw/extensions/](openclaw/extensions/) inbound handlers, especially channel-description, card-action, and embed-render paths.
7. **Channel-setup catalog and plugin shadows.** [openclaw/src/plugins/](openclaw/src/plugins/), [openclaw/src/security/audit-plugins-trust.ts](openclaw/src/security/audit-plugins-trust.ts), [openclaw/src/security/audit-plugin-readonly-scope.test.ts](openclaw/src/security/audit-plugin-readonly-scope.test.ts), [openclaw/src/security/audit-plugin-code-safety.test.ts](openclaw/src/security/audit-plugin-code-safety.test.ts).
8. **Canvas / a2ui (for the iOS bridge).** [openclaw/src/canvas-host/a2ui.ts](openclaw/src/canvas-host/a2ui.ts), [openclaw/src/canvas-host/a2ui-shared.ts](openclaw/src/canvas-host/a2ui-shared.ts), [openclaw/src/canvas-host/server.ts](openclaw/src/canvas-host/server.ts).
9. **Workspace dotenv override surface (overlap with `openclaw-audit-workspace-dotenv-trust-hunter`).** [openclaw/src/infra/dotenv.ts](openclaw/src/infra/dotenv.ts), [openclaw/src/cli/dotenv.ts](openclaw/src/cli/dotenv.ts).

## Pattern fingerprints

1. **Producer enqueues raw external bytes, consumer reads `payload.text` into the system channel.** Walk every queue producer with an external-source argument, then walk every consumer of that queue.
2. **Owner-downgrade table missing an event type.** A switch/dispatch on event type that explicitly downgrades for some types but not others (the bug is the missing case).
3. **System: prompt rendered with un-escaped external sender name/text.** Confirm escape happens at the prompt-render layer, not only at the chat-render layer.
4. **HTML/XSS sink that does not escape.** Inline `<script>`, `dangerouslySetInnerHTML`, template-literal HTML, data-URL with attacker MIME.
5. **Channel-setup catalog reads workspace plugin metadata as trusted.** Untrusted shadow execution at startup.
6. **Hook mapping templates bypass session-key opt-in.** Template substitution evaluated in a context that does not enforce the opt-in flag.
7. **Cross-channel MEDIA paths.** A media tag from channel A consumed as trusted by channel B.
8. **iOS A2UI dispatch trusts local-network pages without origin pinning.**

## What to grep for

- `enqueue`, `emit`, `dispatchEvent`, `publishEvent`, `pushEvent`, `addEvent`.
- `System:` prompt prefix, `systemChannel`, `renderSystemPrompt`.
- `hooks.wake`, `/hooks/wake`, `wakePayload`, `wakeEvent`.
- `agentHookEvent`, `hookEvent`, `runHook`.
- `exec-event`, `execEvent`, `downgradeOwner`, `ownerDowngrade`.
- `cronAwarenessEvent`, `scheduledEvent`.
- `dangerouslySetInnerHTML`, `innerHTML`, `<script`, `data:text/html`, `data:image/`.
- `channelSetup`, `setupCatalog`, `pluginShadow`.
- `allowUnsafeExternalContent`.
- `A2UIRequest`, `agent.request` dispatch.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Producer:    <file:line where untrusted bytes enter the queue>
  Consumer:    <file:line where the payload is read as trusted>
  TrustGap:    <ingress class -> consumer assumed class — e.g. webhook-body -> System:>
  Sanitize:    <where re-sanitization should happen, or "absent">
  Trigger:     <documented surface — webhook POST / chat reply / channel description / hook mapping / cron / iOS bridge>
  Attacker:    <who controls the bytes>
  Effect:      <admin-class effect / RCE / file read / persisted-config write / Control UI XSS>
  Acceptance:  <passes SECURITY.md gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-43534 (agent hook events from unsanitized external input, CRITICAL 9.3), CVE-2026-43566 (heartbeat owner downgrade missed webhook wake events, CRITICAL 9.1), CVE-2026-24764 (Slack channel description prompt injection RCE), CVE-2026-27485 (stored XSS in Control UI assistant name/avatar), CVE-2026-32040 (HTML injection via image MIME), CVE-2026-32037 (MSTeams redirect-chain media allowlist), CVE-2026-43571 (channel-setup catalog plugin shadows), CVE-2026-43569 (workspace provider auth auto-enable plugins), CVE-2026-41398 (iOS A2UI), GHSA-jf56 (/hooks/wake into System:), GHSA-gfmx (background runtime output into System:), GHSA-g375 (heartbeat downgrade missed exec completion), GHSA-57r2 (cron awareness as trusted), GHSA-2qrv (channel shadows execute at setup), GHSA-m563 (OpenShell mirror to workspace hooks), GHSA-2xcp (hook mapping templates bypass session-key), GHSA-jx3c (workspace .env overrides hooks root).
