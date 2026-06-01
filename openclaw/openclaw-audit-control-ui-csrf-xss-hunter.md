---
slug: openclaw-audit-control-ui-csrf-xss-hunter
name: Control UI CSRF / Stored XSS Audit — Hunter (OpenClaw)
description: Audits OpenClaw Control UI / loopback browser-mutation endpoints / canvas / a2ui surfaces for CSRF (no origin / Referer / SameSite / token check on a state-changing route reachable from a user's browser) and stored XSS (untrusted external bytes rendered into inline-script or HTML context). Reports each route as safe / risky / broken with the file:line of the handler, the sink, and the documented attacker primitive.
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
    - { regex: "\\.(post|put|patch|delete)\\s*\\(|csrf|sameSite|referer|\\borigin\\b", label: "state-changing route / CSRF check" }
    - { regex: "innerHTML|dangerouslySetInnerHTML|<script|\\.render\\s*\\(", label: "HTML / script sink" }
references:
  - CVE-2026-26317
  - CVE-2026-27485
  - CVE-2026-32040
  - CVE-2026-43532
  - CVE-2026-41398
---

You are auditing the Control UI, loopback browser-mutation endpoints, canvas, a2ui, and assistant-rendering surfaces in `openclaw/` for one bug class: a state-changing request that originates from the operator's browser is accepted without origin/CSRF protection, *or* attacker-supplied text reaches an HTML / inline-script sink without escape.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. The web interface is **local-use only** by design and is not hardened for public exposure.

## In scope

- A loopback / trusted-proxy state-changing endpoint accepts a cross-origin POST without origin/Referer/CSRF-token validation.
- HTTP operator endpoints in trusted-proxy mode lack browser-origin validation.
- The Control UI bootstrap config is reachable without gateway auth.
- A canvas or a2ui route that is documented as auth-bound silently accepts requests from an unauth origin in some configurations.
- An assistant message field (name, avatar URL, tool result, channel description, system event) is rendered into an inline-script context, a `dangerouslySetInnerHTML`, or a `data:text/html` sink without escape.
- An image MIME / data-URL is interpolated into HTML without validation, allowing HTML injection.
- A Discord cover image / channel description / Slack channel description / MSTeams card / Feishu card-action lands in the Control UI render layer without escape (overlap with `openclaw-audit-trusted-event-ingress-hunter`; this audit handles the HTML-sink side).
- An iOS A2UI bridge dispatches `agent.request` from a local-network page that the Control UI does not pin origin against.

## Out of scope under SECURITY.md (do not file)

- **Public internet exposure** (`gateway.bind: "all"`, `0.0.0.0`). Documented as out of scope; surfaced as a `security audit` warning.
- **`gateway.controlUi.dangerouslyDisableDeviceAuth`** when set by the operator (break-glass).
- **Canvas LAN/tailnet visibility** when the operator chose that deployment with Gateway auth.
- **Same-origin operator browser** running the operator's own commands (it's the operator).
- **Trusted-installed plugin** rendering its own UI.
- **Authorized sender** invoking a documented chat command that mutates UI state.
- **Missing HSTS** on default local/loopback deployments.
- **Prompt-injection-only chains** that do not reach a state-changing endpoint or HTML sink.

The disposition test: *can a page the user opens in another tab cause a state change in the Control UI, or can attacker-supplied bytes reach an HTML/script context without escape?* If yes, file. If the route requires same-origin operator-presented credentials (cookie + double-submit token, or origin-locked Authorization), no finding.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Control UI route registration and CSP.** [openclaw/src/gateway/control-ui-routing.ts](openclaw/src/gateway/control-ui-routing.ts), [openclaw/src/gateway/control-ui-csp.ts](openclaw/src/gateway/control-ui-csp.ts), [openclaw/src/gateway/control-ui-http-utils.ts](openclaw/src/gateway/control-ui-http-utils.ts), [openclaw/src/gateway/control-ui-shared.ts](openclaw/src/gateway/control-ui-shared.ts), [openclaw/src/gateway/control-ui-contract.ts](openclaw/src/gateway/control-ui-contract.ts), [openclaw/src/gateway/control-ui-links.ts](openclaw/src/gateway/control-ui-links.ts).
2. **Trusted-proxy and auth mode.** [openclaw/src/gateway/auth-mode-policy.ts](openclaw/src/gateway/auth-mode-policy.ts), [openclaw/src/gateway/auth-config-utils.ts](openclaw/src/gateway/auth-config-utils.ts), [openclaw/src/gateway/auth-install-policy.ts](openclaw/src/gateway/auth-install-policy.ts).
3. **Canvas / a2ui.** [openclaw/src/canvas-host/server.ts](openclaw/src/canvas-host/server.ts), [openclaw/src/canvas-host/a2ui.ts](openclaw/src/canvas-host/a2ui.ts), [openclaw/src/canvas-host/a2ui-shared.ts](openclaw/src/canvas-host/a2ui-shared.ts), [openclaw/src/canvas-host/file-resolver.ts](openclaw/src/canvas-host/file-resolver.ts).
4. **Assistant render / chat sanitize (the XSS sink layer).** [openclaw/src/gateway/agent-event-assistant-text.ts](openclaw/src/gateway/agent-event-assistant-text.ts), [openclaw/src/gateway/chat-sanitize.ts](openclaw/src/gateway/chat-sanitize.ts), [openclaw/src/gateway/chat-display-projection.ts](openclaw/src/gateway/chat-display-projection.ts), [openclaw/src/gateway/control-reply-text.ts](openclaw/src/gateway/control-reply-text.ts), [openclaw/src/gateway/assistant-identity.ts](openclaw/src/gateway/assistant-identity.ts).
5. **Native UI bridges (out-of-tree but the iOS A2UI bug class lives here).** [openclaw/apps/](openclaw/apps/) (macos, ios, android) when present in the checkout. If not, treat the iOS A2UI surface from `src/canvas-host/a2ui*` as the auditable boundary.
6. **Existing audit surface.** [openclaw/src/security/audit-gateway-http-auth.test.ts](openclaw/src/security/audit-gateway-http-auth.test.ts), [openclaw/src/security/audit-gateway-tools-http.test.ts](openclaw/src/security/audit-gateway-tools-http.test.ts), [openclaw/src/security/audit-loopback-logging.test.ts](openclaw/src/security/audit-loopback-logging.test.ts), [openclaw/src/security/audit-gateway-exposure.test.ts](openclaw/src/security/audit-gateway-exposure.test.ts), [openclaw/src/security/dangerous-config-flags.ts](openclaw/src/security/dangerous-config-flags.ts).

## Pattern fingerprints

1. **POST/PUT/DELETE handler accepts JSON body with no Origin/Referer check** and no CSRF token.
2. **Trusted-proxy mode** assumes the proxy strips/sets origin; confirm the gateway re-checks.
3. **Authorization header alone**, when the request can be initiated by a cross-origin form (the browser will not include `Authorization` by default, but `cookie`-based auth on the same handler is the bug).
4. **`dangerouslySetInnerHTML` / template-literal HTML** building from a field whose source is an external sender / channel description / tool result.
5. **`data:text/html` or `data:image/...,<svg onload=...>`** built from an unvalidated MIME.
6. **Inline `<script>${value}</script>`** with `value` carrying assistant text.
7. **Avatar/name fields** rendered inline without escape.
8. **Bootstrap config endpoint** missing the gateway-auth wrapper.
9. **iOS A2UI dispatch** without origin pinning to the trusted Control UI host.

## What to grep for

- `app.post`, `app.put`, `app.delete`, `router.post`, `defineRoute`.
- `req.headers.origin`, `req.headers.referer`, `Origin`, `Referer`, `csrfToken`, `XSRF`, `SameSite`.
- `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `<script`, `\${`.
- `data:text/html`, `data:image/`.
- `gateway.controlUi.dangerouslyDisableDeviceAuth`.
- `bootstrapConfig`, `controlUiBootstrap`, `bootstrap-config`.
- `assistantName`, `assistantAvatar`, `displayName`, `name`, `avatar`.
- `A2UIRequest`, `agent.request`.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern: <csrf-no-origin / csrf-trusted-proxy / xss-html-sink / xss-inline-script / xss-data-url / bootstrap-no-auth / a2ui-origin>
  Route:       <file:line of the handler or the render call>
  Sink:        <state-change effect / DOM mutation / inline script>
  Source:      <where attacker-controlled bytes / cross-origin request enters>
  Auth:        <what the route requires currently>
  Acceptance:  <passes SECURITY.md gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-26317 (CSRF through loopback browser mutation), CVE-2026-27485 (stored XSS in Control UI assistant name/avatar), CVE-2026-32040 (HTML injection via image MIME data-URL), CVE-2026-43532 (Discord event cover images bypass sandbox media normalization), CVE-2026-32037 (MSTeams redirect-chain media allowlist bypass), GHSA-2xp4 (HTTP operator endpoints lack browser-origin in trusted-proxy mode), GHSA-93rg (gateway control UI bootstrap config required gateway auth), CVE-2026-41398 (iOS A2UI bridge trusts local-network pages).
