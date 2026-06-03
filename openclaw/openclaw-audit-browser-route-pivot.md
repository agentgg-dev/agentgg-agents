---
slug: openclaw-audit-browser-route-pivot
name: Browser Route Pivot / SSRF Audit (OpenClaw)
description: Audits OpenClaw browser-automation and SSRF-guarded fetch surfaces for places attacker-controlled (or model-driven) navigation/interaction reaches an internal address, the cloud-metadata endpoint, a different origin, or a local file. Reports each route as safe / risky / broken with the file:line of the SSRF guard, the navigation primitive, and the bypass shape (IPv4-mapped IPv6, DNS rebinding, trailing-dot host, cross-origin redirect, second-hop CDP, interaction-triggered navigation).
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
  - CVE-2026-26324
  - CVE-2026-43527
  - CVE-2026-28458
  - CVE-2026-43576
  - CVE-2026-35629
---

You are auditing browser-control routes (`browser.request`, `/cdp`, `/__openclaw__/canvas`, `/__openclaw__/a2ui`, snapshot/screenshot, press/type/click, tabs action, profile creation), SSRF-guarded fetch helpers (`fetchWithSsrFGuard`), and channel-extension media fetch paths in `openclaw/` for one bug class: an attacker (or a model output not behind owner-only tool policy) reaches an internal address, the cloud-metadata service, a different origin, or a local file by routing around the SSRF guard or the navigation policy.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. SSRF on the operator-managed proxy-routing feature is largely out of scope.

## In scope

- The SSRF guard rejects `127.0.0.1` / `::1` but a representation of localhost reaches it (IPv4-mapped IPv6 long form, trailing dot, DNS rebinding, decimal/octal IP, IDN, mixed-case loopback).
- Default policy permits private-network navigation when documentation says it should not.
- A browser interaction primitive (press, type, click, scroll, snapshot, screenshot, navigate, tabs.select, tabs.close, profile creation, /cdp profile creation, /cdp /json/version) bypasses the policy that protected the top-level URL.
- A cross-origin redirect on a fetch helper (`fetchWithSsrFGuard`, media fetch, attachment download) replays an unsafe request body or leaks the Authorization header.
- A second-hop SSRF: the first URL is allowed; the response (CDP `/json/version`, OpenAPI redirect, server-side fetch) directs the client to a second URL that is not re-validated.
- An unauthenticated `/cdp` WebSocket grants cross-tab cookie access.
- A channel-extension media fetch (Zalo, QQBot, MSTeams, generic channel base URL) is not run through the SSRF guard.
- The sandbox CDP relay binds to `0.0.0.0`.
- Wide-area discovery accepts arbitrary DNS authority and exfiltrates credentials.
- The iOS A2UI bridge dispatches `agent.request` from arbitrary local-network pages.
- An existing-session browser interaction route bypasses post-reload SSRF policy.
- An interaction-triggered navigation crosses the policy that the explicit-navigate route would have blocked.

## Out of scope under SECURITY.md (do not file)

- **Operator-managed proxy-routing feature** when the demonstrated mitigation is to enable / configure `proxy.enabled` with a filtering `proxy.proxyUrl`. The external proxy's destination policy is operator infrastructure, not an OpenClaw-controlled boundary.
- **Process-local HTTP clients** reaching internal/metadata destinations when proxy routing is disabled or missing. SECURITY.md is explicit: this is operator infrastructure.
- **Canvas host network-visibility** on trusted node scenarios (LAN/tailnet) is intentional and documented.
- **`canvas.eval`, browser evaluate/script execution, direct `node.invoke` execution** treated as vulnerabilities without a separate auth/sandbox/policy bypass.
- **DNS rebinding** alone, without a demonstrated reach into an internal/metadata destination through an OpenClaw-controlled boundary.
- **Public internet exposure** of the gateway.

The disposition test: *with the documented operator config and the docs' deployment model, does the model output or external request reach a destination the SSRF guard, the browser policy, or the auth boundary should have blocked?* If yes, file. If no, hardening.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **SSRF and fetch-guard primitives.** [openclaw/src/infra/net/ssrf.ts](openclaw/src/infra/net/ssrf.ts), [openclaw/src/infra/net/fetch-guard.ts](openclaw/src/infra/net/fetch-guard.ts), [openclaw/src/infra/net/fetch-guard.ssrf.test.ts](openclaw/src/infra/net/fetch-guard.ssrf.test.ts), [openclaw/src/infra/net/proxy/](openclaw/src/infra/net/proxy/). Read these first — every guard rule the bug-class has had a CVE against lives here.
2. **Browser control via plugin-sdk.** Browser code is *not* in `src/browser/`. It lives under `src/plugin-sdk/browser-*`: [openclaw/src/plugin-sdk/browser-bridge.ts](openclaw/src/plugin-sdk/browser-bridge.ts), [openclaw/src/plugin-sdk/browser-cdp.ts](openclaw/src/plugin-sdk/browser-cdp.ts), [openclaw/src/plugin-sdk/browser-config.ts](openclaw/src/plugin-sdk/browser-config.ts), [openclaw/src/plugin-sdk/browser-control-auth.ts](openclaw/src/plugin-sdk/browser-control-auth.ts), [openclaw/src/plugin-sdk/browser-host-inspection.ts](openclaw/src/plugin-sdk/browser-host-inspection.ts), [openclaw/src/plugin-sdk/browser-maintenance.ts](openclaw/src/plugin-sdk/browser-maintenance.ts), [openclaw/src/plugin-sdk/browser-node-host.ts](openclaw/src/plugin-sdk/browser-node-host.ts), [openclaw/src/plugin-sdk/browser-profiles.ts](openclaw/src/plugin-sdk/browser-profiles.ts).
3. **Canvas / a2ui surface.** [openclaw/src/canvas-host/server.ts](openclaw/src/canvas-host/server.ts), [openclaw/src/canvas-host/a2ui.ts](openclaw/src/canvas-host/a2ui.ts), [openclaw/src/canvas-host/a2ui-shared.ts](openclaw/src/canvas-host/a2ui-shared.ts), [openclaw/src/canvas-host/file-resolver.ts](openclaw/src/canvas-host/file-resolver.ts).
4. **Generic fetch helpers.** [openclaw/src/web-fetch/runtime.ts](openclaw/src/web-fetch/runtime.ts), [openclaw/src/web-fetch/content-extractors.runtime.ts](openclaw/src/web-fetch/content-extractors.runtime.ts), [openclaw/src/agents/tools/](openclaw/src/agents/tools/) (look for `web-fetch.ts`, `pdf-tool.ts`, anything that downloads remote bytes), [openclaw/src/plugin-sdk/security-runtime.ts](openclaw/src/plugin-sdk/security-runtime.ts), [openclaw/src/media/web-media.ts](openclaw/src/media/web-media.ts), [openclaw/src/media/store.ts](openclaw/src/media/store.ts).
5. **Per-channel media fetch paths.** [openclaw/extensions/zalo/src/](openclaw/extensions/zalo/src/), [openclaw/extensions/qqbot/src/](openclaw/extensions/qqbot/src/), [openclaw/extensions/msteams/src/](openclaw/extensions/msteams/src/), [openclaw/extensions/discord/src/](openclaw/extensions/discord/src/), [openclaw/extensions/feishu/src/](openclaw/extensions/feishu/src/) (look for `upload`, `media`, `fetch`, `download`).
6. **Existing audit surface.** [openclaw/src/security/audit-sandbox-browser.test.ts](openclaw/src/security/audit-sandbox-browser.test.ts), [openclaw/src/security/audit-loopback-logging.test.ts](openclaw/src/security/audit-loopback-logging.test.ts), [openclaw/src/security/audit-gateway-exposure.test.ts](openclaw/src/security/audit-gateway-exposure.test.ts).

## Pattern fingerprints

1. **Hostname check on string form, not normalized form.** `host === "localhost"` accepts `localhost.`, `LocalHost`, `[::ffff:127.0.0.1]`, `2130706433`, `0177.0.0.1`, IDN homographs. Confirm normalization happens *before* the check.
2. **One-shot SSRF guard at top-level navigation.** A second hop (response redirect, embedded iframe, CDP `/json/version`, OpenAPI follow) is not re-validated.
3. **Cross-origin redirect replays body or Authorization.** A fetch helper that re-issues with the same body/headers when the response is 3xx to a different origin.
4. **Existing-session route bypass.** A route that re-uses a browser session created under a stricter policy and now skips SSRF on subsequent calls.
5. **Channel base URL not guarded.** Operator config provides a base URL; the channel calls it with `fetch` directly. Confirm the call path goes through `fetchWithSsrFGuard` (or equivalent).
6. **Interaction triggers navigation.** A press/type/click/scroll handler causes a navigation that the navigate-route guard would have rejected.
7. **CDP relay or canvas binding to non-loopback by default.** Default config exposes the CDP relay or canvas to LAN.
8. **DNS authority acceptance.** Wide-area discovery accepts arbitrary DNS responses.

## What to grep for

- `fetchWithSsrFGuard`, `withSsrfGuard`, `ssrfDeny`, `isPrivateAddress`, `isLoopbackHost`, `loopbackHostnames`, `validateHttpUrl`, `assertNotLocal`.
- `dns.lookup`, `getaddrinfo`, `URL`, `URL.canParse`, `new URL`.
- `127.0.0.1`, `::1`, `localhost`, `metadata.google.internal`, `169.254.169.254`.
- `redirect`, `followRedirects`, `maxRedirects`, `redirected`, `Location`.
- `navigate`, `goto`, `newPage`, `pages.create`, `tabs`, `bringToFront`.
- `/cdp`, `cdpRelay`, `puppeteer`, `playwright`, `chromium`, `devtools`.
- `0.0.0.0`, `bind: "all"`, `host: "0.0.0.0"`.
- `Authorization`, `headers["authorization"]`, `req.headers["cookie"]` (look for redirect-replay leaks).

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Surface:    <browser route / cdp ws / fetchHelper / channel media fetch / canvas / a2ui>
  Bypass:     <ipv4-mapped-ipv6 / trailing-dot / dns-rebind / second-hop / cross-origin-redirect-body / existing-session / interaction-nav / 0.0.0.0-bind>
  Guard:      <file:line of SSRF/navigation guard call — or "absent">
  Sink:       <file:line of fetch/navigate/spawn>
  Attacker:   <model output / unauthenticated client / authenticated operator with operator.write only / cross-origin browser tab>
  Reach:      <internal addr / metadata / different origin / local file / cookies of another tab>
  Acceptance: <passes SECURITY.md gate? yes / no — and which clause if not (operator-managed proxy is the typical "no")>
```

End with a "Top issues to file" list of up to 5. Keep report under 1100 words.

## Calibration references

CVE-2026-26324 (IPv4-mapped IPv6), CVE-2026-43527 (browser SSRF default private-network), CVE-2026-26317 (loopback CSRF), CVE-2026-28458 (unauth /cdp WS cross-tab), CVE-2026-43577 / CVE-2026-43573 / CVE-2026-42439 (browser interaction routes), CVE-2026-43576 (second-hop /json/version), CVE-2026-42436 (snapshot/screenshot internal pages), CVE-2026-40037 (cross-origin body replay), CVE-2026-41345 (Authorization leak across redirect), CVE-2026-35629 (unguarded channel base URLs), CVE-2026-41912 (interaction-triggered navigation), CVE-2026-43526 (QQBot reply media SSRF), CVE-2026-6011 (web-fetch SSRF), CVE-2026-41393 (DNS authority acceptance), CVE-2026-41398 (iOS A2UI), GHSA-525j (CDP on 0.0.0.0), GHSA-xq94 (DNS rebinding), GHSA-f5fm (trailing-dot localhost), GHSA-2hh7 (Zalo SSRF), GHSA-c4qg (QQBot SSRF), GHSA-j4c5 (CDP profile creation).
