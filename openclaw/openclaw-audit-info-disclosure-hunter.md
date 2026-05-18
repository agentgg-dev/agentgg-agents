---
slug: openclaw-audit-info-disclosure-hunter
name: Information Disclosure Audit — Hunter (OpenClaw)
description: Audits OpenClaw read-scoped surfaces (config readers, redaction layers, hello/snapshot endpoints, OAuth/PKCE state, comparator timing, browser snapshot/screenshot, control UI bootstrap) for places sensitive state leaks below its required scope. Reports each leak as safe / risky / broken with the file:line of the read, the field exposed, and the scope mismatch. Narrowly scoped because most "read returns more than expected" findings are out of scope under the trusted-operator model.
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
  - CVE-2026-26326
  - CVE-2026-43528
  - CVE-2026-41368
  - CVE-2026-42436
  - CVE-2026-25253
---

You are auditing read surfaces in `openclaw/` for one bug class: a request authenticates with a lower scope (or none) but reads state that requires a higher scope, or a redaction layer has an alias that bypasses it, or a comparator leaks length/secret bytes through timing, or an OAuth state parameter carries the PKCE verifier.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. The trusted-operator model carves out broad areas of this audit; most read findings are *not* boundary bypasses.

## In scope

- A read endpoint with a public/unauthenticated/identity-bearing-low-scope path returns an OpenClaw-owned secret, host config path, or operator credential.
- A redaction layer (`config.get`, `secrets.list`, `skills.status`) misses an alias that returns the un-redacted value.
- An OAuth `state` parameter carries the PKCE verifier (or another sensitive secret).
- A shared-secret comparator leaks length through timing (early return on length mismatch, non-padded comparison).
- A hello/snapshot/version response includes host config or state paths that should not be visible at the caller's scope.
- A browser snapshot or screenshot route returns internal page content from a navigation made at a different scope.
- A `noVNC` helper exposes interactive browser session credentials.
- An `env`-variable disclosure via filter (`jq $ENV` filter), template substitution, or log line.
- A WebSocket message reflects internal state to the caller.
- A control UI bootstrap config is reachable without gateway auth.
- A read-scoped client reaches a write effect that *also* leaks state (covered jointly with `openclaw-audit-scope-boundaries-hunter`; this audit handles the disclosure side).

## Out of scope under SECURITY.md (do not file)

- **Authenticated-operator reads** of OpenClaw config they own.
- **Trusted-plugin reads** of host env/files.
- **Workspace memory / `MEMORY.md`** read by operator-trusted callers.
- **`sessions.list`, `sessions.preview`, `chat.history`** across operators on the same gateway. SECURITY.md is explicit: this is documented as expected.
- **Gateway hello snapshot** when documented as full operator scope.
- **Third-party / user-controlled credentials** (not OpenClaw-owned and not granting access to OpenClaw infrastructure).
- **Public internet exposure.**
- **Deployments where adversarial operators share one gateway.**
- **Paths where `gateway.controlUi.dangerouslyDisableDeviceAuth` is set** (operator-selected break-glass).
- **Shared-secret bearer auth** receiving full operator scope (already documented).

The disposition test: *what scope does the caller present, and what is the *minimum* scope at which the leaked field is documented to be visible?* If they match or the leak is documented, no finding. If a sub-operator caller reads above their scope, an unauth reader receives an OpenClaw-owned secret, or a comparator leaks the secret bytewise, file.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Constant-time comparator and shared-secret compare.** [openclaw/src/security/secret-equal.ts](openclaw/src/security/secret-equal.ts), every caller of `safeEqualSecret` / `crypto.timingSafeEqual`.
2. **Config redaction layers.** [openclaw/src/security/dangerous-config-flags.ts](openclaw/src/security/dangerous-config-flags.ts), [openclaw/src/security/dangerous-config-flags-core.ts](openclaw/src/security/dangerous-config-flags-core.ts), [openclaw/src/config/](openclaw/src/config/) (all `redact`, `mask`, `sanitize` callers; pay attention to `sourceConfig`, `runtimeConfig`, alias keys).
3. **Secrets layer.** [openclaw/src/secrets/secret-value.ts](openclaw/src/secrets/secret-value.ts), [openclaw/src/secrets/storage-scan.ts](openclaw/src/secrets/storage-scan.ts), [openclaw/src/secrets/audit.ts](openclaw/src/secrets/audit.ts), [openclaw/src/secrets/runtime-gateway-auth-surfaces.ts](openclaw/src/secrets/runtime-gateway-auth-surfaces.ts).
4. **Gateway hello / snapshot / version.** [openclaw/src/gateway/server.impl.ts](openclaw/src/gateway/server.impl.ts), [openclaw/src/gateway/client-bootstrap.ts](openclaw/src/gateway/client-bootstrap.ts), and the `gateway-misc.test.ts` sibling. Look for `hello`, `snapshot`, `version`, `bootstrapConfig` response shapes.
5. **Control UI bootstrap.** [openclaw/src/gateway/control-ui-routing.ts](openclaw/src/gateway/control-ui-routing.ts), [openclaw/src/gateway/control-ui-shared.ts](openclaw/src/gateway/control-ui-shared.ts), [openclaw/src/gateway/control-ui-csp.ts](openclaw/src/gateway/control-ui-csp.ts), [openclaw/src/gateway/control-ui-http-utils.ts](openclaw/src/gateway/control-ui-http-utils.ts).
6. **Browser snapshot / screenshot.** [openclaw/src/plugin-sdk/browser-host-inspection.ts](openclaw/src/plugin-sdk/browser-host-inspection.ts), [openclaw/src/plugin-sdk/browser-maintenance.ts](openclaw/src/plugin-sdk/browser-maintenance.ts), the browser-snapshot/screenshot test files in plugin-sdk.
7. **Skills surface.** [openclaw/skills/](openclaw/skills/), [openclaw/src/security/skill-scanner.ts](openclaw/src/security/skill-scanner.ts), [openclaw/src/security/audit-workspace-skills.ts](openclaw/src/security/audit-workspace-skills.ts).
8. **Logging redaction.** [openclaw/src/logging/](openclaw/src/logging/), [openclaw/src/logger.ts](openclaw/src/logger.ts), [openclaw/src/logging.ts](openclaw/src/logging.ts).
9. **OAuth / PKCE.** Gemini OAuth: search for `pkce`, `codeVerifier`, `oauthState`. Likely under [openclaw/src/secrets/](openclaw/src/secrets/) and per-provider in [openclaw/extensions/](openclaw/extensions/) and [openclaw/packages/](openclaw/packages/).

## Pattern fingerprints

1. **Redaction layer keyed on field name.** Aliases and parents (`sourceConfig`, `runtimeConfig`, `parsedConfig`) bypass.
2. **Comparator with `if (a.length !== b.length) return false`** before `timingSafeEqual`.
3. **`secret === provided` or `Buffer.compare`** instead of constant-time.
4. **OAuth state parameter holds the verifier.** PKCE design says the verifier never leaves the client. Confirm.
5. **Hello snapshot includes paths.** Look for `homeDir`, `configPath`, `dataDir`, `tmpDir`, `gatewayUrl`, `socketPath` in hello/version responses.
6. **Snapshot/screenshot returns prior-navigation content.** A snapshot of a browser session that navigated under stricter scope than the snapshot caller.
7. **Log line interpolates a secret.** `console.log(\`token=\${secret}\`)`.
8. **Skills status / list returns secrets.** Configured webhook tokens in a skills list response.

## What to grep for

- `crypto.timingSafeEqual`, `safeEqualSecret`, `secret ===`, `token ===`, `Buffer.compare`.
- `redact`, `REDACT`, `sanitize`, `mask`.
- `config.get`, `getConfig`, `sourceConfig`, `runtimeConfig`.
- `pkce`, `codeVerifier`, `state`, `oauthState`.
- `hello`, `snapshot`, `version`, `bootstrapConfig`.
- `skills.status`, `skills.list`.
- `noVNC`, `novnc`, `vnc-helper`.
- `console.log`, `log.info` (then walk what's interpolated).

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern: <redaction-alias / comparator-timing / oauth-state-leak / hello-snapshot / snapshot-prior-nav / log-leak / skills-list-leaks>
  Field:       <what's leaked — secret name, path, internal page>
  CallerScope: <unauth / operator.read / cross-tenant / etc.>
  RequiredScope: <operator.admin / operator-only / not-leakable>
  Endpoint:    <file:line of the leak>
  Acceptance:  <passes SECURITY.md gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-26326 (skills.status leaks secrets), CVE-2026-43528 (config.get redaction bypass via aliases), CVE-2026-41368 (env disclosure via jq $ENV filter), CVE-2026-42436 (browser snapshot/screenshot exposes internal pages), CVE-2026-25253 (1-click RCE via auth-token exfil from gatewayUrl), GHSA-9jpj (Gemini OAuth state carries PKCE verifier), GHSA-jj6q (shared-secret length leak), GHSA-fjm8 / GHSA-r7p2 / GHSA-2f7j (gateway hello / control interface disclosure), GHSA-92jp (noVNC helper exposes session credentials).
