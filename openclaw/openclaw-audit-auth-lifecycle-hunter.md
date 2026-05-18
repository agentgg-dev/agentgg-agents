---
slug: openclaw-audit-auth-lifecycle-hunter
name: Auth Lifecycle Audit — Hunter (OpenClaw)
description: Audits OpenClaw token, session, secret, and dedupe state through their lifecycle (rotation, revocation, config reload, device removal, replay-cache, queue context). Reports each holder of long-lived auth/dedupe state as safe / risky / broken with the file:line where the lifecycle event happens and the file:line of the holder that does not observe it.
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
  - CVE-2026-34503
  - CVE-2026-41916
  - CVE-2026-43535
  - CVE-2026-32987
  - CVE-2026-41351
---

You are auditing auth-state lifecycle in `openclaw/` for one bug class: once a credential, session, dedupe key, or authorization context is established, the gateway forgets to invalidate it on rotation, reload, removal, or replay; or it keys a dedupe cache on the wrong field and lets an attacker replay across boundaries.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. The trusted-operator model and shared-secret bearer auth carve out areas of this audit.

## In scope

- An active WebSocket session survives a token rotation that should have invalidated it.
- A bearer token remains valid after a `SecretRef` rotation or operator config reload.
- A `resolvedAuth` closure captures stale auth across config reload.
- An existing-session browser route bypasses post-reload SSRF policy because the session was created under the prior policy.
- A replay dedupe cache keys on a non-canonical input (raw header, unsigned event ID, base64 with multiple representations) so an attacker re-encodes and replays.
- A dedupe key collides across chats / senders / accounts and suppresses legitimate messages or accepts a replay.
- Collect-mode queue batches reuse the previous-batch authorization context for a sender that was not authorized for the current batch.
- Concurrent async auth attempts bypass a shared rate-limit budget by racing.
- Pairing pending caps enforced per channel instead of per account.
- A fake DeviceToken bypasses shared auth rate limiting by exhausting an unguarded slot.
- A bootstrap setup-code is replayable.
- Plivo/Twilio/Telnyx replay mutates in-process callback origin before replay rejection.

## Out of scope under SECURITY.md (do not file)

- **Trusted-operator session retention** by intentional design (loopback Control UI sessions preserved across operator-driven token rotation when documented).
- **`sessionKey` as an authorization boundary.** Routing control, not auth.
- **Operator-initiated secret rotation** that the operator did not configure to be eager.
- **Multi-tenant adversarial assumptions.** "Operator A's session should not see Operator B's data after rotation."
- **Heuristic / parity findings** about which event classes the heartbeat downgrade table covers without a concrete escalation.
- **Pure performance** issues from cache eviction or TTL choices.

The disposition test: *what is the documented invalidation event, and what holder of long-lived state does not observe it?* If the holder retains capability that the operator-driven event was meant to revoke, file. If the operator did not request invalidation, no finding.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Gateway auth resolution (cached / closure-captured).** [openclaw/src/gateway/auth.ts](openclaw/src/gateway/auth.ts), [openclaw/src/gateway/auth-resolve.ts](openclaw/src/gateway/auth-resolve.ts), [openclaw/src/gateway/auth-surface-resolution.ts](openclaw/src/gateway/auth-surface-resolution.ts), [openclaw/src/gateway/auth-token-resolution.ts](openclaw/src/gateway/auth-token-resolution.ts), [openclaw/src/gateway/auth-rate-limit.ts](openclaw/src/gateway/auth-rate-limit.ts), [openclaw/src/gateway/connection-auth.ts](openclaw/src/gateway/connection-auth.ts), [openclaw/src/gateway/credentials.ts](openclaw/src/gateway/credentials.ts), [openclaw/src/gateway/credentials-secret-inputs.ts](openclaw/src/gateway/credentials-secret-inputs.ts).
2. **Config reload, hot-swap.** [openclaw/src/gateway/config-reload.ts](openclaw/src/gateway/config-reload.ts), [openclaw/src/gateway/config-reload-settings.ts](openclaw/src/gateway/config-reload-settings.ts), [openclaw/src/gateway/config-diff.ts](openclaw/src/gateway/config-diff.ts), [openclaw/src/gateway/server.reload.test.ts](openclaw/src/gateway/server.reload.test.ts). The `resolvedAuth`-stale-after-reload bug class lives here.
3. **Device token rotation and pairing.** [openclaw/src/gateway/device-auth.ts](openclaw/src/gateway/device-auth.ts), [openclaw/src/pairing/pairing-store.ts](openclaw/src/pairing/pairing-store.ts), [openclaw/src/pairing/pairing-challenge.ts](openclaw/src/pairing/pairing-challenge.ts), [openclaw/src/pairing/setup-code.ts](openclaw/src/pairing/setup-code.ts), [openclaw/src/pairing/pairing-messages.ts](openclaw/src/pairing/pairing-messages.ts).
4. **Constant-time and shared-secret comparators.** [openclaw/src/security/secret-equal.ts](openclaw/src/security/secret-equal.ts) and every caller of `safeEqualSecret` / `crypto.timingSafeEqual`.
5. **Sessions, WS lifecycle.** [openclaw/src/sessions/session-lifecycle-events.ts](openclaw/src/sessions/session-lifecycle-events.ts), [openclaw/src/sessions/session-id-resolution.ts](openclaw/src/sessions/session-id-resolution.ts), [openclaw/src/gateway/handshake-timeouts.ts](openclaw/src/gateway/handshake-timeouts.ts), [openclaw/src/gateway/session-reset-service.ts](openclaw/src/gateway/session-reset-service.ts).
6. **Replay / dedupe / nonce caches.** Voice-call replay protection: [openclaw/extensions/voice-call/src/](openclaw/extensions/voice-call/src/) (the seed agent for webhook-ingress already cites `webhook-security.ts` here). Zalo replay dedupe: [openclaw/extensions/zalo/src/](openclaw/extensions/zalo/src/). Generic dedupe primitives in [openclaw/src/plugin-sdk/](openclaw/src/plugin-sdk/) (`createClaimableDedupe`, channel-inbound-debounce.ts).
7. **Pre-auth rate-limit and in-flight budget.** [openclaw/src/plugin-sdk/webhook-memory-guards.ts](openclaw/src/plugin-sdk/webhook-memory-guards.ts), [openclaw/src/gateway/auth-rate-limit.ts](openclaw/src/gateway/auth-rate-limit.ts), [openclaw/src/gateway/control-plane-rate-limit.ts](openclaw/src/gateway/control-plane-rate-limit.ts).
8. **Collect-mode queue context.** [openclaw/src/plugin-sdk/channel-inbound.ts](openclaw/src/plugin-sdk/channel-inbound.ts), [openclaw/src/plugin-sdk/channel-inbound-debounce.ts](openclaw/src/plugin-sdk/channel-inbound-debounce.ts), [openclaw/src/infra/session-delivery-queue-storage.ts](openclaw/src/infra/session-delivery-queue-storage.ts).

## Pattern fingerprints

1. **Holder of resolved auth captured at construction.** A closure or an instance field reads `auth` once at constructor time and never re-reads after reload.
2. **Session table not iterated on rotation.** The token-rotate path mints a new token but does not iterate live sessions and close those bound to the prior token.
3. **Dedupe key over raw input.** `cache.has(rawHeader)` instead of `cache.has(canonicalize(rawHeader))`. Base64 has padded/unpadded and standard/url-safe forms.
4. **Dedupe key without scope.** Key is `(eventId)` instead of `(account, channel, eventId)` so an attacker collides keys across senders.
5. **Race window in async auth.** Two concurrent requests both pass `count < limit`, then both increment.
6. **Reload swaps config but does not invalidate cached resolved values.** `resolvedAuth`, `resolvedScopes`, `resolvedAllowlist` cached.
7. **Pending-cap enforced at the wrong granularity.** Per channel where the documented limit is per account.
8. **Replay rejection happens after a side effect.** Plivo "mutates in-process callback origin before replay rejection" pattern.
9. **Bootstrap or setup code reusable.** Single-use code accepted twice.

## What to grep for

- `tokenRotate`, `rotateToken`, `device.token.rotate`, `revokeToken`.
- `closeAllSessions`, `iterateSessions`, `terminateSessions`, `disconnectAll`.
- `secretRef`, `SecretRef`, `resolveSecret`, `cacheSecret`.
- `resolvedAuth`, `cachedAuth`, `cachedScopes`.
- `dedupe`, `replayCache`, `nonceCache`, `seenEvents`, `recentEvents`.
- `canonicalize`, `normalizeHeader`, `Buffer.from(.., "base64").toString("base64")`.
- `inflight`, `inFlight`, `inflightLimiter`, `concurrentBudget`.
- `pendingCap`, `pendingPair`, `maxPending`.
- `configReload`, `reloadConfig`, `onConfigChange`, `watchConfig`.
- `setupCode`, `bootstrapCode`, `pairingCode`.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern: <stale-closure / session-survives-rotation / dedupe-key-non-canonical / dedupe-key-no-scope / race-shared-budget / reload-cached / pending-cap-granularity / replay-after-side-effect / bootstrap-replay>
  Holder:      <file:line where stale state lives>
  Event:       <file:line of the rotate/reload/revoke/cache that should have invalidated>
  Trigger:     <operator action that should have taken effect — token rotate, config reload, device removal>
  Attacker:    <who exploits — operator-removed device, holder of revoked token, replay attacker, racing concurrent requests>
  Effect:      <retained capability / replay accepted / cross-sender suppression / budget bypass>
  Acceptance:  <passes SECURITY.md gate? yes / no — and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-34503 (incomplete WS termination on device removal / token revocation), CVE-2026-41916 (stale auth on config reload), CVE-2026-43535 (collect-mode queue reuses last sender authorization), CVE-2026-43573 (existing-session browser bypasses SSRF policy), CVE-2026-32987 (bootstrap setup-code replay, CRITICAL 9.3), CVE-2026-32053 (Twilio replay via randomized event ID), CVE-2026-41351 (replay bypass via base64 re-encode), GHSA-rxmx (Zalo replay dedupe collision), GHSA-xmxx (gateway re-resolves bearer after SecretRef rotation), GHSA-q8ff (webhooks SecretRef route secret valid after rotation), GHSA-5h3f (WS sessions survive shared gateway token rotation), GHSA-wwc3 (device.token.rotate does not terminate WS), GHSA-25wv (concurrent async auth bypasses rate limit), GHSA-mf69 (pairing pending caps per channel instead of per account), GHSA-w9f5 (fake DeviceToken bypasses rate limit), GHSA-cw28 (Plivo replay mutates origin before rejection), GHSA-68x5 (resolvedAuth closure stale).
