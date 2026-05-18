---
slug: openclaw-audit-preauth-amplification-hunter
name: Pre-auth Amplification Audit — Hunter (OpenClaw)
description: Audits OpenClaw pre-auth ingress paths (webhook bodies, WebSocket upgrades, base64 media decoders, archive extractors, audio preflight, JWKS fetch on inbound auth, Nostr inbound DM crypto) for places a small attacker request causes large server work *before* the auth boundary. Narrowly scoped to amplification or limit-bypass; pure performance DoS is explicitly out of scope under SECURITY.md.
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
  - CVE-2026-28478
  - CVE-2026-29609
  - CVE-2026-29612
  - CVE-2026-32062
  - CVE-2026-41399
---

You are auditing pre-auth ingress in `openclaw/` for one bug class: a small unauthenticated request causes large memory, CPU, or filesystem work *before* the auth boundary, providing an asymmetric amplification primitive.

Read [.claude/SECURITY.md](.claude/SECURITY.md) before triaging. **Pure performance is explicitly out of scope.** Reports whose only impact is transient extra memory / CPU / allocation work from decoding, base64 expansion, transcoding, or format conversion *after* input passed configured limits are hardening. This audit looks specifically for *amplification across the limit* or *crash, persistent exhaustion, or boundary bypass*.

## In scope

- A webhook body of N bytes causes >>N bytes of server work pre-auth (unbounded buffering, base64 decode-before-size-estimate, JSON parse before signature check, JWKS fetch before issuer check).
- Pre-auth body read uses the post-auth profile (>64KB / >5s) on a webhook handler.
- A WebSocket upgrade path performs unbounded work pre-auth (oversized frame accept, unbounded message accumulator).
- A media stream accepts oversized frames before the connection is authenticated.
- An archive (ZIP/TAR) expands at a ratio that is not capped, or has unbounded entry count, or accepts an unguarded mode.
- A Nostr (or similar) inbound DM triggers crypto work before sender policy enforcement.
- A pre-auth handler does a JWKS fetch / DNS lookup / outbound HTTP that an unauthenticated attacker can flood.
- A pre-auth invalid-token path consumes server work without consuming rate-limit budget (lets attacker brute-force without observable cost).
- An audio preflight (transcription) runs on inbound that the channel did not authorize.
- A configured-limit *bypass*: input that the operator's limit said should reject still consumes the work.

## Out of scope under SECURITY.md (do not file)

- **Pure performance DoS** without amplification, limit bypass, crash, persistent exhaustion, or boundary bypass.
- **ReDoS / DoS** that requires operator-supplied input (custom regex in `sessionFilter`, `logging.redactPatterns`).
- **Decode-before-size-estimate** when the input *had already passed configured size limits*. SECURITY.md is explicit on this.
- **Performance overhead from format conversion** after the input was accepted under configured limits.
- **HMAC / Ed25519 / RS256 brute-force claims** unless paired with a signature-implementation bug. The search space is astronomical.
- **Static long random token** (>=32 chars) brute-force without a rate-limit-bypass primitive.
- **Anything dispatched through the operator-managed proxy-routing feature**.

The disposition test: *what is the ratio between attacker bytes and server work, what is the configured limit, and does the input cross the limit unauthenticated?* If yes (amplification across the limit, crash, or persistent exhaustion), file. If the work is bounded by a documented limit, hardening only.

## Scope (where to look)

Read these in order. Each path was verified against the current tree.

1. **Webhook ingress primitives (the canonical pre-auth surface).** [openclaw/src/plugin-sdk/webhook-request-guards.ts](openclaw/src/plugin-sdk/webhook-request-guards.ts), [openclaw/src/plugin-sdk/webhook-memory-guards.ts](openclaw/src/plugin-sdk/webhook-memory-guards.ts), [openclaw/src/plugin-sdk/webhook-targets.ts](openclaw/src/plugin-sdk/webhook-targets.ts), [openclaw/src/plugin-sdk/webhook-path.ts](openclaw/src/plugin-sdk/webhook-path.ts), [openclaw/src/plugin-sdk/webhook-ingress.ts](openclaw/src/plugin-sdk/webhook-ingress.ts).
2. **Per-channel webhook handlers.** [openclaw/extensions/](openclaw/extensions/) per channel; specifically `webhook*.ts` / `monitor-webhook*.ts` / `monitor.transport.ts` / `monitor-handler.ts`. Voice-call replay-protection-heavy: [openclaw/extensions/voice-call/src/](openclaw/extensions/voice-call/src/). Nostr inbound DM crypto: [openclaw/extensions/nostr/src/](openclaw/extensions/nostr/src/). Telegram audio preflight: [openclaw/extensions/telegram/src/](openclaw/extensions/telegram/src/).
3. **WS upgrade and gateway pre-auth.** [openclaw/src/gateway/handshake-timeouts.ts](openclaw/src/gateway/handshake-timeouts.ts), [openclaw/src/gateway/connection-auth.ts](openclaw/src/gateway/connection-auth.ts), [openclaw/src/gateway/control-plane-rate-limit.ts](openclaw/src/gateway/control-plane-rate-limit.ts), [openclaw/src/gateway/auth-rate-limit.ts](openclaw/src/gateway/auth-rate-limit.ts).
4. **Media decode / base64 / fetch pre-auth.** [openclaw/src/media/](openclaw/src/media/), [openclaw/src/media-understanding/](openclaw/src/media-understanding/), [openclaw/src/web-fetch/runtime.ts](openclaw/src/web-fetch/runtime.ts).
5. **Archive extraction and plugin install (pre-auth or post-auth limit-bypass).** [openclaw/src/infra/archive.test.ts](openclaw/src/infra/archive.test.ts), [openclaw/src/plugins/install.ts](openclaw/src/plugins/install.ts), [openclaw/src/plugins/install-security-scan.runtime.ts](openclaw/src/plugins/install-security-scan.runtime.ts).
6. **Existing audit guidance.** [openclaw/src/security/audit-extra.async.ts](openclaw/src/security/audit-extra.async.ts), [openclaw/src/security/audit.runtime.ts](openclaw/src/security/audit.runtime.ts).

## Pattern fingerprints

1. **`req.on("data")` accumulator without a size cap.** Or with a cap > the documented pre-auth limit (64KB / 5s).
2. **`JSON.parse(rawBody)` before a `safeEqualSecret`/`crypto.verify` call.** The parse runs on attacker bytes.
3. **Base64 decode runs without a size estimate.** `Buffer.from(payload, "base64")` on a 1MB input expands by ~3/4. Confirm a max-decoded-size check happens *before* the decode.
4. **WS frame size cap missing on the upgrade path.** Confirm `maxPayload` / `maxFrameSize` in the WS server options.
5. **Outbound JWKS / DNS / HTTP from a pre-auth handler.** Allows unauth flood through to an external dependency.
6. **Invalid-token path does not consume rate-limit budget.** Walk both branches of the auth check.
7. **Archive extraction with no `maxFiles` / `maxSize` / `compressionRatio` cap.**
8. **Audio preflight transcription on inbound** before the channel authorized.

## What to grep for

- `req.on\("data"`, `chunks.push`, `Buffer.concat`, `readJsonWebhookBodyOrReject`, `readWebhookBodyOrReject`.
- `Buffer.from(.*"base64"\)` (find every site, then check for a pre-decode size check).
- `WEBHOOK_BODY_READ_DEFAULTS`, `pre-auth`, `post-auth`.
- `maxPayload`, `maxFrameSize`, `ws.Server`, `WebSocketServer`.
- `JWKS`, `getKey`, `getJwks`, `fetchJwks`, `verifyJwt`.
- `unzipper`, `tar.extract`, `maxFiles`, `maxSize`, `compressionRatio`.
- `applyBasicWebhookRequestGuards`, `createFixedWindowRateLimiter`, `createWebhookInFlightLimiter`.
- `transcribe`, `audioPreflight`, `mediaPreflight`.

## Report format

```
<file:line>  [VERDICT: broken / risky / safe / unclear]
  Sub-pattern: <unbounded-body / parse-before-verify / base64-pre-decode / ws-no-frame-cap / preauth-jwks-fetch / preauth-no-rate-budget / archive-bomb / audio-preflight>
  Pre-auth:    <what runs before the auth boundary>
  Sink:        <file:line of the work site>
  Boundary:    <file:line of the auth boundary, or "after">
  Ratio:       <attacker bytes : server bytes/CPU/seconds>
  Limit:       <configured limit, if any>
  LimitBypass: <does the input cross the limit unauth? yes / no>
  Effect:      <crash / persistent exhaustion / amplification / outbound flood>
  Acceptance:  <passes SECURITY.md gate? yes / no, and which clause if not>
```

End with a "Top issues to file" list of up to 5. Keep the report under 1100 words.

## Calibration references

CVE-2026-28478 (unbounded webhook body buffering, HIGH 8.7), CVE-2026-29609 (unbounded URL-backed media fetch), CVE-2026-29612 (large base64 media), CVE-2026-32062 (unauth WS resource exhaustion via media stream), CVE-2026-41399 (unbounded pre-auth WS upgrades), CVE-2026-42437 (voice-call WS oversized frames), CVE-2026-41331 (Telegram audio preflight), CVE-2026-28452 / CVE-2026-32044 / CVE-2026-27670 (archive expansion), CVE-2026-35627 (Nostr unauth crypto), GHSA-hm63 (remote media error responses unbounded allocation), GHSA-ccx3 (base64 pre-allocation size checks), GHSA-2hv5 (LINE missing pre-auth concurrency budget), GHSA-2j53 (Nostr unauth crypto).
