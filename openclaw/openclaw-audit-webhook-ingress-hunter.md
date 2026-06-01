---
slug: openclaw-audit-webhook-ingress-hunter
name: Webhook Ingress Audit — Hunter (OpenClaw chat-channel extensions)
description: Audits OpenClaw chat-channel extensions for webhook-ingress vulnerabilities — places where the gateway accepts an internet-reachable HTTP POST without enforcing signature/secret verification *first*, allowing an attacker who can reach the webhook URL to forge inbound messages and impersonate the platform. Reports each channel as safe / risky / broken with the file:line of the auth boundary and the specific weakness (missing secret, parse-before-verify, timing leak, replay, path ambiguity, etc.). Pairs with `openclaw-audit-allowlist-identity-hunter` — that one asks "is this *sender* allowed?", this one asks "did this even come from the platform?"
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
    - { regex: "webhook|\\.(post|all)\\s*\\(|req\\.(body|rawBody)", label: "webhook ingress" }
    - { regex: "verif(y|ication)|hmac|signature|x-hub-signature|\\bsecret\\b|timingSafeEqual", label: "signature / secret check" }
references:
  - CVE-2026-25474
  - CVE-2026-32896
  - CVE-2026-28475
  - CVE-2026-32053
  - CVE-2026-41351
  - CVE-2026-28469
  - CVE-2026-35628
  - CVE-2026-43534
---

You are auditing channel extensions in `openclaw/extensions/` for one specific bug class: a webhook handler accepts and processes inbound HTTP without first cryptographically authenticating that the request actually came from the platform. The operator believes only Telegram / Slack / etc. can deliver into the gateway; the code is actually accepting any POST that knows the URL.

The threat boundary is **forgery**. The single question this audit answers: can an internet attacker who reaches the webhook URL forge an inbound message and impersonate the platform? Resource exhaustion (slow parses, missing rate limits, missing concurrency caps) is *not* the question — under OpenClaw's policy, performance-only DoS without a trust-boundary bypass is explicitly out of scope. See "OpenClaw policy alignment" below.

This is a source-level code review. Threat model: the operator's gateway is reachable from the public internet — public domain, cloud VM, or tunnel (ngrok, Cloudflare Tunnel, Tailscale Funnel). Localhost-only polling-mode deployments are immune; every webhook-mode deployment is exposed. **Do not assign CVSS scores or "Medium/High" severity bands** — they aren't asked for and the policy doesn't use them as a triage signal. The verdict is binary: either you can write the `curl` that forges a message, or you can't.

## Scope — where the bug actually lives

Every webhook-mode channel follows a similar lifecycle on inbound HTTP: method check → rate limit → secret/signature verify → replay check → body parse → handler dispatch. **The auth boundary is the third step.** Anything attacker-influencable that runs *before* the verify is suspect.

Open these files first per channel:

1. **`webhook*.ts` / `monitor-webhook*.ts` / `monitor.webhook*.ts`** — the canonical entry point that calls `http.createServer` or registers a handler with `withResolvedWebhookRequestPipeline`. The auth boundary lives here.
2. **`signature.ts` / `webhook-security.ts` / `webhook-shared.ts` / `auth.ts`** — sibling files that hold the actual signature/HMAC/JWT verification primitive. The constant-time comparison and the input canonicalization live here.
3. **`monitor.transport.ts` (Feishu)**, **`monitor-handler.ts` (MS Teams)**, **`webhook-ingress.ts` (BlueBubbles)** — channel-specific names for the same role.

Likely-safe-to-skip in most channels: `accounts.ts`, `setup-*.ts`, `config-schema*.ts` (unless the schema makes a webhook secret optional — that's a finding), `send.ts`, `directory*.ts`. Skip `*.test.ts` unless you need a worked example of intended behavior.

The shared SDK at `openclaw/src/plugin-sdk/` provides the helpers every channel should be using:

- `webhook-ingress.ts` — barrel re-export
- `webhook-request-guards.ts` — `applyBasicWebhookRequestGuards` (method/rate/content-type), `beginWebhookRequestPipelineOrReject` (full lifecycle), `readJsonWebhookBodyOrReject` / `readWebhookBodyOrReject` (size/timeout-bounded body read), `WEBHOOK_BODY_READ_DEFAULTS` (pre-auth: 64KB/5s, post-auth: 1MB/30s)
- `webhook-targets.ts` — `withResolvedWebhookRequestPipeline` (dispatch wrapper), `resolveWebhookTargetWithAuthOrReject(Sync)` (single-target match with ambiguous-rejection)
- `webhook-memory-guards.ts` — `createFixedWindowRateLimiter`, `createWebhookInFlightLimiter`, `createWebhookAnomalyTracker`
- `webhook-path.ts` — `normalizeWebhookPath`
- `security/secret-equal.ts` — `safeEqualSecret` (padded `crypto.timingSafeEqual`)

A channel that imports these helpers but uses them in the wrong order, or skips one, is the most common finding.

## Out of scope — polling-mode channels

These channels make outbound connections to their platform and have no inbound HTTP webhook surface. **Do not audit them under this agent.** Mark them safe-by-design with a one-line note.

`slack` (Socket Mode WS), `discord` (gateway WS), `matrix` (sync), `irc` (TCP), `nostr` (relay sub), `signal` (signal-cli daemon), `imessage` (file/notification poll), `whatsapp` (whatsmeow socket).

(Discord *interactions* — slash commands — go over HTTP, but openclaw's discord extension does not register the interactions endpoint. If that changes, audit it.)

## OpenClaw policy alignment — what counts as a finding

OpenClaw is local-first agent infrastructure for trusted operators. The security policy is unusually restrictive about what counts as a vulnerability: **performance issues, parity gaps, and operator footguns are not vulnerabilities** unless they produce a concrete trust-boundary bypass. Read [SECURITY.md](openclaw/SECURITY.md) directly when triaging; the rules below are summary, not authority.

**In scope (file these — they cross a documented trust boundary):**
- An attacker who reaches the URL can forge a message the gateway processes as authentic — i.e., the platform-impersonation boundary is broken.
- Cross-account forgery: an attacker submits a request signed for tenant A and has it routed/accepted as tenant B (path/target ambiguity).
- Privilege escalation through the trusted-event surface: a webhook that passes signature verification gets enqueued as a *trusted system event* without re-sanitization, allowing the attacker (with a valid signature for one event class) to forge admin-class events.
- Timing-leak compare exposing the secret over the wire (samples → recover → forge).
- Forwarded-header trust that lets an attacker control inputs feeding signature reconstruction (e.g., Twilio HMAC over URL+params with attacker-controlled `X-Forwarded-Host`).
- JWT bearer with missing audience or principal binding (any other tenant in the same identity provider can forge).
- A signature-implementation bug: canonicalization mismatch, hex-vs-base64 interchange, partial-digest compare, header-absent fall-through, JWKS validation skipped, alg-confusion (`alg: none`).

**Out of scope (do not file — policy explicit):**
- *Performance-only DoS.* "Reports whose only impact is transient extra memory, CPU, or allocation work from decoding... serialization, or other format conversion" are explicitly performance issues, not vulnerabilities. **Parse-before-verify on a constant-time comparator against a startup-loaded secret is DoS, not forgery** — the comparison still holds, the attacker still doesn't know the secret. File only if the parse output flows into auth state in a way that flips the comparator (HPP picking the wrong field, prototype pollution flagging the request as already-validated, key-case confusion that bypasses the check). Pure "JSON.parse runs before token compare" is hardening.
- *Missing rate limit / in-flight cap on cryptographically strong auth.* HMAC-SHA256, Ed25519, RS256 JWT — search space is astronomical, so rate-limit absence does not weaken auth. The policy classifies this as "ReDoS/DoS without a trust-boundary bypass." Hardening, not a finding.
- *Operator-opt-in dangerous flags.* `skipSignatureVerification`, `dangerouslyAllow*`, `insecureSkip*` — when they default off, require explicit operator config, and log warnings, they are footguns, not vulnerabilities. The policy: "operator-enabled `dangerous*/dangerously*` config option weakens defaults — explicit break-glass tradeoffs by design."
- *Heuristic / parity drift.* Different exec or detection paths having different protections, without a concrete bypass primitive, is hardening only.
- *Multi-tenant adversarial assumptions.* OpenClaw does not model one gateway as a multi-tenant boundary. Reports that depend on "operator A and operator B share one gateway and shouldn't see each other's data" are out of scope.

**Branch by auth scheme — what is forgery-enabling depends on the primitive:**
- *HMAC-SHA256 / Ed25519 / RS256 JWT*: secret search space is astronomical. Missing rate limit / in-flight cap = hardening. Forgery requires a *signature-implementation bug* (canonicalization, encoding interchange, partial-digest compare, length-leak compare).
- *Static short token* (≤8 chars, OTP-style): missing rate limit *is* forgery-enabling (online brute-force). File as broken.
- *Static long random token* (≥32 chars): same as HMAC — missing rate limit = hardening.
- *JWT bearer* (Google/Microsoft): forgery turns on (a) issuer/JWKS validation, (b) audience binding, (c) principal/appId binding. Any one missing = forgery from another tenant in the same IdP.

**Disposition test before filing.** For every candidate finding, ask in this order:
1. *What bytes would the attacker send to forge an inbound message?* If you can write the `curl`, it's broken. If the answer is "a lot of curls until something melts," it's hardening — out of scope.
2. *Does the bug require an operator config that the docs warn against, or a `dangerously*` flag?* If yes, out of scope.
3. *Does the bug require multiple operators sharing one gateway?* If yes, out of scope.
4. *Does the bug only fire when the operator's host is already compromised?* If yes, out of scope.

If the finding survives all four, it's reportable. Otherwise mark it hardening and move on.

## The fingerprint — 8 dimensions

A webhook handler is suspect if any of these is broken. Each dimension has a published CVE/GHSA precedent and a confirmed-good reference in the tree. **Each dimension is tagged `[Forgery]` (in scope under OpenClaw policy) or `[Hardening]` (out of scope as a vulnerability — note it but do not file).** A few dimensions are conditional: their disposition depends on auth scheme or downstream effects.

### 1. [Forgery] Webhook secret presence enforced at startup

The handler must refuse to start if the configured secret is empty. Falling back to passwordless mode silently accepts any forged request.

- **Reference (good)**: [extensions/telegram/src/webhook.ts:273-279](openclaw/extensions/telegram/src/webhook.ts#L273-L279) throws `"Telegram webhook mode requires a non-empty secret token"`. Same shape in [extensions/line/src/webhook.ts:114-121](openclaw/extensions/line/src/webhook.ts#L114-L121) and [extensions/feishu/src/monitor.transport.ts:285-288](openclaw/extensions/feishu/src/monitor.transport.ts#L285-L288).
- **Anti-pattern**: `if (secret) { verify } else { accept }`, or `secret ?? ""` with a downstream check that treats empty as "verification skipped."
- **Precedent**: CVE-2026-25474 (Telegram missing webhookSecret, High 7.5), CVE-2026-32896 (BlueBubbles passwordless fallback, Medium 6.3).

### 2. Signature/secret verification before body parsing

The auth boundary must run before any non-trivial parsing or crypto work. `JSON.parse`, decompression, base64 decode of attachments, downstream API calls, or ID-token JWKS fetches all become DoS amplifiers if they run pre-auth.

- **Reference (good)**: [extensions/feishu/src/monitor.transport.ts:343-353](openclaw/extensions/feishu/src/monitor.transport.ts#L343-L353) — explicit comment "Reject invalid signatures before any JSON parsing to keep the auth boundary strict." Verifies HMAC over `rawBody` *before* `parseFeishuWebhookPayload`.
- **Anti-pattern**: `const payload = JSON.parse(rawBody); if (!verify(payload.signature, ...)) return 401;` — the parse already ran on attacker bytes. Worse: parsing the body to *find* the signature, then verifying.
- **Precedent**: GHSA-8f9r-gr6r-x63q (Feishu pre-validation parsing), GHSA-2j53-2c28-g9v2 (Nostr unauth crypto work, also CVE-2026-35627).

### 3. Pre-auth body bounds

Reading the body to verify a signature is unavoidable, but the read must use the **pre-auth profile** (`maxBytes: 64KB`, `timeoutMs: 5s` — `WEBHOOK_BODY_READ_DEFAULTS.preAuth`). After verification succeeds, post-auth reads up to 1MB/30s are fine.

- **Reference (good)**: [extensions/feishu/src/monitor.transport.ts:328-334](openclaw/extensions/feishu/src/monitor.transport.ts#L328-L334) passes `profile: "pre-auth"`. [extensions/googlechat/src/monitor-webhook.ts:204-213](openclaw/extensions/googlechat/src/monitor-webhook.ts#L204-L213) explicitly switches profile based on whether the bearer was already verified.
- **Anti-pattern**: a 1MB+ body read with a 30s timeout before signature verify; or no `maxBytes`/`timeoutMs` cap at all (raw `req.on("data")` accumulator).
- **Precedent**: CVE-2026-28478 (unbounded webhook body, High 8.7), CVE-2026-41405 (MS Teams unauth body parsing, High 8.7), CVE-2026-29612 (large base64 media, Medium 6.8), CVE-2026-43534 (unsanitized external input as trusted system events, Critical 9.3).

### 4. Constant-time secret comparison

The secret/HMAC compare must be timing-safe AND length-safe. `crypto.timingSafeEqual` throws on length mismatch, so a naive caller does `if (a.length !== b.length) return false; return timingSafeEqual(a, b);` — that early-return leaks length via timing. The fix is to pad both to `max(len_a, len_b)`, call `timingSafeEqual` unconditionally, then `&&` with `len_a === len_b`.

- **Reference (good)**: [openclaw/src/security/secret-equal.ts](openclaw/src/security/secret-equal.ts) (`safeEqualSecret`) — pad-then-compare. [extensions/line/src/signature.ts:11-24](openclaw/extensions/line/src/signature.ts#L11-L24) inlines the same pattern with explicit comment "Call timingSafeEqual unconditionally to ensure constant-time execution regardless of length mismatch (avoids `&&` short-circuit timing leak)."
- **Anti-pattern**: `secret === provided`, `Buffer.compare`, `if (a.length !== b.length) return false; return crypto.timingSafeEqual(...)`.
- **Precedent**: CVE-2026-28475 (Hook Token Comparison timing attack, Medium 6.3).

### 5. Pre-auth rate limiting + invalid-token lockout

The handler must rate-limit before signature verification, keyed on `${path}:${clientIp}` (or `${accountId}` if proxy collapses IPs). Invalid-token attempts must additionally lock the source after N failures in a window, otherwise an attacker brute-forces a weak secret one HMAC at a time.

- **Reference (good)**: [extensions/synology-chat/src/webhook-handler.ts:38-117](openclaw/extensions/synology-chat/src/webhook-handler.ts#L38-L117) (`InvalidTokenRateLimiter`) — separate budget that locks an IP after `PREAUTH_MAX_REQUESTS_PER_MINUTE` bad-token attempts. [extensions/zalo/src/monitor.webhook.ts:201-212](openclaw/extensions/zalo/src/monitor.webhook.ts#L201-L212) uses `applyBasicWebhookRequestGuards` keyed on `${path}:${clientIp}` *before* the secret compare so guesses consume budget.
- **Anti-pattern**: rate limit only after secret check (so wrong guesses don't count); rate limit keyed only on path (one global counter); no rate limit at all.
- **Precedent**: CVE-2026-35628 (Telegram missing webhook rate limiting, Medium 6.3), CVE-2026-35640 (unauth parsing DoS, Medium 6.9), GHSA-r4c2-gq3j-7rpj (Telegram brute-force).

### 6. Pre-auth in-flight concurrency cap

A single attacker can flood the handler with concurrent slow-body requests to exhaust handler slots even if rate-limited. `createWebhookInFlightLimiter` (default 8 concurrent per key, 4096 keys) caps simultaneous handlers and must be wired into `withResolvedWebhookRequestPipeline` or `beginWebhookRequestPipelineOrReject`.

- **Reference (good)**: [extensions/googlechat/src/monitor-webhook.ts:184-197](openclaw/extensions/googlechat/src/monitor-webhook.ts#L184-L197) passes `inFlightLimiter` into `withResolvedWebhookRequestPipeline`.
- **Anti-pattern**: missing in-flight cap on a handler that does crypto, JWKS fetch, or other I/O before auth.
- **Precedent**: GHSA-2hv5-4h3g-4hjv (LINE missing pre-auth concurrency budget), CVE-2026-35626 (voice-call webhook resource exhaustion, Medium 6.9).

### 7. Replay protection — timestamp window + nonce, with canonical encoding

A cryptographically valid request can still be replayed by an attacker who captured one. The fix is two layers: (a) reject requests outside a clock-skew window, (b) cache `(timestamp, nonce, signature)` for the window's duration. **Crucially, the cache key must be over a *canonical* form of the input** — base64 has multiple representations (URL-safe vs standard, padded vs unpadded) and an attacker can re-encode the signature to bypass a naive cache.

- **Reference (good)**: [extensions/voice-call/src/webhook-security.ts](openclaw/extensions/voice-call/src/webhook-security.ts):
  - Telnyx canonicalizes `signatureBuffer.toString("base64")` *before* hashing into the replay key (line 532, 547). This is the explicit fix for CVE-2026-41351.
  - Twilio replay key is `sha256(verificationUrl + canonicalParams + signature)` (lines 436-445), with `buildCanonicalTwilioParamString` sorting params before hashing.
  - Plivo V2/V3 replay keys derive from `getBaseUrlNoQuery` + nonce (lines 723-739).
  - Cache: 10-minute window, max 10K entries, prune every 64 calls (lines 8-72).
  - Telnyx clock-skew check: `maxSkewMs ?? 5 * 60 * 1000` (line 540).
- **Anti-pattern**: no replay cache on a webhook with a deterministic body; replay key over the raw header (varies by encoding); replay window > 1 hour; cache without size bound.
- **Precedent**: CVE-2026-32053 (Twilio randomized event ID, Medium 6.9), CVE-2026-41351 (base64 re-encoding bypass, Medium 6.3), GHSA-cw28-63x4-37c3 (Plivo replay origin), CVE-2026-32987 (Bootstrap setup code replay, Critical 9.3).

### 8. Path uniqueness / target ambiguity

When multiple accounts register webhook handlers, their paths and secrets must uniquely identify exactly one target. `resolveWebhookTargetWithAuthOrReject` returns `{kind: "ambiguous"}` if multiple targets match the same `(path, secret)` and the wrapper replies 401.

- **Reference (good)**: [openclaw/src/plugin-sdk/webhook-targets.ts:170-281](openclaw/src/plugin-sdk/webhook-targets.ts#L170-L281) — explicit ambiguous case. [extensions/zalo/src/monitor.webhook.ts:215-219](openclaw/extensions/zalo/src/monitor.webhook.ts#L215-L219) uses `resolveWebhookTargetWithAuthOrRejectSync` to enforce uniqueness.
- **Anti-pattern**: per-account webhook paths sharing a prefix without account-scoping; `targets.find(...)` returning the first match without checking for additional matches; trusting body-supplied `accountId` to disambiguate.
- **Precedent**: CVE-2026-28469 (Google Chat shared-path target ambiguity, High 8.2), CVE-2026-35635 (Synology Chat path replacement, Medium 6.3), GHSA-g8mc-c5f2-mqg7 (Synology DM-policy collision).

### Cross-cutting (additional)

**9. Forwarded-IP / host trust.** `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host` must only be trusted if the immediate peer is in `gateway.trustedProxies` (or an explicit `allowedHosts` whitelist). Otherwise an attacker spoofs source IP / public URL, bypassing rate-limit keys and (for Twilio) signature reconstruction.

- **Reference (good)**: [extensions/telegram/src/webhook.ts:149-242](openclaw/extensions/telegram/src/webhook.ts#L149-L242) — `isTrustedProxyAddress` + `resolveForwardedClientIp`. [extensions/voice-call/src/webhook-security.ts:252-341](openclaw/extensions/voice-call/src/webhook-security.ts#L252-L341) — host-header injection guard with `allowedHosts` whitelist.
- **Precedent**: CVE-2026-35656 (XFF Loopback Spoofing, Medium 6.3).

**10. Audience / principal verification on JWT bearer.** When the auth scheme is a Google/Microsoft JWT, the handler must verify both the `audience` claim *and* the expected app principal. Accepting any JWT signed by Google with no audience binding lets any other Google add-on impersonate the operator's bot.

- **Reference (good)**: [extensions/googlechat/src/monitor-webhook.ts:113-118](openclaw/extensions/googlechat/src/monitor-webhook.ts#L113-L118) calls `verifyGoogleChatRequest` with `expectedAddOnPrincipal: target.account.config.appPrincipal`.
- **Precedent**: GHSA-hgwr-wr8h-rxm7 (Google Chat add-on accepted non-deployment principals), CVE-2026-43572 (MS Teams SSO invoke handler missed sender authorization, Medium 6.3).

**11. Wake-event / system-event trust boundary.** Webhook payloads must not be enqueued as *trusted system events* without re-sanitization. If a webhook can mutate operator state by writing into the same queue as internal admin events, an attacker who passes signature verification still gets to forge admin actions.

- **Precedent**: CVE-2026-43534 (agent hook events from unsanitized external input, Critical 9.3), CVE-2026-43566 (heartbeat owner downgrade missed untrusted webhook wake events, Critical 9.1).

## What to grep for

The greps below are *entry points* — once you find a candidate site, read the handler end-to-end and walk the lifecycle: which dimension fires first, which fires last, which is missing entirely.

**Auth-boundary helpers (every webhook handler should call one of these):**
- `safeEqualSecret`, `crypto.timingSafeEqual`, `verifyTwilioWebhook`, `verifyPlivoWebhook`, `verifyTelnyxWebhook`, `verifyGoogleChatRequest`, `validateLineSignature`, `validateToken`, `isFeishuWebhookSignatureValid`, `validate*Signature`
- `applyBasicWebhookRequestGuards`, `beginWebhookRequestPipelineOrReject`, `withResolvedWebhookRequestPipeline`, `resolveWebhookTargetWithAuthOrReject(Sync)`
- `readWebhookBodyOrReject`, `readJsonWebhookBodyOrReject`, `readRequestBodyWithLimit`, `installRequestBodyLimitGuard`
- `createFixedWindowRateLimiter`, `createWebhookInFlightLimiter`, `WEBHOOK_RATE_LIMIT_DEFAULTS`, `WEBHOOK_BODY_READ_DEFAULTS`

**Anti-pattern probes:**
- `JSON.parse(.*body|.*rawBody|.*raw)` — find places that parse before verify; trace upward to confirm the verify hasn't run
- `req.on\("data"|on\("end"|chunks\.push|Buffer\.concat` — manual body accumulators that bypass `WEBHOOK_BODY_READ_DEFAULTS`
- `secret\s*===|secret\s*==|provided\s*===|token\s*===` — non-constant-time compares
- `if\s*\(.*\.length\s*!==.*\.length\)\s*return\s*false` — early-return length check before timingSafeEqual (timing leak)
- `skipVerification|skip_verification|allowUnverified|allowUnsafe|insecureSkip` — dev-mode bypasses; verify they aren't reachable from production config
- `if\s*\(.*secret\)\s*\{` followed by an `else` that doesn't reject — passwordless fallback shape
- `headers\["x-forwarded-for"\]|x-forwarded-host|x-real-ip` without `trustedProxies` checks nearby
- `JSON.parse` inside a function whose caller doesn't enforce a `maxBytes` — unbounded parse

**Replay-protection probes:**
- `replayCache|replayWindow|seenUntil|nonceCache|recentEvents|createClaimableDedupe` — find the cache, then verify the key includes canonical-form inputs
- `Buffer\.from\(.*"base64"\).*toString\("base64"\)` — explicit canonicalization (good)
- Header reads of `x-*-timestamp`, `x-*-nonce`, `x-*-request-id` — confirm the timestamp is checked against a clock-skew window before the cache claim

**Webhook-secret schema probes:**
- `webhookSecret\?:|secret\?:|encryptKey\?:|channelSecret\?:` in `config-schema*.ts` — optional secret = passwordless fallback unless explicitly enforced at startup
- `throw new Error.*webhook.*secret|webhook.*requires.*secret` — startup enforcement (good)

**Path/target probes:**
- `targetsByPath|webhookTargets|targets\.find|targets\.filter` — verify ambiguous-target rejection
- `normalizeWebhookPath` — verify it's called on both registration and dispatch

## For each channel, determine

1. **Is this channel webhook-mode?** If polling/socket-only (slack, discord-gateway, matrix, irc, nostr, signal, imessage, whatsapp), report safe-by-design and stop.
2. **What's the auth scheme?** Static header secret (Telegram, Zalo), HMAC over body (LINE, Slack-style, Feishu), HMAC over URL+params (Twilio), Ed25519 (Telnyx, Discord interactions), JWT bearer (Google Chat, MS Teams). The dimensions to prioritize differ — replay protection matters most for HMAC-with-timestamp; audience/principal matters most for JWT; pre-auth body bounds matter for everyone.
3. **Where is the auth boundary?** Find the first line that runs `safeEqualSecret` / `crypto.verify` / `validate*Signature` against the request. Everything *above* that line is pre-auth and must be cheap and bounded.
4. **Walk the 8 dimensions in order.** For each, mark present / absent / wrong-order. Cite file:line.
5. **Operator config form.** Confirm the documented config shape requires the secret. If the schema makes it optional, that's a finding even if the runtime checks it (operators following the docs may write a config without one).
6. **Skip-verification reachability.** Many handlers expose a `skipVerification` flag for dev. Confirm it's only set from a debug/test entry point, not from operator config or env.

## Verdict criteria

- **Broken** — there is a code path where, with the documented operator config, an attacker who can reach the webhook URL can forge a request the gateway processes as authentic. This includes: missing-secret fallback, parse-before-verify, non-constant-time compare, no replay protection on a deterministic-body endpoint, ambiguous-target acceptance, accepting forwarded headers from untrusted peers, JWT without audience/principal binding. Cite file:line for the auth-boundary call AND the missing/wrong-order step.
- **Risky** — the auth boundary is correct in the common case but has a narrow bypass: replay window too long, in-flight cap missing on a handler that does pre-auth I/O, dev-mode bypass reachable from a non-obvious config flag, partial canonicalization (e.g., header lowercased but value not).
- **Safe** — all 8 dimensions are present and ordered correctly; cross-cutting (forwarded-IP, audience, wake-event) match the references.
- **Safe-by-design** — polling/socket-only channel; no inbound HTTP webhook surface.
- **Unclear** — the verify is delegated to a third-party SDK (e.g., MS Teams Bot Framework adapter) whose configuration the audit can't inspect from source. Flag for human review with the specific question (e.g., "is `MicrosoftAppId` enforced when set, or does empty fall through?").

## Acceptance Gate — does this finding write up as a CVE?

Apply this gate before calling something broken. The published OpenClaw CVEs in this category cluster around CVSS Medium 6.3-6.9 with a few High 7.5-8.7 outliers. To match that bar:

- **Internet-reachable surface assumed.** Polling-mode-only channels are out of scope. A bug that only fires when the operator opts into webhook mode AND deploys publicly is still in scope — that's the documented webhook deployment.
- **Documented operator config.** Operators who configure the webhook per the channel README must be exposed. If the bug only fires when the operator writes an undocumented or obviously-unsafe config (e.g., manually setting `skipVerification: true`), that's heuristic and should be downgraded.
- **No third-party prerequisite.** SIM swap, carrier number recycling, social engineering of the platform, or compromise of the operator's host all fail the gate. The attacker should need only `curl` and the URL.
- **No `dangerously*` opt-in already enabled.** Same scope rule as the allowlist-identity audit.
- **Trusted-operator boundary.** Bugs that require the operator's own host to be compromised (e.g., reading the secret from disk) are out of scope.
- **Rate-limit / DoS findings**: Medium 6.3-6.9 is the typical band. Reachable unauthenticated DoS that costs significant CPU/memory before auth (CVE-2026-29612 large base64, CVE-2026-35626 voice-call) qualifies; a 1KB body that costs O(1) work does not.

The validated references (Telegram, Twilio, BlueBubbles, Synology) all pass cleanly because: (i) the URL is the documented one operators expose, (ii) `curl` with no platform credentials reproduces the issue, (iii) the operator-facing signal is at most a verbose log line they don't normally diff, (iv) the bug fires on every restart with the same config, (v) no chained vulnerability is required.

## Validated references — example shapes

Use these as calibration, not as a checklist. Each one is a different *surface* showing the same fingerprint — the agent should generalize from them, not narrow to them.

- **CVE-2026-25474 (Telegram missing webhookSecret, High 7.5).** Static-header auth scheme. Demonstrates dimension 1 (secret presence) — pre-fix, the secret was optional and the runtime accepted unauthenticated POSTs. Fix lives at [extensions/telegram/src/webhook.ts:273-279](openclaw/extensions/telegram/src/webhook.ts#L273-L279).
- **CVE-2026-32896 (BlueBubbles passwordless fallback, Medium 6.3).** Same dimension 1, different shape — the schema *was* optional and the runtime *had* a fallback. Fix removed the fallback.
- **CVE-2026-28475 (Hook Token timing attack, Medium 6.3).** Dimension 4 — `===` on hook tokens leaked timing. Fix is `safeEqualSecret`. Shows that even a static-secret scheme needs constant-time compare.
- **CVE-2026-32053 (Twilio replay via randomized event ID, Medium 6.9).** Dimension 7 — replay key derived from a value the attacker controls (event ID) instead of a value the platform signs. Fix moved the replay key over the canonicalized signed material at [extensions/voice-call/src/webhook-security.ts:436-445](openclaw/extensions/voice-call/src/webhook-security.ts#L436-L445).
- **CVE-2026-41351 (Webhook replay via base64 re-encoding, Medium 6.3).** Dimension 7 again — replay cache keyed on the raw signature header; Base64 has multiple representations, so an attacker re-encodes and bypasses dedup. Fix canonicalizes via `signatureBuffer.toString("base64")` before hashing into the replay key.
- **CVE-2026-28469 (Google Chat shared-path webhook, High 8.2).** Dimension 8 — multiple accounts registered the same path; the first matching target was used regardless of which target's auth verified. Fix uses `resolveWebhookTargetWithAuthOrReject` which rejects ambiguous matches.
- **CVE-2026-35628 (Telegram missing webhook rate limiting, Medium 6.3).** Dimension 5 — invalid-token guesses didn't consume rate budget. Fix wired `applyBasicWebhookRequestGuards` before secret check.
- **CVE-2026-43534 (Agent hook events from unsanitized external input, Critical 9.3).** Dimension 11 — webhook payloads enqueued as trusted system events without re-sanitization. Even with a valid signature, the webhook was a privilege-escalation surface into operator-owned event types.

**Generalize from these:** the bug class spans (a) "no auth at all," (b) "auth runs but in the wrong order," (c) "auth runs but the comparison leaks," (d) "auth runs but is replayable," (e) "auth runs and verifies one principal but trusts another," (f) "auth runs but the post-auth payload is trusted with too much authority." Look for the *order* and the *trust transitions*, not just the syntax.

## Channels to prioritize

Audit in this order — known to have or recently had findings:

**Top priority:** `voice-call` (twilio/plivo/telnyx — three providers in one extension, replay-protection-heavy), `googlechat` (JWT audience/principal), `feishu` (HMAC-with-encrypt-key, has had pre-validation parsing fixes), `synology-chat` (has had path-replacement and pre-auth-rate-limit fixes), `bluebubbles` (had passwordless fallback), `telegram` (the canonical reference; verify all 8 dimensions hold).

**Sweep the rest:** `line`, `zalo`, `mattermost` (interactions endpoint), `nextcloud-talk`, `webhooks` (generic ingress).

**Delegated/unclear:** `msteams` (Bot Framework SDK does the JWT verify; audit the wiring at [extensions/msteams/src/monitor-handler.ts](openclaw/extensions/msteams/src/monitor-handler.ts) but recognize the actual verify is in a third-party library).

**Safe-by-design (one-line each):** `slack`, `discord`, `matrix`, `irc`, `nostr`, `signal`, `imessage`, `whatsapp`. Note their inbound transport (Socket Mode WS, gateway WS, sync, TCP, relay sub, daemon, file-watch, whatsmeow socket) and stop.

## Report format

Group by verdict, then by channel. For each finding:

```
extensions/<channel>  [VERDICT: broken / risky / safe / safe-by-design / unclear]
  Mode:        <webhook / polling / socket / hybrid>
  Auth scheme: <static-header / hmac-body / hmac-url-params / ed25519 / jwt-bearer / sdk-delegated / none>
  Boundary:    <file:line of the signature/secret verify call — first authenticated step>
  Dimensions:  <d1..d11 status — present / absent / wrong-order / partial>
  Failing:     <which dimension(s) are broken or risky, with file:line>
  Anti-pattern:<the specific code shape, e.g. `JSON.parse before verify` / `=== compare` / `replay key over raw header`>
  Pre-auth:    <what happens before the auth boundary — body parse? crypto? I/O?>
  Reachable:   <documented operator config that reaches this path; secret optionality>
  Attacker:    <who can forge — anyone on internet / anyone with URL / requires X-Forwarded-* spoof>
  Effect:      <what they get — forge inbound message / DoS amplification / replay / cross-account routing / privileged event injection>
  Acceptance:  <passes GHSA gate? yes / heuristic / chained — and which clause if not>
```

End with a "Top issues to file" list of up to 5 broken/risky findings ranked by ease of exploitation, prioritizing those that pass the Acceptance Gate. Keep the report under 1100 words. Prefer five solid findings over twenty maybes — every broken verdict needs a concrete attacker action, a cited line, and an explicit Acceptance verdict.
