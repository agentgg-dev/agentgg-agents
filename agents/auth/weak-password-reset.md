---
slug: weak-password-reset
name: Weak Password Reset Flow
description: 'Password reset endpoints that rely on knowledge-based answers (security questions, DOB, address), accept attacker-supplied identity claims without proof-of-possession, or skip rate limiting — attackers reset accounts using publicly knowable information.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
      - py
      - rb
      - go
      - php
      - java
      - kt
      - cs
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - php
    - java
    - kt
    - cs
  preFilter:
    - semgrepRule: auth/password-hash-call
      label: Password hash or reset token generation call
references:
  - CWE-640
  - CWE-307
  - 'OWASP-A07:2021'
---

You are reviewing source code for weak password reset flows — paths
that let a user choose a new password without first proving control of
the account's verified channel (email, SMS, authenticator), or that
gate the reset on knowledge an attacker can guess or research
(security questions whose answers are public).

The safe pattern is well-known: generate a single-use, time-limited,
high-entropy token, email it to the verified address on file, and
require that token (plus optional re-auth) to set the new password.
Anything that diverges from that — security questions, knowledge
factors, "answer matches → reset now" — is a finding.

## What to look for

**Security-question-as-only-factor:**
```ts
app.post("/api/reset-password", async (req, res) => {
  const user = await User.findOne({ where: { email: req.body.email } });
  if (user.securityAnswer === req.body.answer) {
    await user.update({ password: hash(req.body.newPassword) });
    return res.json({ ok: true });
  }
  res.status(403).json({ error: "wrong answer" });
});
```
The reset succeeds with just (email, security answer, new password).
No emailed token, no rate limiting, no lockout.

**Direct password set with no token verification:**
```ts
// "I forgot my password" means submit email + new password means done
app.post("/forgot", async (req, res) => {
  await User.update({ password: hash(req.body.newPassword) },
                    { where: { email: req.body.email } });
});
```

**Token issued but never verified for single-use / TTL:**
```ts
const token = randomBytes(16).toString("hex");
await User.update({ resetToken: token }, { where: { id } });
// later:
const u = await User.findOne({ where: { resetToken: req.query.token } });
await u.update({ password: hash(req.body.password) });
// token not invalidated; no expiry check
```

**Token comparison via `==` / non-constant-time:**
```ts
if (user.resetToken === req.query.token) { ... }    // timing oracle
```

**Reset that infers identity from request input alone:**
```python
@app.post("/reset")
def reset():
    user = User.query.filter_by(email=request.json["email"]).first()
    user.password = hash(request.json["new_password"])   # no auth required
```

**Patterns that indicate the safe path (don't flag if present):**
- Single-use token in a separate table with `expiresAt`, marked
  consumed on use.
- Reset link delivered only via `sendMail(user.verifiedEmail, ...)` —
  email derived from the stored record, never from the request body.
- Rate limiting on reset-initiation per email/IP.
- Step-up via existing session (user must be logged in already to
  change their own password).
- Constant-time token compare (`crypto.timingSafeEqual` /
  `secrets.compare_digest`).

## True positive criteria

Flag when ANY of the following hold:

1. Reset completes based on a **knowledge factor** (security question,
   DOB, address, mother's maiden name) without an out-of-band token.
2. Reset accepts the target email/username from the request body and
   sets a new password, **without** requiring proof-of-control of that
   email (no token round-trip).
3. Reset token is issued but its TTL, single-use, or constant-time
   compare is missing.
4. No rate limit or lockout on reset attempts (allows brute-force of
   tokens or security answers).

## What to ignore

- Authenticated password change (`/change-password` with current
  password required) — not a reset flow.
- Magic-link / OTP flows where the link is mailed to the verified
  channel and required to land on the reset page.
- Internal admin tools where a privileged role can reset another
  user's password — different threat model.

## Examples

True positives:
```ts
// Security question as sole factor
app.post("/api/reset", async (req, res) => {
  const u = await User.findOne({ where: { email: req.body.email } });
  if (u?.securityAnswer === req.body.answer) {
    u.password = hash(req.body.newPassword);
    await u.save();
    return res.json({ ok: true });
  }
  res.sendStatus(403);
});

// Direct set, no proof of email control
app.post("/forgot", async (req, res) => {
  await db.user.update({ where: { email: req.body.email },
                          data:  { password: hash(req.body.newPassword) } });
  res.json({ ok: true });
});
```

False positives to skip:
```ts
// Token round-trip + TTL + single-use + email-bound
app.post("/forgot", async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user) return res.json({ ok: true });   // don't leak existence
  const token = randomBytes(32).toString("hex");
  await db.resetToken.create({
    data: { userId: user.id, token: hash(token), expiresAt: Date.now() + 15 * 60_000 },
  });
  await mailer.send(user.email, resetLink(token));
  res.json({ ok: true });
});
```

Security questions are a well-known anti-pattern — answers are often
researchable on social media (pet's name, school, hometown). The mere
presence of a `securityAnswer` column being checked in a reset path is
a red flag.
