# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/agentgg-dev/agentgg-agents/security) of this repo
2. Click **Report a vulnerability**
3. Fill in the form — we receive it privately

If GitHub's reporting form is unavailable, email **Contact@agentgg.dev** instead.

## Scope

This repo contains markdown prompt files used by the [agentgg CLI](https://github.com/agentgg-dev/agentgg) to scan for vulnerabilities in user code. Two distinct kinds of security issues exist:

**In scope — please report:**
- A malicious or weaponized agent prompt that tries to manipulate the LLM into producing harmful output, exfiltrating user code, or executing attacker-controlled actions
- An agent prompt that leaks data from one user's scan to another
- Supply-chain integrity issues — tampering with releases, tags, or workflows

**Out of scope — not security issues here:**
- An agent missing a vulnerability it should have caught (this is an agent quality bug — open a normal [bug report](https://github.com/agentgg-dev/agentgg-agents/issues/new?template=bug_report.yml))
- An agent producing false positives (also an agent quality bug)
- Vulnerabilities in the agentgg CLI itself — report those at the [CLI repo's security tab](https://github.com/agentgg-dev/agentgg/security)
- Vulnerabilities in code being scanned BY agentgg — that's the user's own codebase, report to them

## Response timeline

- **Acknowledgement** within 3 business days
- **Initial assessment** within 7 business days
- **Fix or mitigation** target depends on severity; we aim for 30 days for high-severity issues
- **Public disclosure** coordinated with you once a fix is published

## Disclosure

We support coordinated disclosure. We'll credit you in the release notes and GitHub Security Advisory unless you prefer to remain anonymous.
