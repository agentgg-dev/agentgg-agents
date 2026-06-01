# Contributing to agentgg-agents

This repo is the official agent library for [agentgg](https://github.com/agentgg-dev/agentgg) — every agent here is a self-contained markdown file that the CLI downloads and runs.

**Your agent ships to every agentgg user the moment it merges**, with your name in its `author:` field. We welcome contributions of all sizes — a typo fix, a false-positive flag, a sharper prompt, or a whole new agent. No contribution is too small.

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Add a new agent** — propose a new vulnerability check or recon pattern
- **Improve an existing agent** — sharpen the prompt, tighten its `where` scope, reduce false positives
- **Report a noisy or broken agent** — open an issue with a repro
- **Fix typos or docs** — small PRs welcome, no issue needed

## Quick start

```bash
git clone https://github.com/agentgg-dev/agentgg-agents
cd agentgg-agents
git config core.hooksPath .githooks   # enable pre-commit lint
```

Install the CLI if you don't have it:

```bash
npm install -g agentgg   # once published
# or point at a local checkout: export AGENTGG_BIN="npx tsx ../agentgg/packages/cli/src/cli.ts"
```

## Writing a new agent

Drop a `.md` file in the appropriate category folder. **The filename must match the `slug:` field** (e.g. `slug: sql-injection` → `sql-injection.md`).

```markdown
---
slug: my-new-check
name: My New Check
description: One-line summary shown in `agentgg agents list`.
version: 0.1.0
author: your-github-handle
noiseTier: normal
precondition:                      # optional — when should this agent run?
  regex:
    patterns:
      - regex: "<the construct you look for>"
        in: ["**/*.{ts,js,py}"]
where:                             # which files to run on
  extensions: [ts, js, py]
  preFilter:
    - { regex: "<the construct you look for>", label: "what it is" }
references:
  - CWE-XXX
  - OWASP-AXX:2021
---

You are reviewing source code for <vulnerability>.

## True positives
- <list of patterns that are real findings>

## False positives — do NOT flag
- <list of patterns that look similar but aren't bugs>

## Output
<format you want the model to return>
```

### Get credit for your contribution

- Set `author:` to your GitHub username (or any handle you'd like to be known by). It ships in the agent file itself — every user sees who wrote it.
- Optionally add yourself to [`contributors.json`](contributors.json) with your social links (GitHub / Twitter / LinkedIn / website / email). All fields are optional.
- Squash-merged PRs preserve your name via `Co-Authored-By:` trailers, so you also show up in the GitHub contributor graph.

### What makes a good agent

- **Single responsibility.** One agent = one vulnerability class. Don't bundle "all injection bugs" into one prompt.
- **Explicit false-positive criteria.** The single biggest source of noise is missing FP guidance. List the patterns that *look* like the bug but aren't.
- **Tight `where`.** Scope to the relevant file types (`extensions`) and narrow with a `preFilter` for the suspicious construct. Don't hand a JS-only check every Python file — wasted tokens = wasted money for users.
- **A real `precondition`.** Gate the agent so it skips repos it can't apply to: a cheap `regex` check (e.g. `extensions: [".php"]` for a PHP-only agent) and/or a `prompt` gate ("Run only if this is a Laravel app"). This is what keeps a 200-agent scan affordable.
- **Reference a CWE / CVE / OWASP entry when one fits.** Optional but helpful — users use these to triage findings and report to their security team. Skip if the bug class doesn't map cleanly to an identifier.
- **`noiseTier` honestly:**
  - `precise` — near-zero false positives. Safe to run in CI.
  - `normal` — some noise expected, worth the signal.
  - `noisy` — high recall, low precision. Opt-in only.

## Testing your agent locally

```bash
# Run just your new agent against a test fixture
agentgg scan ./path/to/test-code -t ./base/category/my-new-check.md

# Lint the whole tree (also runs in pre-commit hook)
agentgg agents lint .
```

## Pull request process

1. Fork, branch from `main`
2. Add or modify your agent
3. Run `agentgg agents lint .` (pre-commit hook will do this for you)
4. Open a PR — the PR template will ask for a brief description and test evidence
5. A maintainer will review for prompt quality, false-positive risk, and category placement

PRs are squash-merged. Your contribution is preserved via `Co-Authored-By:` trailers in the squash commit.

## Reporting issues

- **An agent is noisy or wrong** → open a [bug report](https://github.com/agentgg-dev/agentgg-agents/issues/new?template=bug_report.yml) with the file/code that triggered the bad finding
- **You want an agent that doesn't exist** → open a [new agent request](https://github.com/agentgg-dev/agentgg-agents/issues/new?template=new_agent.yml)
- **You found a security issue in agentgg itself** (not in code being scanned) → see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
