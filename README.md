# agentgg-agents

<p align="center">
  <img src="static/logo.png" alt="agentgg" width="300">
</p>

The official agent library for [agentgg](https://github.com/agentgg-dev/agentgg) — AI-powered SAST agents for code security review.

Each agent is a self-contained markdown file with YAML frontmatter (metadata) and a markdown body (the LLM prompt). Agents are downloaded automatically by agentgg on first scan and updated with `agentgg agents update`.

## Directory structure

```
agentgg-agents/
├── demo-agents/      # Small curated set — one agent per mode (file / walker / hunt) for a quick first scan via `-t demo-agents/`
└── base/             # Full vulnerability library, organized by category — runs automatically when no -t flag is given
    ├── injection/    # SQL, NoSQL, command, XSS, path traversal, mass assignment
    ├── auth/         # Authentication, authorization, JWT, OAuth, session, IDOR
    ├── exposure/     # Secrets, env vars, error leaks, debug endpoints
    ├── misconfiguration/ # CORS, caching, cookies, feature-flag security
    ├── logic/        # Race conditions, async bugs, event handler mismatches
    ├── infrastructure/ # Docker, Kubernetes, Terraform, GitHub Actions
    ├── cloud/        # AWS Lambda, GCP, Azure, IAM
    ├── cryptography/ # Insecure algorithms, unsafe deserialization
    ├── mobile/       # Android, iOS
    └── ai/           # LLM/agent security, MCP, prompt injection
```

## Usage

agentgg downloads and manages agents automatically. No manual setup needed.

**Default scan** — runs the full `base/` vulnerability library:

```bash
agentgg scan ./src
```

**Run the quick `demo-agents/` set** (one agent per mode — file / walker / hunt — for a fast first scan):

```bash
agentgg scan ./src -t demo-agents/
```

**Run a specific category:**

```bash
agentgg scan ./src -t base/injection/
agentgg scan ./src -t base/auth/
```

**Run multiple categories:**

```bash
agentgg scan ./src -t base/injection/ -t base/auth/
```

**Run a single agent by slug:**

```bash
agentgg scan ./src -t sql-injection
```

**Update to the latest agents:**

```bash
agentgg agents update
```

## Agent format

Each agent is a `.md` file:

```markdown
---
slug: sql-injection
name: SQL Injection
description: SQL queries built by concatenating untrusted input instead of using parameterized queries.
version: 0.1.0
author: your-github-handle
mode: file
noiseTier: normal
filePatterns:
  - "**/*.{ts,js,py,rb,go,rs,php,java,cs}"
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing source code for SQL injection...
```

### Frontmatter fields

| Field | Description |
|---|---|
| `slug` | Unique identifier, kebab-case. Used with `-t`. Must match the filename (`<slug>.md`). |
| `name` | Human-readable name. |
| `description` | One-line summary shown in `agentgg agents list`. |
| `version` | Semver string. |
| `author` | Your GitHub username, Twitter handle, or alias. Your name ships with the agent. Use `agentgg` for official agents. Optionally add a full profile in [`contributors.json`](contributors.json). |
| `mode` | `file` (one LLM call per matching file), `walker` (agentic batches), or `hunt` (whole-repo exploration). |
| `noiseTier` | `precise`, `normal`, or `noisy` — how many false positives to expect. |
| `filePatterns` | Glob patterns for files this agent should scan. |
| `references` | Optional. CWE, CVE, or OWASP identifiers — helps users triage findings and report to their security team. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. In short:

1. Fork this repo
2. Add a new `.md` agent in the appropriate category folder (slug rules in the schema above)
3. Test it locally: `agentgg scan ./test-fixture -t ./your-agent.md`
4. Lint the whole tree: `agentgg agents lint .`
5. Open a pull request

New agents should have:
- A focused, single-responsibility prompt
- Clear true-positive and false-positive criteria in the prompt body
- Tight `filePatterns` to avoid scanning irrelevant files
- A CWE / CVE / OWASP reference when one fits (optional)

## Related

- [agentgg](https://github.com/agentgg-dev/agentgg) — the CLI that runs these agents
