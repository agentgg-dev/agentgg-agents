# agentgg-agents

<p align="center">
  <img src="static/logo.png" alt="agentgg" width="300">
</p>

The official agent library for [agentgg](https://github.com/agentgg-dev/agentgg) — AI-powered SAST agents for code security review.

Every template is **one kind of thing**: an agent. A `.md` file with YAML frontmatter (metadata: a `precondition` and a `where`) and a markdown body (the LLM prompt / instructions). There are no execution modes — every agent is a tool-enabled investigation (Read/Glob/Grep) that runs over the files its `where` selects.

Agents are downloaded automatically by agentgg on first scan and updated with `agentgg agents update`.

## Directory structure

```
agentgg-agents/
├── agents/           # The agent library, organized by category
│   ├── injection/    # SQL, NoSQL, command, XSS, path traversal, mass assignment
│   ├── auth/         # Authentication, authorization, JWT, OAuth, session, IDOR
│   ├── misconfiguration/ # CORS, caching, cookies, feature-flag security
│   ├── logic/        # Race conditions, async bugs, event handler mismatches
│   ├── infrastructure/ # Docker, Kubernetes, Terraform, GitHub Actions
│   ├── cloud/        # AWS Lambda, GCP, Azure, IAM
│   ├── cryptography/ # Insecure algorithms, unsafe deserialization
│   ├── mobile/       # Android, iOS
│   ├── smartcontract/ # Solidity access control, reentrancy
│   ├── ai/           # LLM/agent security, MCP, prompt injection
│   └── deep/         # Broad-net variants — opt-in only, never run by default
└── semgrep-rules/    # Shared semgrep rules agents reference by name
```

Every category except `deep/` runs when no `-t` flag is given. `deep/` agents
cast a much wider net per run, so they are opt-in via `-t`.

## Usage

agentgg downloads and manages agents automatically. No manual setup needed.

```bash
agentgg scan ./src                              # every category except deep/
agentgg scan ./src -t agents/injection/         # one category
agentgg scan ./src -t agents/injection/ -t agents/auth/   # multiple
agentgg scan ./src -t agents/deep/              # the broad-net variants
agentgg scan ./src -t sql-injection             # a single agent by slug
agentgg agents update                           # refresh the catalog
```

## Agent format

Each agent is a `.md` file with three parts: a **precondition** (should this run on this repo?), a **where** (which files?), and the **instructions** (the prompt body).

```markdown
---
slug: sql-injection
name: SQL Injection
description: SQL built from untrusted input instead of parameterized queries.
version: 0.1.0
author: your-github-handle
noiseTier: normal
precondition:                      # optional — omit to always run
  regex:
    patterns:
      - regex: "\\.(query|execute)\\s*\\("
        in: ["**/*.{ts,js,py,go,php}"]
  # prompt: "Run only if this project talks to a SQL database."   # optional LLM gate
where:
  extensions: [ts, js, py, go, php]
  excludePatterns: ["**/*.{test,spec}.*"]
  preFilter:
    - { regex: "\\.(query|execute)\\s*\\(", label: "raw SQL call" }
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
| `author` | Your GitHub handle / alias — ships with the agent. Use `agentgg` for official agents. Optionally add a profile in [`contributors.json`](contributors.json). |
| `noiseTier` | `precise`, `normal`, or `noisy` — how many false positives to expect. |
| `precondition` | Optional gate deciding whether the agent runs on this repo. See below. Omit = always run. |
| `where` | Which files the agent runs on. See below. |
| `references` | Optional. CWE / CVE / OWASP identifiers — helps users triage. |

### `precondition` — should this agent run?

Evaluated before any agent runs; the queued/skipped decisions are saved to `state/plan.json`. Two sub-keys, both optional:

- **`regex`** — a cheap, no-LLM filesystem check. Queued if ANY of:
  - `extensions: [".php"]` — a file of this type exists
  - `files: ["artisan", "**/Dockerfile"]` — a file at this path exists
  - `directories: ["app/**"]` — a directory matching this glob exists
  - `patterns: [{ regex, in, notIn, label }]` — a content regex matches in files scoped by `in`/`notIn`
- **`prompt`** — a one-shot LLM check (it sees the recon brief): *"Run only if this is a Laravel app."*

Both present = **AND**. This replaces the old per-stack tech gate — a PHP agent simply preconditions on `.php`, so it skips a Go-only repo on its own.

### `where` — which files?

| Key | Description |
|---|---|
| `extensions` | Plain file types — `[ts, js, php]` (leading dot optional). The common case. |
| `filePatterns` | Globs or paths for complex rules — `["**/app/**/*.php", "src/legacy"]`. A bare directory/path matches everything under it. OR'd with `extensions`. |
| `excludePatterns` | Paths/globs to skip — a folder name skips the whole folder. |
| `preFilter` | List of `{ regex, label }`. Narrows to files containing a match, and hands the model those lines as anchors. `regex` is per-line, JS-flavor; YAML double-escapes backslashes (`\\s`). |
| `useDefaultExcludes` | Default `true`. Set `false` to scan inside `node_modules`/build dirs/etc. |
| `maxFilesPerBatch` | Files per LLM session. Default 5. |
| `maxTurnsPerBatch` | Tool-use turns per session. Default 30. |

An empty `where` = all files. The selected files are reviewed in batches; every agent has Read/Glob/Grep, so it can follow imports and chase callers beyond the seeded files to confirm a finding.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. In short:

1. Fork this repo
2. Add a new `.md` agent in the appropriate category folder (slug must match the filename)
3. Test it locally: `agentgg scan ./test-fixture -t ./your-agent.md`
4. Lint the whole tree: `agentgg agents lint .`
5. Open a pull request

New agents should have:
- A focused, single-responsibility prompt with clear true-positive and false-positive criteria
- A `where` scoped to the relevant files (`extensions` + a `preFilter` for the suspicious construct)
- A `precondition` so the agent skips repos it can't apply to (cheap `regex`, and/or a `prompt` gate)
- A CWE / CVE / OWASP reference when one fits (optional)

## Related

- [agentgg](https://github.com/agentgg-dev/agentgg) — the CLI that runs these agents
