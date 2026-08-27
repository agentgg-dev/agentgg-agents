# agentgg-agents

<p align="center">
  <img src="static/logo.png" alt="agentgg" width="300">
</p>

The official agent library for [agentgg](https://github.com/agentgg-dev/agentgg) — AI-powered SAST agents for code security review.

Every template is **one kind of thing**: an agent. A `.md` file with YAML frontmatter (a `precondition` and a `where`) and a markdown body that is the prompt. There are no execution modes — every agent is a tool-enabled investigation (Read/Glob/Grep) that runs over the files its `where` selects.

agentgg downloads this catalog automatically on first scan and refreshes it with `agentgg agents update`. No manual setup needed.

**[Documentation](https://docs.agentgg.dev/agents/overview)** · [agentgg CLI](https://github.com/agentgg-dev/agentgg) · [agentgg.dev](https://agentgg.dev)

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
│   ├── ai/           # Agent loops, tool definitions, MCP handlers
│   └── deep/         # Broad-net variants — opt-in only, never run by default
└── semgrep-rules/    # Shared semgrep rules agents reference by name
```

Every category except `deep/` runs when no `-t` flag is given. `deep/` agents cast a much wider net per run, so they are opt-in via `-t`.

## Usage

```bash
agentgg scan ./src                              # every category except deep/
agentgg scan ./src -t agents/injection/         # one category
agentgg scan ./src -t agents/injection/ -t agents/auth/   # multiple
agentgg scan ./src -t agents/deep/              # the broad-net variants
agentgg scan ./src -t sql-injection             # a single agent by slug
agentgg agents update                           # refresh the catalog
```

See [Choose agents](https://docs.agentgg.dev/cli/guides/choose-agents) for the full selection rules.

## Write an agent

An agent declares a **precondition** (should this run on this repo?), a **where** (which files?), and the **instructions** (the prompt body):

```markdown
---
slug: sql-injection
name: SQL Injection
description: SQL built from untrusted input instead of parameterized queries.
version: 0.1.0
author: your-github-handle
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: "\\.(query|execute)\\s*\\("
        in: ["**/*.{ts,js,py,go,php}"]
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

Every frontmatter field is documented at:

- [Agent anatomy](https://docs.agentgg.dev/agents/anatomy) — the file format and every frontmatter field
- [Targeting](https://docs.agentgg.dev/agents/targeting) — `precondition` and `where` in full
- [Create from reports](https://docs.agentgg.dev/agents/create-from-reports) — turn a past incident into an agent
- [Manage agents](https://docs.agentgg.dev/agents/manage) — list, lint, and update the catalog

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. In short:

1. Fork this repo
2. Add a new `.md` agent in the appropriate category folder (slug must match the filename)
3. Test it locally: `agentgg scan ./test-fixture -t ./your-agent.md`
4. Lint the whole tree: `agentgg agents lint .`
5. Open a pull request

New agents should have:

- A focused, single-responsibility prompt with clear true-positive and false-positive criteria
- A `where` scoped to the relevant files (`extensions` plus a `preFilter` for the suspicious construct)
- A `precondition` so the agent skips repos it can't apply to (cheap `regex`, and/or a `prompt` gate)
- A CWE / CVE / OWASP reference when one fits (optional)

To report a vulnerability privately, see [SECURITY.md](SECURITY.md).

## License

The agent library is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
