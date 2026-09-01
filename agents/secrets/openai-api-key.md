---
slug: openai-api-key
name: OpenAI API Key Exposure
description: 'Hardcoded OpenAI API keys (sk-..., sk-proj-..., sk-admin-..., sk-svcacct-...) in source or config. A leaked key can run unlimited inference requests, exfiltrate fine-tuned models, and incur unbounded billing charges.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '(sk-[a-zA-Z0-9]{48})'
      label: OpenAI classic API key (sk-)
    - regex: 'sk-proj-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}'
      label: OpenAI project API key (sk-proj-)
    - regex: 'sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58}'
      label: OpenAI admin API key (sk-admin-)
    - regex: 'sk-svcacct-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}'
      label: OpenAI service account API key (sk-svcacct-)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded OpenAI API keys.

## Key formats

OpenAI has several key formats, each with different scopes:

**Classic key (`sk-[48 alphanumeric chars]`):** Original format. Full access to the organization's OpenAI account — all models, fine-tuning, embeddings, assistants, files.

**Project key (`sk-proj-...-T3BlbkFJ-...`):** Scoped to a specific OpenAI project. The `T3BlbkFJ` substring is an encoded identifier. Still powerful — can run inference and access project-level resources.

**Admin key (`sk-admin-...-T3BlbkFJ-...`):** Administrative access to the organization. Can manage users, billing, rate limits, and API usage policies. Highest severity.

**Service account key (`sk-svcacct-...-T3BlbkFJ-...`):** Belongs to a service account rather than a user. Often used in automated pipelines; leaking it exposes whatever services use the key.

## Risk assessment

An attacker with an OpenAI key can:
- Run inference against any available model, incurring unlimited charges on the victim's billing account
- List and download fine-tuned models (potentially containing proprietary training data)
- Access files uploaded to the Assistants API (potentially sensitive documents)
- For admin keys: enumerate all users, modify organization settings, revoke other keys

## True positive criteria

Flag when ALL hold:
1. The value matches one of the `sk-` prefix patterns with the correct length/structure
2. It is a string literal — not a variable reference like `process.env.OPENAI_API_KEY` or `os.environ.get("OPENAI_API_KEY")`
3. It is not a placeholder: `sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`, all same characters, or documentation examples

Treat any `sk-admin-` key as critical severity regardless of context.

## What to ignore

- Environment variable references
- Clearly truncated or redacted values
- Test files that mock the OpenAI client with fake keys and verify no real HTTP calls are made

## Examples

True positives:
```ts
const openai = new OpenAI({ apiKey: 'sk-<48-char-key>' });
```
```python
openai.api_key = 'sk-proj-<74-chars>T3BlbkFJ<74-chars>'
```
```yaml
OPENAI_API_KEY: sk-<48-char-key>
```

False positives to skip:
```ts
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
```
```python
openai.api_key = os.environ.get("OPENAI_API_KEY")
```

Note the key type (classic / project / admin / service account), what API endpoints it calls (chat completions, fine-tuning, assistants), and whether the code runs in a user-facing or backend context. Admin keys should always be flagged as critical.
