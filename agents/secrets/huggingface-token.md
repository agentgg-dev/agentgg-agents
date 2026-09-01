---
slug: huggingface-token
name: HuggingFace Access Token Exposure
description: 'Hardcoded HuggingFace user access tokens (hf_[34 alpha]) in source or config. A write-access token can upload models, modify datasets, and push to private repositories; a read token exposes private model weights and datasets.'
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
    - regex: '\b(hf_[a-zA-Z]{34})\b'
      label: HuggingFace user access token (hf_)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded HuggingFace access tokens.

## Token format

HuggingFace user access tokens begin with `hf_` followed by 34 alphabetic characters (uppercase and lowercase, no digits): `hf_[a-zA-Z]{34}`.

HuggingFace tokens come in two permission levels:
- **Read:** Download private models, datasets, and spaces the account has access to
- **Write:** Upload model weights, push to repositories, create/delete repos, manage organizations

## Risk

An attacker with a HuggingFace token can:
- **Read token:** Download private model weights (proprietary IP), access private datasets (potentially containing sensitive training data or PII), view private Spaces
- **Write token (higher risk):**
  - Upload malicious model files or code to the account's repositories
  - Overwrite existing model weights or inject backdoors into fine-tuned models
  - If the model is publicly available and widely used: affect downstream users who pull the model
  - Access and modify dataset contents used for future training

## Cross-file analysis

When a token is found, look for:
1. `HfApi` or `login(token=...)` calls — determines the token's scope of use
2. Model repository names (e.g., `hf_api.upload_file(repo_id="org/model-name")`) — identifies what could be overwritten
3. Whether the model is a public, widely-used one vs. a private internal model
4. `HUGGING_FACE_HUB_TOKEN` or `HF_TOKEN` environment variable references elsewhere — confirms this is meant to be secret

## True positive criteria

Flag when ALL hold:
1. The value matches `hf_[a-zA-Z]{34}` exactly
2. It is a string literal, not an environment variable reference (`os.environ.get('HF_TOKEN')`, `process.env.HUGGINGFACE_API_KEY`)
3. It is not a placeholder: `hf_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`, all same characters

## What to ignore

- Environment variable references
- Clearly expired or revoked tokens in git history (though flagging for rotation is still appropriate)
- Documentation examples using a fake `hf_` prefixed string with obvious placeholder characters

## Examples

True positives:
```python
from huggingface_hub import login
login(token="hf_<34-char-token>")
```
```python
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("org/private-model",
    use_auth_token="hf_<34-char-token>")
```
```yaml
HUGGINGFACE_TOKEN: hf_<34-char-token>
```

False positives to skip:
```python
login(token=os.environ.get("HF_TOKEN"))
```
```python
model = AutoModelForCausalLM.from_pretrained("org/model",
    use_auth_token=os.environ["HUGGINGFACE_API_KEY"])
```

Note whether this is a read or write token (look for upload/push calls vs. only download calls), and which model repositories are involved, to assess IP and supply chain risk.
