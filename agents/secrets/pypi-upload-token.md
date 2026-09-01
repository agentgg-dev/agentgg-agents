---
slug: pypi-upload-token
name: PyPI Upload Token Exposure
description: 'Hardcoded PyPI API tokens (pypi-AgEI... prefix) in source or config. Allow publishing Python packages — a leaked token can push malicious package versions for supply chain attacks.'
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
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b'
      label: PyPI API token (pypi-AgEIcHlwaS5vcmc... precise prefix)
    - regex: '(?i)(?:TWINE_PASSWORD|PYPI_TOKEN|PYPI_API_TOKEN)\s*[=:]\s*[''"]?pypi-[A-Za-z0-9_\-]{50,}'
      label: PyPI token in CI variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded PyPI API tokens. PyPI is the Python Package Index — a leaked token can push malicious package versions, enabling supply chain attacks.

## Token format

```
pypi-AgEIcHlwaS5vcmc<50+ alphanumeric/base64 chars>
```

The `pypi-AgEIcHlwaS5vcmc` prefix is consistent across all PyPI tokens (it's base64 for `\x01\x08pypi.org`). Total length typically 100-200 chars.

Common locations:
- `TWINE_PASSWORD` in CI config (twine uses the password field for API tokens)
- `.pypirc` committed to repo

## What a leaked token enables

- Publish new versions of any package the account owns
- Push malicious code that runs during `pip install` (via setup.py hooks or malicious imports)
- Upload backdoored releases indistinguishable from legitimate ones
- Account-scoped tokens: affect ALL packages owned by the account

## True positive criteria

Flag when ALL hold:
1. Value starts with `pypi-AgEIcHlwaS5vcmc` followed by 50+ chars
2. String literal, not `${{ secrets.PYPI_TOKEN }}`
3. Not a placeholder

## Examples

True positive:
```yaml
env:
  TWINE_PASSWORD: pypi-AgEIcHlwaS5vcmcCJDhhZjQ2YjU0...
```
```ini
[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDhhZjQ2YjU0...
```

Report whether the token is account-scoped or project-scoped, and what packages the repo publishes.
