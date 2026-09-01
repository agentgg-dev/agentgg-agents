---
slug: frameio-token
name: Frame.io API Token Exposure
description: 'Hardcoded Frame.io user tokens (fio-u- prefix, 64 chars) in source or config. Grants access to video review projects, assets, comments, and team workspaces.'
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
    - regex: '\bfio-u-[0-9a-zA-Z_\-]{64}\b'
      label: Frame.io user token (fio-u- prefix)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Frame.io API tokens. Frame.io is a video production collaboration platform used by creative teams — leaked tokens expose project assets, review links, and client communication.

## Token format

```
fio-u-<64 alphanumeric/dash/underscore characters>
```

## What a leaked token enables

- Read all projects, assets (video files), and comments the user has access to
- Download media assets including raw video files
- Post or delete review comments
- Access client-facing review links
- Enumerate team members and workspace structure

## True positive criteria

Flag when ALL hold:
1. Value matches `fio-u-[0-9a-zA-Z_-]{64}` exactly
2. String literal, not an env var reference
3. Not a placeholder

## Examples

True positive:
```python
import frameioclient
client = frameioclient.FrameioClient('fio-u-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh')
```

Report what projects or assets the code accesses and whether this is a personal or service account token.
