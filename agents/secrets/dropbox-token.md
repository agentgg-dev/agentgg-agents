---
slug: dropbox-token
name: Dropbox API Token Exposure
description: 'Hardcoded Dropbox access tokens (sl. prefix, 130-140 chars) in source or config. Grants access to read and modify all files and folders the app has permission to in Dropbox.'
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
    - regex: '\bsl\.[A-Za-z0-9_\-]{130,140}\b'
      label: Dropbox access token (sl. prefix, 130-140 chars)
    - regex: '(?i)(?:dropbox|DROPBOX_TOKEN|DROPBOX_ACCESS_TOKEN).{0,30}[=:"''\s]+sl\.[A-Za-z0-9_\-]{100,}'
      label: Dropbox token in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Dropbox access tokens.

## Token format

```
sl.<130-140 alphanumeric/dash/underscore characters>
```

Long-lived access tokens are created via the Dropbox API app console.

## What a leaked token enables

- Read all files in the app's accessible scope (can be full Dropbox or a specific folder)
- Upload, modify, and delete files
- Read and modify shared links
- For full-access apps: access entire Dropbox including sensitive documents, backups, and credentials stored in files

## True positive criteria

Flag when ALL hold:
1. Value matches `sl.[A-Za-z0-9_-]{130,140}` exactly
2. String literal, not an env var reference
3. Not a placeholder

## Examples

True positive:
```python
import dropbox
dbx = dropbox.Dropbox('sl.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnO')
```

Report the scope of the app (full Dropbox vs folder-scoped) if determinable.
