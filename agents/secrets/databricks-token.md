---
slug: databricks-token
name: Databricks API Token Exposure
description: 'Hardcoded Databricks personal access tokens (dapi prefix + 32 hex) in source or config. Grants access to run jobs, read notebooks, access Delta Lake tables, and control ML experiments on the workspace.'
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
    - regex: '\bdapi[a-f0-9]{32}\b'
      label: Databricks personal access token (dapi prefix)
    - regex: '(?i)(?:databricks|DATABRICKS_TOKEN|DB_TOKEN).{0,30}[=:"''\s]+dapi[a-f0-9]{32}'
      label: Databricks token in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Databricks personal access tokens. Databricks is a unified data analytics platform — a leaked token exposes data pipelines, notebooks, and potentially production ML models.

## Token format

```
dapi<32 lowercase hex characters>
```
Example: `dapi` followed by 32 lowercase hex characters

## What a leaked token enables

- Read and execute all notebooks in the workspace
- Run Spark jobs (can incur significant compute cost)
- Access Delta Lake tables and read production data
- Read MLflow experiment results and registered models
- Access cluster configuration and environment variables (which may contain other secrets)
- Upload malicious notebooks or jobs

## True positive criteria

Flag when ALL hold:
1. Value matches `dapi[a-f0-9]{32}` exactly
2. String literal, not an env var reference
3. Not a placeholder

## Examples

True positive:
```python
import databricks.sdk
w = databricks.sdk.WorkspaceClient(
    host='https://adb-123456.azuredatabricks.net',
    token='dapi<your-32-hex-chars>'
)
```

Report the workspace host URL if visible and what data operations the code performs.
