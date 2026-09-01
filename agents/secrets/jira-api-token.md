---
slug: jira-api-token
name: Jira / Atlassian API Token Exposure
description: 'Hardcoded Jira or Atlassian API tokens in source or config. Used as HTTP basic auth password — grants read/write access to Jira issues, Confluence pages, and other Atlassian products as the token owner.'
version: 0.1.0
author: agentgg
noiseTier: normal
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
    - regex: '(?i)(?:jira|atlassian|confluence|JIRA_TOKEN|JIRA_API_TOKEN|ATLASSIAN_TOKEN).{0,40}[=:"''\s]+[A-Za-z0-9+/]{20,}={0,2}'
      label: Jira/Atlassian API token in named variable
    - regex: '(?i)(?:jira|atlassian)\.com.{0,60}(?:api_?token|password)\s*[=:]\s*[''"]?[A-Za-z0-9+/]{20,}'
      label: Atlassian domain config with adjacent token
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Jira or Atlassian API tokens. Atlassian API tokens are used as passwords in HTTP basic auth — leaking one gives full API access as the owning user.

## Token format

Atlassian API tokens are base64-encoded strings, typically 24-32 characters. They are used as the password in `Authorization: Basic base64(email:api_token)`.

Tokens are created at https://id.atlassian.com/manage-profile/security/api-tokens.

## What a leaked token enables

- Read all Jira issues the user can access (including security vulnerability reports and internal bugs)
- Create, update, and close issues
- Read Confluence pages (runbooks, architecture diagrams, internal documentation)
- Access Bitbucket repositories if on the Atlassian platform

## Cross-file analysis

When a token is found:
1. Look for the associated email address — both together form the full credential
2. Check what Atlassian instance is targeted (`your-org.atlassian.net`)
3. Determine what Jira projects or Confluence spaces the code accesses

## True positive criteria

Flag when ALL hold:
1. A base64-looking string (20+ chars) appears near "jira", "atlassian", or `JIRA_TOKEN`/`ATLASSIAN_TOKEN`
2. Context shows it used as an API password or Authorization header value
3. String literal, not an env var reference

## Examples

True positive:
```python
auth = HTTPBasicAuth('user@example.com', 'AbCdEfGhIjKlMnOpQrStUvWx')
response = requests.get('https://myorg.atlassian.net/rest/api/3/issue/PROJ-123', auth=auth)
```

Report the Atlassian instance URL, the user account email if visible, and what projects the code accesses.
