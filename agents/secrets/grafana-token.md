---
slug: grafana-token
name: Grafana Token Exposure
description: 'Hardcoded Grafana service account tokens (glsa_) or legacy API keys in source or config. These tokens grant access to dashboards, data sources, alerts, and in self-hosted instances may reach underlying databases.'
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
    - regex: '\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b'
      label: Grafana service account token (glsa_)
    - regex: '(?i)(?:grafana).{0,30}[=:"''\s]+[A-Za-z0-9+/]{40,80}[=]{0,2}'
      label: Grafana API key (legacy format, near "grafana")
    - regex: '(?i)(?:GF_SECURITY_ADMIN_PASSWORD|grafana_api_key|GRAFANA_TOKEN)\s*[=:]\s*[''"]?[^\s''"]{8,}'
      label: Grafana admin password or token env var with value
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Grafana tokens. Grafana is a widely-used observability dashboard platform — a leaked token exposes monitoring data, infrastructure topology, and possibly credentials stored as data source passwords.

## Token formats

**Service account token (Grafana 9+, recommended format):**
```
glsa_<32 alphanumeric>_<8 hex>
```
Example: `glsa_abc123def456ghi789jkl012mno345p_1a2b3c4d`

Service account tokens have roles (Viewer, Editor, Admin) and are scoped to an organization.

**Legacy API keys (Grafana < 9):**
Base64-encoded JSON blob, typically 60-90 characters. Found near `grafana` context.

**Admin password:**
`GF_SECURITY_ADMIN_PASSWORD` environment variable — grants full Grafana admin access.

## What a leaked token enables

**Viewer token:** read all dashboards and alerts in the organization — may reveal infrastructure topology, service names, database hostnames, and performance metrics.

**Editor token:** modify dashboards and alerts — can delete monitors, create noise, or hide alerts.

**Admin token:** full organization control:
- Add/remove data sources (each may have stored credentials)
- Create and delete users
- Read and modify alert notification channels (Slack webhooks, PagerDuty keys, SMTP passwords)
- On self-hosted Grafana, access to the underlying SQLite/PostgreSQL/MySQL database config

## Cross-file analysis

1. Identify the token role (Viewer/Editor/Admin) if visible in variable name or surrounding config
2. Look for `GF_SERVER_ROOT_URL` or `grafana_url` to identify which Grafana instance is targeted
3. Check if the token appears in provisioning config (`provisioning/datasources/`, `provisioning/dashboards/`) — these often contain data source credentials

## True positive criteria

Flag when ALL hold:
1. The value matches a Grafana token pattern and appears near Grafana context
2. It is a string literal, not an environment variable reference
3. It is not a placeholder

## What to ignore

- Environment variable references: `GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}`
- Grafana provisioning files that use variable interpolation: `password: $__env{DS_PASSWORD}`
- Anonymous access tokens (empty or null tokens for public dashboards)

## Examples

True positives:
```yaml
grafana:
  api_token: glsa_abc123def456ghi789jkl012mno345p_1a2b3c4d
  url: https://grafana.prod.internal
```
```env
GF_SECURITY_ADMIN_PASSWORD=SuperSecretAdminPass123
```

False positives to skip:
```yaml
grafana:
  api_token: ${GRAFANA_API_TOKEN}
```

Report the token type (service account token vs legacy API key vs admin password), the Grafana instance URL if visible, and what the surrounding code does with the token (read dashboards, provision data sources, etc.).
