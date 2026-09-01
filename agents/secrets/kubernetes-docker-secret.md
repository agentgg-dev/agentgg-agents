---
slug: kubernetes-docker-secret
name: Kubernetes Docker Pull Secret Credentials
description: 'Kubernetes imagePullSecrets or docker registry credentials (dockerconfigjson/.dockercfg format) committed to source. Contains base64-encoded docker registry username/password — decoding exposes credentials for private container registries.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '\.dockerconfigjson|\.dockercfg|imagePullSecrets'
        in:
          - '**/*.yaml'
          - '**/*.yml'
          - '**/*.json'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: Kubernetes docker registry secret or imagePullSecret
where:
  filePatterns:
    - '**/*.yaml'
    - '**/*.yml'
    - '**/*.json'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '\.dockerconfigjson\s*:\s*[A-Za-z0-9+/=]{20,}'
      label: dockerconfigjson base64-encoded value in k8s Secret
    - regex: '\.dockercfg\s*:\s*[A-Za-z0-9+/=]{20,}'
      label: dockercfg base64-encoded value in k8s Secret
    - regex: '"auths"\s*:\s*\{[^}]*"auth"\s*:\s*"[A-Za-z0-9+/=]{10,}"'
      label: Docker auth base64 credential in config JSON
references:
  - CWE-798
  - CWE-321
  - 'OWASP-A02:2021'
---

You are reviewing Kubernetes configuration files for committed docker registry credentials.

## What to look for

### Kubernetes Secret with dockerconfigjson

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: regcred
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6...  # base64-encoded docker config
```

The `.dockerconfigjson` value is a base64-encoded JSON object containing registry credentials.

### Docker config JSON format (decoded)

```json
{
  "auths": {
    "registry.example.com": {
      "auth": "dXNlcm5hbWU6cGFzc3dvcmQ=",  // base64("username:password")
      "email": "user@example.com"
    }
  }
}
```

The `auth` value is further base64-encoded `username:password`.

### Legacy dockercfg format

```yaml
data:
  .dockercfg: eyJyZWdpc3RyeS5leGFtcGxlLmNvbSI6...
```

Older format, also base64-encoded credentials.

## True positive criteria

Flag at critical:
1. `kubernetes.io/dockerconfigjson` Secret with a `.dockerconfigjson` value that is not a template placeholder
2. `kubernetes.io/dockercfg` Secret committed to source
3. A raw `~/.docker/config.json` file committed with non-empty `auth` values

## What to ignore

- `imagePullSecrets: - name: regcred` — references a secret by name, does not contain credentials
- `data: .dockerconfigjson: ${REGISTRY_SECRET}` — template placeholder, not real credentials
- `stringData` with placeholder values like `USERNAME:PASSWORD` or `CHANGE_ME`

## Decoding the credential (for reporting)

If you see a base64 value for `.dockerconfigjson`, decode it to get the JSON, then decode the `auth` field to get `username:password`. Report the registry hostname and username (not the password in plaintext).

Report: the registry hostname, whether it's a public registry (Docker Hub, GitHub Container Registry, ECR) or private, and whether the credential has push access (vs. read-only pull).
