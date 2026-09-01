---
slug: k8s-secret-reference
name: Kubernetes Secret Mounted as Env Var
description: 'Secrets exposed via env: valueFrom: secretKeyRef — visible in /proc/<pid>/environ to any process in the container and to anyone who can `kubectl exec`. Prefer mounted volumes.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - yml
      - yaml
where:
  extensions:
    - yml
    - yaml
  preFilter:
    - semgrepRule: infrastructure/k8s-secret-ref
      label: Kubernetes secretKeyRef or secretRef in manifest
    - regex: 'secretKeyRef:'
      label: secretKeyRef env var
    - regex: 'secretRef:'
      label: secretRef envFrom
references:
  - CWE-526
  - 'OWASP-A02:2021'
---

You are reviewing Kubernetes manifests (Deployment, StatefulSet,
DaemonSet, Job, CronJob, Pod) for secrets passed to containers as
environment variables rather than mounted volumes.

## Why env-var secrets are risky

When a Kubernetes secret is exposed as an env var:
- Any process in the container can read `/proc/self/environ` and
  see all env vars, including secrets.
- `kubectl exec` users see the env via `printenv` / `env`.
- Crash dumps, error reports, and `--debug` logs frequently include
  the entire environment.
- Some sidecar containers (logging, monitoring) collect environment
  for metadata enrichment.

Mounted volume secrets are read by the application explicitly, can
have restricted file permissions, and don't leak into accidental
diagnostics.

## What to look for

**`env: valueFrom: secretKeyRef`:**
```yaml
spec:
  containers:
    - name: app
      env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
```

**`envFrom: secretRef`:**
```yaml
spec:
  containers:
    - name: app
      envFrom:
        - secretRef:
            name: app-secrets
```

## Safe pattern: mounted volume

```yaml
spec:
  containers:
    - name: app
      volumeMounts:
        - name: db-secret
          mountPath: /etc/secrets/db
          readOnly: true
  volumes:
    - name: db-secret
      secret:
        secretName: db-secret
        defaultMode: 0400
```

The application reads `/etc/secrets/db/password` directly.

## True positive criteria

Flag when:
1. A container spec uses `env:` with `valueFrom: secretKeyRef:` AND
   the secret name suggests genuine sensitivity (`db-password`,
   `api-key`, `jwt-secret`, `private-key`, anything matching the
   patterns `*-secret`, `*-password`, `*-key`).
2. A container spec uses `envFrom: secretRef:` (which pulls every
   key from a Secret resource into env).

## What to ignore

- Secrets that genuinely need to be env vars (legacy applications
  that only read from env, with documented mitigations).
- ConfigMap references (not secrets).
- Helm chart templates marked as examples.

## Examples

True positives:
```yaml
env:
  - name: STRIPE_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: stripe
        key: secret-key
```

```yaml
envFrom:
  - secretRef:
      name: production-secrets
```

False positives to skip:
```yaml
volumeMounts:
  - name: db-secret
    mountPath: /etc/secrets/db
    readOnly: true
volumes:
  - name: db-secret
    secret:
      secretName: db-secret
      defaultMode: 0400
```
