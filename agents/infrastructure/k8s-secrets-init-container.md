---
slug: k8s-secrets-init-container
name: Kubernetes Init Container Copies Secrets to Shared Volume
description: Init container that reads a Secret and writes it to an emptyDir volume shared with the main container — the secret is now on disk in a volume any container in the pod can read.
version: 0.1.0
author: agentgg
noiseTier: precise
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
      label: Kubernetes secretKeyRef or secretRef reference in manifest
references:
  - CWE-526
  - 'OWASP-A02:2021'
---

You are reviewing Kubernetes Pod / Deployment manifests for init
containers that copy secrets into emptyDir (or other shared) volumes,
defeating the isolation that secret volumes provide.

## The pattern

```yaml
spec:
  initContainers:
    - name: fetch-secrets
      image: secret-fetcher:1.0
      env:
        - name: VAULT_TOKEN
          valueFrom:
            secretKeyRef: { name: vault, key: token }
      command:
        - sh
        - -c
        - "vault kv get -field=password secret/db > /shared/db-password"
      volumeMounts:
        - name: shared
          mountPath: /shared
  containers:
    - name: app
      image: app:1.0
      volumeMounts:
        - name: shared
          mountPath: /etc/secrets
  volumes:
    - name: shared
      emptyDir: {}
```

Issues:
- The plaintext secret is on the emptyDir volume, readable by every
  container that mounts it.
- Sidecar containers (logging, monitoring) often mount shared
  volumes for log collection — they now see the secret.
- emptyDir persists for the pod's lifetime; a kernel exploit /
  hostPath escape can read the file.

## Safe alternatives

- **Mount the secret directly** as a volume in the main container.
  No init container needed.
- **Use a CSI Secret Store** (Secrets Store CSI Driver) to mount
  vault-managed secrets without shell-piping them through a volume.
- **Sidecar pattern with shared in-memory IPC** if the fetcher must
  be separate.

## What to look for

- `initContainers:` whose command writes to a volume that is also
  mounted by the main `containers:`.
- The output is a secret (the source is `Vault`, AWS Secrets
  Manager, a `secretKeyRef`, etc.).
- The shared volume is `emptyDir`, `hostPath`, or another shared
  volume type.

## True positive criteria

Flag when ALL of the following hold:

1. The manifest has `initContainers` and `containers` both
   referencing the same volume.
2. The init container's command writes a secret-shaped value to a
   file in that volume.
3. The volume is `emptyDir` or another non-isolated type.

## What to ignore

- Init containers that perform schema migrations, DB seeding, or
  other non-secret-handling tasks.
- Init containers that pre-warm caches without writing secrets.
- Secrets Store CSI Driver setups (`volumes: - csi: driver: secrets-store.csi.k8s.io`).

## Examples

True positives:
```yaml
initContainers:
  - name: fetch-db-pass
    command: ["sh", "-c", "vault kv get -field=password db > /secrets/db.pass"]
    volumeMounts: [{ name: shared, mountPath: /secrets }]
containers:
  - name: app
    volumeMounts: [{ name: shared, mountPath: /etc/db }]
volumes:
  - name: shared
    emptyDir: {}
```

False positives to skip:
```yaml
# Init container only runs migrations — no secret handoff
initContainers:
  - name: migrate
    image: app-migrate:1.0
    command: ["migrate", "up"]

# Secrets Store CSI driver — secrets stay isolated
volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      volumeAttributes:
        secretProviderClass: app-secrets
```
