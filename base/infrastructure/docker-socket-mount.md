---
slug: docker-socket-mount
name: Docker Socket Mounted Into Container
description: 'The Docker/containerd daemon socket mounted into a container (docker-compose volumes, docker run -v, Kubernetes hostPath, or privileged docker-in-docker) — grants the container full root control of the host.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(docker\.sock|containerd\.sock|docker\.socket)'
        in:
          - '**/*.yaml'
          - '**/*.yml'
          - '**/docker-compose*.y*ml'
          - '**/compose*.y*ml'
          - '**/Dockerfile*'
          - '**/*.sh'
          - '**/*.bash'
        label: docker-socket-ref
where:
  extensions:
    - yml
    - yaml
    - sh
    - bash
  filePatterns:
    - '**/docker-compose*.yml'
    - '**/docker-compose*.yaml'
    - '**/compose*.yml'
    - '**/compose*.yaml'
    - '**/*.yaml'
    - '**/*.yml'
    - '**/Dockerfile*'
    - '**/*.sh'
    - '**/*.bash'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/.terraform/**'
  preFilter:
    - regex: 'docker\.sock'
      label: docker-sock
    - regex: 'containerd\.sock'
      label: containerd-sock
    - regex: '/var/run/docker'
      label: var-run-docker
    - regex: 'docker:[0-9.]*dind'
      label: dind-image
    - regex: 'DOCKER_HOST'
      label: docker-host
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-250
  - CWE-668
  - 'OWASP-A05:2021'
---

You are reviewing docker-compose files, Dockerfiles, shell scripts, and
Kubernetes manifests for the Docker (or containerd) daemon socket being
mounted into a container. The Docker socket is the daemon's root API: a
process that can write to it can start a new container that mounts the
host root filesystem, giving the attacker full, unconfined root on the
host. This is equivalent to handing out root — treat any writable mount
as a host takeover.

## Cross-file analysis

The mount and the thing that abuses it can be in different files:
- A **docker-compose** service mounting the socket is the sink; check
  whether the image is third-party/untrusted (a CI runner, a webhook
  receiver, a dashboard) — that is the attacker entry point.
- A **Kubernetes** `hostPath` volume pointing at the socket is paired
  with a `volumeMount` in the container spec; both halves are in the
  same Pod template but may be far apart in the file. Confirm the mount
  actually reaches a container.
- **docker-in-docker (dind):** a service using the `docker:*-dind` image
  with `privileged: true`, or a job that sets `DOCKER_HOST` to a mounted
  socket, achieves the same host-control outcome.

## What to look for

**docker-compose volume:**
```yaml
services:
  agent:
    image: some/ci-runner
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**docker run / shell script:**
```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock myimage
```

**Kubernetes hostPath:**
```yaml
volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
containers:
  - name: app
    volumeMounts:
      - name: docker-sock
        mountPath: /var/run/docker.sock
```

**Privileged docker-in-docker:**
```yaml
services:
  dind:
    image: docker:24-dind
    privileged: true
```

**containerd socket (same risk):** `/run/containerd/containerd.sock`.

## True positive criteria

Flag when you can state the host takeover capability. "As an attacker
with code execution in this container, because the docker socket is
mounted I can run `docker run -v /:/host ... ` and become root on the
host":
1. `/var/run/docker.sock` (or `/run/docker.sock`,
   `/var/run/docker.socket`) bound into a container via compose
   `volumes:`, `docker run -v`, or a K8s `hostPath` + `volumeMount`.
2. The containerd socket (`containerd.sock`) mounted the same way.
3. A `*-dind` image run with `privileged: true`.
4. A script that mounts the socket or points `DOCKER_HOST` at a mounted
   socket inside an untrusted container.

The mount being writable (default) is what makes it a takeover; assume
writable unless `:ro` / `readOnly: true` is explicitly present.

## What to ignore

- A **read-only socket proxy**: the socket bound `:ro` into a dedicated
  hardened proxy (e.g. `tecnativa/docker-socket-proxy`) that exposes
  only a filtered subset of the API to other services. Note it but it is
  a deliberate, scoped mitigation, not a full takeover of the consuming
  service. A bare `:ro` mount into a general app still grants read of all
  container data and is worth a lower-confidence note.
- References to the socket path in **comments, documentation, or
  example** files clearly marked as samples (under `examples/`,
  `docs/`).
- The Docker daemon's own `daemon.json` or systemd unit configuring the
  socket on the host (that is the host, not a container mount).
- A variable named `docker_sock` that is never actually bound into a
  container.

## Examples

True positives:
```yaml
services:
  portainer:
    image: portainer/portainer-ce
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

```yaml
volumes:
  - name: sock
    hostPath:
      path: /var/run/docker.sock
containers:
  - name: builder
    volumeMounts:
      - name: sock
        mountPath: /var/run/docker.sock
```

```bash
docker run -d -v /var/run/docker.sock:/var/run/docker.sock watchtower
```

False positives to skip:
```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

```yaml
volumes:
  - name: data
    hostPath:
      path: /var/lib/app
```
