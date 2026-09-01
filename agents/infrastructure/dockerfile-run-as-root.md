---
slug: dockerfile-run-as-root
name: Dockerfile Runs Container as Root
description: 'Dockerfile with no USER directive, or USER 0 / USER root — container processes run as root, escalating impact of any in-container vulnerability.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - Dockerfile
where:
  extensions:
    - Dockerfile
  filePatterns:
    - '**/Dockerfile'
    - '**/Dockerfile.*'
    - '**/Containerfile'
  preFilter:
    - semgrepRule: infrastructure/dockerfile-best-practice
      label: Dockerfile FROM with mutable tag or root USER directive
references:
  - CWE-250
  - 'OWASP-A05:2021'
---

You are reviewing Dockerfiles for containers that run as root.
Containers default to root if no `USER` directive is given. If a
process inside the container is compromised (RCE, deserialization,
etc.), running as root expands the blast radius — easier privilege
escalation paths to the host, especially when combined with mounted
volumes or capability grants.

## What to look for

**No `USER` directive in the final image stage:**
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
# No USER — container runs as root
```

**Explicit `USER root` or `USER 0`:**
```dockerfile
USER root
USER 0
```

**`USER` directive set in a build stage but reset to root before the
final image's CMD/ENTRYPOINT:**
```dockerfile
FROM node:20-alpine AS build
USER node
RUN npm install

FROM node:20-alpine
COPY --from=build /app /app
CMD ["node", "/app/server.js"]
# Final image runs as root
```

## Safe pattern

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY --chown=node:node . .
USER node            # Built-in non-root user
CMD ["node", "server.js"]
```

Or create a non-root user:
```dockerfile
RUN addgroup --system app && adduser --system --ingroup app appuser
USER appuser
```

## True positive criteria

Flag when:
1. A Dockerfile has no `USER` directive in the final stage at all.
2. The final stage's last `USER` directive (if any) is `USER root`,
   `USER 0`, or `USER 0:0`.

## What to ignore

- Containers explicitly intended to run as root for a specific reason
  documented in a comment (privileged DNS, debug containers in a
  controlled environment).
- Build stages — the `USER` of intermediate stages doesn't affect
  the final image, so an intermediate `USER root` for chmod
  operations is fine if the final stage drops to a non-root user.
- Test Dockerfiles in `__tests__/` folders.

## Examples

True positives:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
# No USER — root
```

```dockerfile
FROM ubuntu:22.04
USER 0
CMD ["./run.sh"]
```

False positives to skip:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY --chown=node:node . .
USER node
CMD ["node", "server.js"]
```
