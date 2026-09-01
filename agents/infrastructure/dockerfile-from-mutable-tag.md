---
slug: dockerfile-from-mutable-tag
name: Dockerfile FROM with Mutable Tag
description: 'Dockerfile FROM directive using :latest or a non-pinned floating tag — supply-chain risk because the image content changes without notice.'
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
      label: Dockerfile FROM with mutable or root-user pattern
references:
  - CWE-1357
  - 'OWASP-A06:2021'
---

You are reviewing Dockerfiles for `FROM` directives that pin to a
mutable tag, exposing builds to silent supply-chain changes.

## What to look for

**`:latest` or no tag (defaults to :latest):**
```dockerfile
FROM nginx
FROM nginx:latest
FROM node:latest
```

**Major-only or major.minor tags (floating):**
```dockerfile
FROM node:20
FROM node:20-alpine
FROM python:3
FROM postgres:16
```
These move forward — a published `node:20.10.0` becomes `node:20.11.0`
without your knowledge.

## Safe patterns

**Specific patch version:**
```dockerfile
FROM node:20.10.0-alpine
```

**SHA256 digest (immutable):**
```dockerfile
FROM node@sha256:abc123...
```
This is the most robust — the image content cannot change.

## True positive criteria

Flag when:
1. A `FROM` line uses `:latest` explicitly.
2. A `FROM` line uses no tag at all (defaults to :latest).
3. A `FROM` line uses a major-only (`node:20`) or major.minor
   (`node:20-alpine`) tag.
4. A `FROM` line does NOT include `@sha256:...` digest pinning.

For multi-stage builds, every `FROM` is independently subject to the
check.

## What to ignore

- `FROM scratch` — there's nothing to pin.
- `FROM <build-stage>` referring to a previous `AS` stage in the
  same Dockerfile.
- Dockerfiles in example/template directories.

## Examples

True positives:
```dockerfile
FROM node:latest
FROM nginx
FROM python:3-slim
FROM postgres:16
```

False positives to skip:
```dockerfile
FROM node:20.10.0-alpine
FROM node@sha256:8c2f4f9a...
FROM scratch
FROM builder AS final
```
